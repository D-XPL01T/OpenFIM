//! Policy linting: catches configuration that parses but will not do what it says.
//!
//! A YAML policy can be perfectly valid and still be wrong in ways the parser cannot
//! see. The failures that matter are the quiet ones:
//!
//! - a check enabled on a platform that cannot perform it, which then compares nothing;
//! - a rule whose paths match nothing on disk, so it protects an empty set;
//! - a rule shadowed entirely by a more specific one, so its settings never apply;
//! - an ignore pattern that excludes the rule's own target, disabling the rule;
//! - `nodiff: false` on a path that plainly holds secrets.
//!
//! Each of these leaves the operator believing a control is active when it is not.
//! `openfim-cli policy lint` surfaces them and exits non-zero, so it can gate CI.

use std::path::Path;

use crate::capabilities::{support_for, Check};
use crate::policy::{ActiveResponseAction, Policy, RuleChecks, RuleMode};

/// How much a finding matters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Worth knowing, no action strictly required.
    Info,
    /// The policy does not do what it appears to say.
    Warning,
    /// The policy is contradictory, or silently protects nothing.
    Error,
}

impl Severity {
    pub const fn label(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Warning => "warning",
            Severity::Error => "error",
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// A single lint finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub severity: Severity,
    /// Stable identifier, so findings can be referenced and suppressed by name.
    pub code: &'static str,
    /// The rule this concerns, where applicable.
    pub rule_id: Option<String>,
    pub message: String,
    /// What to do about it.
    pub remedy: Option<String>,
}

impl Finding {
    fn new(severity: Severity, code: &'static str, message: String) -> Self {
        Self {
            severity,
            code,
            rule_id: None,
            message,
            remedy: None,
        }
    }

    fn for_rule(mut self, rule_id: &str) -> Self {
        self.rule_id = Some(rule_id.to_string());
        self
    }

    fn with_remedy(mut self, remedy: impl Into<String>) -> Self {
        self.remedy = Some(remedy.into());
        self
    }
}

/// The result of linting a policy.
#[derive(Debug, Clone, Default)]
pub struct LintReport {
    pub findings: Vec<Finding>,
}

impl LintReport {
    /// Findings at or above a severity.
    pub fn at_least(&self, severity: Severity) -> impl Iterator<Item = &Finding> {
        self.findings.iter().filter(move |f| f.severity >= severity)
    }

    pub fn count(&self, severity: Severity) -> usize {
        self.findings
            .iter()
            .filter(|f| f.severity == severity)
            .count()
    }

    /// True when nothing at warning level or above was found.
    pub fn is_clean(&self) -> bool {
        self.at_least(Severity::Warning).count() == 0
    }

    /// Exit code for CI use: non-zero when anything actionable was found.
    pub fn exit_code(&self) -> i32 {
        if self.is_clean() {
            0
        } else {
            1
        }
    }
}

/// Reads one check's flag out of a `RuleChecks`.
fn is_requested(checks: &RuleChecks, check: Check) -> bool {
    match check {
        Check::Hash => checks.hash,
        Check::Size => checks.size,
        Check::Permissions => checks.permissions,
        Check::Ownership => checks.ownership,
        Check::Timestamps => checks.timestamps,
        Check::Attributes => checks.attributes,
        Check::Xattrs => checks.xattrs,
    }
}

/// Filename fragments that very likely indicate secret material.
///
/// Used only to advise enabling `nodiff`; nothing is excluded from monitoring on the
/// strength of a filename guess.
const SECRET_HINTS: &[&str] = &[
    "shadow",
    "gshadow",
    ".key",
    ".pem",
    ".p12",
    ".pfx",
    "id_rsa",
    "id_ed25519",
    ".env",
    "credential",
    "secret",
    "password",
    "token",
    ".kdbx",
];

fn looks_like_secret(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    SECRET_HINTS.iter().any(|hint| lower.contains(hint))
}

/// Lints a policy against the current platform's capabilities and the filesystem.
///
/// `check_filesystem` controls whether path existence is probed. Turn it off when
/// linting a policy intended for a different host, where absent paths are expected.
pub fn lint_policy(policy: &Policy, check_filesystem: bool) -> LintReport {
    let mut report = LintReport::default();

    if policy.rules.is_empty() {
        report.findings.push(
            Finding::new(
                Severity::Error,
                "EMPTY_POLICY",
                "the policy defines no rules, so it monitors nothing".to_string(),
            )
            .with_remedy("add at least one rule with a `paths` entry"),
        );
    }

    // ---- Global settings ----

    if policy
        .globals
        .default_hash
        .parse::<crate::HashAlgorithm>()
        .is_err()
    {
        report.findings.push(
            Finding::new(
                Severity::Error,
                "BAD_DEFAULT_HASH",
                format!(
                    "globals.default_hash is '{}', which is not a supported algorithm",
                    policy.globals.default_hash
                ),
            )
            .with_remedy("use one of: sha256, blake3, sha512"),
        );
    }

    if policy.globals.max_io_rate_mb_s == 0 {
        report.findings.push(
            Finding::new(
                Severity::Info,
                "UNTHROTTLED_IO",
                "globals.max_io_rate_mb_s is 0, so scanning is unthrottled and may \
                 compete with the production workload for disk bandwidth"
                    .to_string(),
            )
            .with_remedy("set a MB/s ceiling unless unthrottled scanning is intended"),
        );
    }

    if policy.globals.realtime_fallback_sweep_interval == 0 {
        report.findings.push(
            Finding::new(
                Severity::Warning,
                "NO_FALLBACK_SWEEP",
                "globals.realtime_fallback_sweep_interval is 0, disabling the \
                 reconciliation sweep. Real-time watchers drop events under load, and \
                 without a sweep those misses are permanent and silent."
                    .to_string(),
            )
            .with_remedy("set an interval in seconds (3600 is a reasonable default)"),
        );
    }

    let mut seen_ids: Vec<&str> = Vec::new();

    for rule in &policy.rules {
        // ---- Rule identity ----

        if rule.id.trim().is_empty() {
            report.findings.push(Finding::new(
                Severity::Error,
                "EMPTY_RULE_ID",
                "a rule has an empty id, which makes its alerts untraceable".to_string(),
            ));
        } else if seen_ids.contains(&rule.id.as_str()) {
            report.findings.push(
                Finding::new(
                    Severity::Error,
                    "DUPLICATE_RULE_ID",
                    format!("rule id '{}' is used more than once", rule.id),
                )
                .for_rule(&rule.id)
                .with_remedy("give each rule a unique id"),
            );
        }
        seen_ids.push(&rule.id);

        if rule.paths.is_empty() {
            report.findings.push(
                Finding::new(
                    Severity::Error,
                    "NO_PATHS",
                    format!(
                        "rule '{}' declares no paths, so it monitors nothing",
                        rule.id
                    ),
                )
                .for_rule(&rule.id),
            );
        }

        if !(1..=10).contains(&rule.severity) {
            report.findings.push(
                Finding::new(
                    Severity::Warning,
                    "SEVERITY_OUT_OF_RANGE",
                    format!(
                        "rule '{}' has severity {}, outside the documented 1-10 range",
                        rule.id, rule.severity
                    ),
                )
                .for_rule(&rule.id),
            );
        }

        // ---- Unenforceable checks ----

        for check in Check::ALL {
            if !is_requested(&rule.checks, check) {
                continue;
            }
            let support = support_for(check);
            if !support.is_active() {
                report.findings.push(
                    Finding::new(
                        Severity::Warning,
                        "CHECK_UNENFORCEABLE",
                        format!(
                            "rule '{}' enables `{}`, which cannot be enforced on {}: {}",
                            rule.id,
                            check.field_name(),
                            crate::capabilities::platform_name(),
                            support.note().unwrap_or("unsupported")
                        ),
                    )
                    .for_rule(&rule.id)
                    .with_remedy(format!(
                        "set `{}: false` to make the gap explicit, or run on a platform \
                         that supports it",
                        check.field_name()
                    )),
                );
            }
        }

        // A rule with every check disabled still matches paths but compares nothing.
        let any_check = Check::ALL.iter().any(|&c| is_requested(&rule.checks, c));
        if !any_check {
            report.findings.push(
                Finding::new(
                    Severity::Error,
                    "NO_CHECKS_ENABLED",
                    format!(
                        "rule '{}' has every check disabled, so it will never report a \
                         change to the files it matches",
                        rule.id
                    ),
                )
                .for_rule(&rule.id)
                .with_remedy("enable at least `hash`"),
            );
        }

        // ---- Self-defeating ignore patterns ----

        for target in &rule.paths {
            let target_path = Path::new(target);
            if rule
                .ignore
                .iter()
                .any(|pat| ignore_swallows_target(pat, target))
            {
                report.findings.push(
                    Finding::new(
                        Severity::Error,
                        "IGNORE_SWALLOWS_TARGET",
                        format!(
                            "rule '{}' ignores its own target '{}', so the rule is inert",
                            rule.id, target
                        ),
                    )
                    .for_rule(&rule.id)
                    .with_remedy("narrow the ignore pattern, or remove the rule"),
                );
            }

            // ---- Paths that match nothing ----

            if check_filesystem && !target.contains('*') && !target.contains('?') {
                if !target_path.exists() {
                    report.findings.push(
                        Finding::new(
                            Severity::Warning,
                            "PATH_ABSENT",
                            format!(
                                "rule '{}' targets '{}', which does not exist on this host",
                                rule.id, target
                            ),
                        )
                        .for_rule(&rule.id)
                        .with_remedy(
                            "the rule protects nothing until the path exists; confirm the \
                             path is correct for this host",
                        ),
                    );
                } else if target_path.is_dir() && !rule.recursive {
                    report.findings.push(
                        Finding::new(
                            Severity::Info,
                            "DIRECTORY_NOT_RECURSIVE",
                            format!(
                                "rule '{}' targets the directory '{}' with recursive: false, \
                                 so only the directory entry itself is watched, not its contents",
                                rule.id, target
                            ),
                        )
                        .for_rule(&rule.id),
                    );
                }
            }

            // ---- Secrets and diff capture ----

            if looks_like_secret(target) && !rule.nodiff {
                report.findings.push(
                    Finding::new(
                        Severity::Warning,
                        "SECRET_WITHOUT_NODIFF",
                        format!(
                            "rule '{}' targets '{}', which looks like secret material, but \
                             nodiff is false",
                            rule.id, target
                        ),
                    )
                    .for_rule(&rule.id)
                    .with_remedy(
                        "set `nodiff: true` so file contents are never captured into the \
                         event log",
                    ),
                );
            }
        }

        // ---- Active response ----

        if rule.active_response.action == ActiveResponseAction::RestoreBaseline && rule.nodiff {
            report.findings.push(
                Finding::new(
                    Severity::Info,
                    "RESTORE_ON_SECRET",
                    format!(
                        "rule '{}' restores from a backup store, which keeps verbatim copies \
                         of a path marked nodiff",
                        rule.id
                    ),
                )
                .for_rule(&rule.id)
                .with_remedy(
                    "confirm the backup store is protected to the same standard as the \
                     monitored secret",
                ),
            );
        }

        if rule.active_response.action == ActiveResponseAction::KillProcess {
            report.findings.push(
                Finding::new(
                    Severity::Warning,
                    "KILL_PROCESS_UNAVAILABLE",
                    format!(
                        "rule '{}' requests kill_process, which this build cannot perform: \
                         terminating the writer requires kernel-level process attribution",
                        rule.id
                    ),
                )
                .for_rule(&rule.id)
                .with_remedy("use quarantine or restore_baseline, or accept alert-only"),
            );
        }

        if rule.whodata {
            report.findings.push(
                Finding::new(
                    Severity::Warning,
                    "WHODATA_UNAVAILABLE",
                    format!(
                        "rule '{}' enables whodata, but this build cannot identify the \
                         acting process; events are recorded as UNATTRIBUTED",
                        rule.id
                    ),
                )
                .for_rule(&rule.id)
                .with_remedy(
                    "no action available yet; kernel attribution (fanotify FAN_REPORT_PIDFD, \
                     eBPF, or a Windows minifilter) is required",
                ),
            );
        }

        if rule.mode != RuleMode::Realtime && policy.globals.realtime_fallback_sweep_interval == 0 {
            report.findings.push(
                Finding::new(
                    Severity::Error,
                    "SCHEDULED_WITHOUT_INTERVAL",
                    format!(
                        "rule '{}' uses mode {:?}, which is driven by the sweep interval, but \
                         globals.realtime_fallback_sweep_interval is 0",
                        rule.id, rule.mode
                    ),
                )
                .for_rule(&rule.id),
            );
        }
    }

    // ---- Shadowed rules ----
    //
    // Precedence is longest-target-wins. A rule every one of whose targets is a strict
    // prefix-child of another recursive rule's target, with lower severity, can never
    // win, so its settings never apply.
    for (i, rule) in policy.rules.iter().enumerate() {
        if rule.paths.is_empty() {
            continue;
        }
        let shadowed_by = policy.rules.iter().enumerate().find(|(j, other)| {
            *j != i
                && other.severity >= rule.severity
                && rule.paths.iter().all(|target| {
                    other.paths.iter().any(|other_target| {
                        other_target.len() > target.len()
                            && normalize(other_target).starts_with(&normalize(target))
                    })
                })
        });

        if let Some((_, other)) = shadowed_by {
            report.findings.push(
                Finding::new(
                    Severity::Info,
                    "POSSIBLY_SHADOWED",
                    format!(
                        "rule '{}' may never apply: rule '{}' targets a more specific path and \
                         wins on precedence",
                        rule.id, other.id
                    ),
                )
                .for_rule(&rule.id),
            );
        }
    }

    report
}

fn normalize(s: &str) -> String {
    let out = s.replace('\\', "/");
    if cfg!(windows) {
        out.to_lowercase()
    } else {
        out
    }
}

/// True when an ignore pattern excludes the rule's own target outright.
fn ignore_swallows_target(pattern: &str, target: &str) -> bool {
    let pat = normalize(pattern);
    let tgt = normalize(target);

    if pat == tgt {
        return true;
    }
    // `**` alone, or a pattern that is exactly the target plus a recursive wildcard.
    if pat == "**" || pat == "*" {
        return true;
    }
    if let Some(stripped) = pat.strip_suffix("/**") {
        if stripped == tgt.trim_end_matches('/') {
            return true;
        }
    }
    glob::Pattern::new(&pat)
        .map(|p| p.matches(&tgt))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{ActiveResponseConfig, PolicyGlobals, PolicyRule};

    fn rule(id: &str, paths: &[&str]) -> PolicyRule {
        PolicyRule {
            id: id.to_string(),
            description: "d".to_string(),
            paths: paths.iter().map(|s| s.to_string()).collect(),
            recursive: true,
            mode: RuleMode::Realtime,
            checks: RuleChecks::default(),
            nodiff: false,
            ignore: vec![],
            severity: 5,
            whodata: false,
            active_response: ActiveResponseConfig::default(),
        }
    }

    fn policy_with(rules: Vec<PolicyRule>) -> Policy {
        Policy {
            version: "1.0".to_string(),
            policy_id: "p".to_string(),
            name: "n".to_string(),
            author: "a".to_string(),
            signature_algorithm: "ed25519".to_string(),
            globals: PolicyGlobals::default(),
            rules,
        }
    }

    fn codes(report: &LintReport) -> Vec<&'static str> {
        report.findings.iter().map(|f| f.code).collect()
    }

    #[test]
    fn empty_policy_is_an_error() {
        let report = lint_policy(&policy_with(vec![]), false);
        assert!(codes(&report).contains(&"EMPTY_POLICY"));
        assert_eq!(report.exit_code(), 1);
    }

    #[test]
    fn rule_with_no_checks_is_an_error() {
        let mut r = rule("R1", &["/etc"]);
        r.checks = RuleChecks {
            hash: false,
            size: false,
            permissions: false,
            ownership: false,
            timestamps: false,
            attributes: false,
            xattrs: false,
        };
        let report = lint_policy(&policy_with(vec![r]), false);
        assert!(codes(&report).contains(&"NO_CHECKS_ENABLED"));
    }

    #[test]
    fn rule_ignoring_its_own_target_is_an_error() {
        // The quietest possible misconfiguration: the rule looks active and protects
        // nothing at all.
        let mut r = rule("R1", &["/etc/ssh"]);
        r.ignore = vec!["/etc/ssh".to_string()];
        let report = lint_policy(&policy_with(vec![r]), false);
        assert!(codes(&report).contains(&"IGNORE_SWALLOWS_TARGET"));
    }

    #[test]
    fn recursive_wildcard_ignore_of_own_target_is_caught() {
        let mut r = rule("R1", &["/etc/ssh"]);
        r.ignore = vec!["/etc/ssh/**".to_string()];
        let report = lint_policy(&policy_with(vec![r]), false);
        assert!(codes(&report).contains(&"IGNORE_SWALLOWS_TARGET"));
    }

    #[test]
    fn blanket_ignore_is_caught() {
        let mut r = rule("R1", &["/etc"]);
        r.ignore = vec!["**".to_string()];
        assert!(
            codes(&lint_policy(&policy_with(vec![r]), false)).contains(&"IGNORE_SWALLOWS_TARGET")
        );
    }

    #[test]
    fn narrow_ignore_is_not_flagged() {
        let mut r = rule("R1", &["/etc"]);
        r.ignore = vec!["*.tmp".to_string(), "/etc/mtab".to_string()];
        assert!(
            !codes(&lint_policy(&policy_with(vec![r]), false)).contains(&"IGNORE_SWALLOWS_TARGET")
        );
    }

    #[test]
    fn duplicate_rule_ids_are_an_error() {
        let report = lint_policy(
            &policy_with(vec![rule("SAME", &["/etc"]), rule("SAME", &["/var"])]),
            false,
        );
        assert!(codes(&report).contains(&"DUPLICATE_RULE_ID"));
    }

    #[test]
    fn severity_outside_range_is_flagged() {
        let mut r = rule("R1", &["/etc"]);
        r.severity = 42;
        assert!(
            codes(&lint_policy(&policy_with(vec![r]), false)).contains(&"SEVERITY_OUT_OF_RANGE")
        );
    }

    #[test]
    fn secret_path_without_nodiff_is_flagged() {
        let r = rule("R1", &["/etc/shadow"]);
        assert!(
            codes(&lint_policy(&policy_with(vec![r]), false)).contains(&"SECRET_WITHOUT_NODIFF")
        );
    }

    #[test]
    fn secret_path_with_nodiff_is_not_flagged() {
        let mut r = rule("R1", &["/etc/shadow"]);
        r.nodiff = true;
        assert!(
            !codes(&lint_policy(&policy_with(vec![r]), false)).contains(&"SECRET_WITHOUT_NODIFF")
        );
    }

    #[test]
    fn several_secret_shapes_are_recognized() {
        for path in [
            "/etc/shadow",
            "/root/.ssh/id_rsa",
            "/app/.env",
            "/certs/server.pem",
            "/secrets/db_password",
            "/vault/creds.kdbx",
        ] {
            let r = rule("R1", &[path]);
            assert!(
                codes(&lint_policy(&policy_with(vec![r]), false))
                    .contains(&"SECRET_WITHOUT_NODIFF"),
                "{} was not recognized as secret material",
                path
            );
        }
    }

    #[test]
    fn ordinary_paths_are_not_treated_as_secrets() {
        for path in ["/usr/bin", "/etc/hosts", "/var/www/index.html"] {
            let r = rule("R1", &[path]);
            assert!(
                !codes(&lint_policy(&policy_with(vec![r]), false))
                    .contains(&"SECRET_WITHOUT_NODIFF"),
                "{} was wrongly treated as secret material",
                path
            );
        }
    }

    #[test]
    fn kill_process_is_flagged_as_unavailable() {
        let mut r = rule("R1", &["/etc"]);
        r.active_response.action = ActiveResponseAction::KillProcess;
        assert!(
            codes(&lint_policy(&policy_with(vec![r]), false)).contains(&"KILL_PROCESS_UNAVAILABLE")
        );
    }

    #[test]
    fn whodata_is_flagged_as_unavailable() {
        let mut r = rule("R1", &["/etc"]);
        r.whodata = true;
        assert!(codes(&lint_policy(&policy_with(vec![r]), false)).contains(&"WHODATA_UNAVAILABLE"));
    }

    #[test]
    fn unenforceable_checks_are_reported_per_platform() {
        // xattrs is unsupported everywhere in this build, so it must always be flagged.
        let mut r = rule("R1", &["/etc"]);
        r.checks.xattrs = true;
        let report = lint_policy(&policy_with(vec![r]), false);
        let findings: Vec<&Finding> = report
            .findings
            .iter()
            .filter(|f| f.code == "CHECK_UNENFORCEABLE")
            .collect();
        assert!(!findings.is_empty());
        assert!(findings.iter().all(|f| f.remedy.is_some()));
        assert!(findings.iter().any(|f| f.message.contains("xattrs")));
    }

    #[test]
    fn zero_sweep_interval_is_a_warning() {
        let mut p = policy_with(vec![rule("R1", &["/etc"])]);
        p.globals.realtime_fallback_sweep_interval = 0;
        assert!(codes(&lint_policy(&p, false)).contains(&"NO_FALLBACK_SWEEP"));
    }

    #[test]
    fn scheduled_mode_without_interval_is_an_error() {
        let mut r = rule("R1", &["/etc"]);
        r.mode = RuleMode::Scheduled;
        let mut p = policy_with(vec![r]);
        p.globals.realtime_fallback_sweep_interval = 0;
        assert!(codes(&lint_policy(&p, false)).contains(&"SCHEDULED_WITHOUT_INTERVAL"));
    }

    #[test]
    fn bad_default_hash_is_an_error() {
        let mut p = policy_with(vec![rule("R1", &["/etc"])]);
        p.globals.default_hash = "md5".to_string();
        assert!(codes(&lint_policy(&p, false)).contains(&"BAD_DEFAULT_HASH"));
    }

    #[test]
    fn absent_path_is_flagged_only_when_probing_the_filesystem() {
        let r = rule("R1", &["/definitely/not/here/openfim"]);
        let p = policy_with(vec![r]);
        assert!(codes(&lint_policy(&p, true)).contains(&"PATH_ABSENT"));
        assert!(!codes(&lint_policy(&p, false)).contains(&"PATH_ABSENT"));
    }

    #[test]
    fn shadowed_rule_is_reported() {
        let broad = rule("BROAD", &["/etc"]);
        let mut specific = rule("SPECIFIC", &["/etc/ssh"]);
        specific.severity = 9;
        let report = lint_policy(&policy_with(vec![broad, specific]), false);
        assert!(
            codes(&report).contains(&"POSSIBLY_SHADOWED"),
            "{:?}",
            codes(&report)
        );
    }

    #[test]
    fn a_sensible_policy_lints_clean() {
        let mut r = rule("GOOD", &["/etc/hosts"]);
        r.checks = RuleChecks {
            hash: true,
            size: true,
            permissions: cfg!(unix),
            ownership: cfg!(unix),
            timestamps: false,
            attributes: cfg!(windows),
            xattrs: false,
        };
        r.severity = 8;
        let report = lint_policy(&policy_with(vec![r]), false);
        assert!(
            report.is_clean(),
            "a well-formed policy should lint clean, got: {:?}",
            report.findings
        );
        assert_eq!(report.exit_code(), 0);
    }

    #[test]
    fn every_finding_names_a_code_and_a_message() {
        let mut r = rule("", &[]);
        r.severity = 0;
        r.whodata = true;
        let report = lint_policy(&policy_with(vec![r]), false);
        assert!(!report.findings.is_empty());
        for f in &report.findings {
            assert!(!f.code.is_empty());
            assert!(!f.message.is_empty(), "{} has no message", f.code);
        }
    }

    #[test]
    fn warnings_and_errors_both_fail_the_exit_code() {
        let mut warn_only = rule("R1", &["/etc"]);
        warn_only.whodata = true; // warning
        assert_eq!(
            lint_policy(&policy_with(vec![warn_only]), false).exit_code(),
            1
        );
    }
}
