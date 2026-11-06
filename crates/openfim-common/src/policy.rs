use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use glob::Pattern;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

use crate::backup::{BackupStore, RestoreOutcome};
use crate::error::{OpenFimError, Result};

/// Execution mode for a monitoring rule
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum RuleMode {
    #[default]
    Realtime,
    Scheduled,
    OnBoot,
}

/// Active automated response action when an integrity violation is detected
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum ActiveResponseAction {
    #[default]
    None,
    RestoreBaseline,
    KillProcess,
    Quarantine,
}

/// Outcome of an attempted automated remediation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemediationOutcome {
    /// No action was configured for this rule.
    NotConfigured,
    /// The action ran and changed the system. The string describes what happened.
    Applied(String),
    /// The action was deliberately not taken. The string explains why.
    Declined(String),
}

impl RemediationOutcome {
    /// True when the action actually modified the system.
    pub fn was_applied(&self) -> bool {
        matches!(self, RemediationOutcome::Applied(_))
    }

    /// Human-readable description of the outcome.
    pub fn message(&self) -> &str {
        match self {
            RemediationOutcome::NotConfigured => "No remediation configured",
            RemediationOutcome::Applied(m) | RemediationOutcome::Declined(m) => m,
        }
    }
}

impl std::fmt::Display for RemediationOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RemediationOutcome::NotConfigured => write!(f, "not configured"),
            RemediationOutcome::Applied(m) => write!(f, "applied: {}", m),
            RemediationOutcome::Declined(m) => write!(f, "declined: {}", m),
        }
    }
}

/// Default ceiling on automated remediations per rolling hour.
///
/// The threat model's own risk register (RSK-04) requires this: an attacker who can
/// repeatedly touch a monitored file would otherwise drive an unbounded loop of
/// quarantines or rollbacks, turning the defensive response into a denial of service
/// against the very data it protects.
pub const DEFAULT_MAX_REMEDIATIONS_PER_HOUR: u32 = 3;

/// Rate limiter and audit counter guarding automated active response.
#[derive(Debug, Clone)]
pub struct RemediationGuard {
    max_per_hour: u32,
    window: std::time::Duration,
    recent: std::collections::VecDeque<std::time::Instant>,
}

impl Default for RemediationGuard {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_REMEDIATIONS_PER_HOUR)
    }
}

impl RemediationGuard {
    /// Creates a guard allowing at most `max_per_hour` remediations in any rolling hour.
    /// A limit of 0 disables automated remediation entirely.
    pub fn new(max_per_hour: u32) -> Self {
        Self {
            max_per_hour,
            window: std::time::Duration::from_secs(3600),
            recent: std::collections::VecDeque::new(),
        }
    }

    /// Creates a guard with a custom window length (used by tests).
    pub fn with_window(max_per_hour: u32, window: std::time::Duration) -> Self {
        Self {
            max_per_hour,
            window,
            recent: std::collections::VecDeque::new(),
        }
    }

    fn prune(&mut self) {
        let cutoff = std::time::Instant::now();
        while let Some(front) = self.recent.front() {
            if cutoff.duration_since(*front) >= self.window {
                self.recent.pop_front();
            } else {
                break;
            }
        }
    }

    /// Number of remediations performed within the current window.
    pub fn count_in_window(&mut self) -> usize {
        self.prune();
        self.recent.len()
    }

    /// Remaining budget in the current window.
    pub fn remaining(&mut self) -> u32 {
        let used = self.count_in_window() as u32;
        self.max_per_hour.saturating_sub(used)
    }

    /// Consumes one unit of budget, returning false when the circuit breaker is open.
    pub fn try_consume(&mut self) -> bool {
        self.prune();
        if (self.recent.len() as u32) >= self.max_per_hour {
            return false;
        }
        self.recent.push_back(std::time::Instant::now());
        true
    }

    /// Executes an action through the circuit breaker.
    pub fn execute<P: AsRef<Path>>(
        &mut self,
        action: ActiveResponseAction,
        path: P,
        backup: Option<&BackupStore>,
    ) -> std::io::Result<RemediationOutcome> {
        if action == ActiveResponseAction::None {
            return Ok(RemediationOutcome::NotConfigured);
        }
        if !self.try_consume() {
            return Ok(RemediationOutcome::Declined(format!(
                "circuit breaker open: {} remediation(s) already performed in the last hour \
                 (limit {}); escalating to alert-only to avoid an automated response loop",
                self.recent.len(),
                self.max_per_hour
            )));
        }
        action.execute(path, backup)
    }
}

impl ActiveResponseAction {
    /// Executes automated defensive remediation on an integrity violation.
    ///
    /// Prefer [`RemediationGuard::execute`], which additionally enforces the
    /// per-hour circuit breaker. This method performs the action unconditionally.
    pub fn execute<P: AsRef<Path>>(
        &self,
        path: P,
        backup: Option<&BackupStore>,
    ) -> std::io::Result<RemediationOutcome> {
        let p = path.as_ref();
        match self {
            Self::None => Ok(RemediationOutcome::NotConfigured),
            Self::Quarantine => {
                if !p.exists() {
                    return Ok(RemediationOutcome::Declined(
                        "target does not exist; nothing to quarantine".to_string(),
                    ));
                }
                let q_dir = p
                    .parent()
                    .unwrap_or_else(|| Path::new("."))
                    .join(".quarantine");
                std::fs::create_dir_all(&q_dir)?;
                let file_name = p.file_name().unwrap_or_default().to_string_lossy();
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let dest = q_dir.join(format!("{}.{}.quarantined", file_name, now));
                std::fs::rename(p, &dest)?;
                Ok(RemediationOutcome::Applied(format!(
                    "compromised file quarantined to {}",
                    dest.display()
                )))
            }
            Self::RestoreBaseline => {
                let store = match backup {
                    Some(s) => s,
                    None => {
                        return Ok(RemediationOutcome::Declined(
                            "no backup store configured, so no pristine copy is available \
                             to restore; leaving the file in place for manual triage"
                                .to_string(),
                        ))
                    }
                };

                match store.restore(p) {
                    Ok(RestoreOutcome::Restored { sha256, size }) => {
                        Ok(RemediationOutcome::Applied(format!(
                            "restored pristine state ({} bytes, sha256 {}) from the backup store at {}",
                            size,
                            &sha256[..sha256.len().min(16)],
                            store.root().display()
                        )))
                    }
                    // Deliberately do NOT fall back to quarantine here.
                    //
                    // Quarantine *moves the file away*. Silently substituting it for a
                    // failed restore turns "put the good copy back" into "delete the
                    // live file", which is a destructive outcome the operator never
                    // asked for and the single most dangerous failure mode in the
                    // whole response path.
                    Ok(RestoreOutcome::NoBackup) => Ok(RemediationOutcome::Declined(format!(
                        "no pristine copy of {} in the backup store at {}; refusing to \
                         substitute a destructive quarantine for the requested restore",
                        p.display(),
                        store.root().display()
                    ))),
                    // A corrupt store, a missing object, or a digest mismatch. The live
                    // file is left untouched by `BackupStore::restore` in every one of
                    // these cases, so report and decline rather than act on bad data.
                    Err(e) => Ok(RemediationOutcome::Declined(format!(
                        "restore aborted, live file left untouched: {}",
                        e
                    ))),
                }
            }
            Self::KillProcess => {
                // Honest refusal rather than a success string for work never done.
                //
                // Terminating the writer requires the acting PID, which in turn
                // requires kernel-level attribution (fanotify FAN_REPORT_PIDFD, eBPF,
                // or a Windows minifilter). The sensor does not have that yet, so
                // there is no process here to kill. Reporting "dispatched" would put a
                // false containment record into the audit trail.
                Ok(RemediationOutcome::Declined(
                    "kill_process requires kernel-level process attribution, which this \
                     build does not implement; no process was terminated"
                        .to_string(),
                ))
            }
        }
    }
}

/// Active response configuration block
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ActiveResponseConfig {
    #[serde(default)]
    pub action: ActiveResponseAction,
}

/// Metadata and content checks enabled for a rule
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleChecks {
    #[serde(default = "default_true")]
    pub hash: bool,
    #[serde(default = "default_true")]
    pub size: bool,
    #[serde(default = "default_true")]
    pub permissions: bool,
    #[serde(default = "default_true")]
    pub ownership: bool,
    #[serde(default = "default_false")]
    pub timestamps: bool,
    #[serde(default = "default_true")]
    pub attributes: bool,
    #[serde(default = "default_false")]
    pub xattrs: bool,
}

impl Default for RuleChecks {
    fn default() -> Self {
        Self {
            hash: true,
            size: true,
            permissions: true,
            ownership: true,
            timestamps: false,
            attributes: true,
            xattrs: false,
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_false() -> bool {
    false
}

fn default_severity() -> u32 {
    5
}

fn default_io_rate() -> u64 {
    25
}

fn default_nice() -> i32 {
    10
}

fn default_sweep_interval() -> u64 {
    3600
}

fn default_sha256_str() -> String {
    "sha256".to_string()
}

/// Global scanner performance options and defaults
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyGlobals {
    #[serde(default = "default_sha256_str")]
    pub default_hash: String,

    #[serde(default = "default_io_rate")]
    pub max_io_rate_mb_s: u64,

    #[serde(default = "default_nice")]
    pub scan_nice_priority: i32,

    #[serde(default = "default_sweep_interval")]
    pub realtime_fallback_sweep_interval: u64,
}

impl Default for PolicyGlobals {
    fn default() -> Self {
        Self {
            default_hash: "sha256".to_string(),
            max_io_rate_mb_s: 25,
            scan_nice_priority: 10,
            realtime_fallback_sweep_interval: 3600,
        }
    }
}

/// Individual file integrity rule definition
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRule {
    pub id: String,
    pub description: String,
    pub paths: Vec<String>,

    #[serde(default = "default_true")]
    pub recursive: bool,

    #[serde(default)]
    pub mode: RuleMode,

    #[serde(default)]
    pub checks: RuleChecks,

    #[serde(default = "default_false")]
    pub nodiff: bool,

    #[serde(default)]
    pub ignore: Vec<String>,

    #[serde(default = "default_severity")]
    pub severity: u32,

    #[serde(default = "default_false")]
    pub whodata: bool,

    #[serde(default)]
    pub active_response: ActiveResponseConfig,
}

/// Complete declarative OpenFIM Policy
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub version: String,
    pub policy_id: String,
    pub name: String,
    pub author: String,

    #[serde(default = "default_ed25519_str")]
    pub signature_algorithm: String,

    #[serde(default)]
    pub globals: PolicyGlobals,

    pub rules: Vec<PolicyRule>,
}

fn default_ed25519_str() -> String {
    "ed25519".to_string()
}

/// Where an effective setting came from, so `policy check` can show precedence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingSource {
    /// A command-line flag, which overrides the policy.
    CommandLine,
    /// The policy's `globals` block.
    Policy,
    /// The built-in default, because neither of the above supplied a value.
    Default,
}

impl std::fmt::Display for SettingSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            SettingSource::CommandLine => "command line",
            SettingSource::Policy => "policy globals",
            SettingSource::Default => "built-in default",
        })
    }
}

/// A resolved setting plus where it came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Effective<T> {
    pub value: T,
    pub source: SettingSource,
}

impl<T: std::fmt::Display> std::fmt::Display for Effective<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (from {})", self.value, self.source)
    }
}

/// The scanner settings actually in force, after resolving CLI over policy over default.
///
/// Before this existed, `globals.default_hash`, `max_io_rate_mb_s` and
/// `scan_nice_priority` were parsed, printed by `policy check`, and then ignored — the
/// hasher was hardcoded to SHA-256 and throttling came only from a CLI flag. An
/// operator who set `default_hash: blake3` got SHA-256 with no indication.
#[derive(Debug, Clone)]
pub struct EffectiveScanSettings {
    pub hash_algorithm: Effective<crate::hasher::HashAlgorithm>,
    pub max_io_rate_mb_s: Effective<u64>,
    pub scan_nice_priority: Effective<i32>,
    pub sweep_interval_secs: Effective<u64>,
}

impl EffectiveScanSettings {
    /// Rate limit in bytes per second, saturating rather than overflowing.
    pub fn rate_bytes_per_sec(&self) -> u64 {
        self.max_io_rate_mb_s
            .value
            .saturating_mul(1024)
            .saturating_mul(1024)
    }
}

/// Applies the scan priority to the current thread, best effort.
///
/// Reports failure rather than succeeding silently: on Unix lowering the nice value
/// requires privilege, and an operator who asked for a priority change deserves to know
/// it did not happen.
pub fn apply_scan_priority(nice: i32) -> std::result::Result<(), String> {
    #[cfg(unix)]
    {
        // SAFETY: setpriority with PRIO_PROCESS and who=0 targets the calling process
        // and cannot violate memory safety.
        let rc = unsafe { libc::setpriority(libc::PRIO_PROCESS, 0, nice) };
        if rc == 0 {
            Ok(())
        } else {
            Err(format!(
                "setpriority({}) failed: {}",
                nice,
                std::io::Error::last_os_error()
            ))
        }
    }

    #[cfg(windows)]
    {
        // Windows has no per-thread nice value. Map the POSIX-style range onto the
        // nearest thread priority so the intent (scan politely) is honoured.
        use windows_sys::Win32::System::Threading::{
            GetCurrentThread, SetThreadPriority, THREAD_PRIORITY_ABOVE_NORMAL,
            THREAD_PRIORITY_BELOW_NORMAL, THREAD_PRIORITY_LOWEST, THREAD_PRIORITY_NORMAL,
        };

        let priority = if nice >= 10 {
            THREAD_PRIORITY_LOWEST
        } else if nice > 0 {
            THREAD_PRIORITY_BELOW_NORMAL
        } else if nice == 0 {
            THREAD_PRIORITY_NORMAL
        } else {
            THREAD_PRIORITY_ABOVE_NORMAL
        };

        // SAFETY: GetCurrentThread returns a pseudo-handle that needs no release, and
        // SetThreadPriority only mutates scheduler state.
        let ok = unsafe { SetThreadPriority(GetCurrentThread(), priority) };
        if ok != 0 {
            Ok(())
        } else {
            Err(format!(
                "SetThreadPriority failed: {}",
                std::io::Error::last_os_error()
            ))
        }
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = nice;
        Err("scan priority is not supported on this platform".to_string())
    }
}

impl Policy {
    /// Resolves the scan settings actually in force.
    ///
    /// Precedence is command line, then policy globals, then built-in default. The
    /// source is carried along so the CLI can show the operator which one won instead
    /// of leaving them to guess why their policy value had no effect.
    pub fn effective_scan_settings(&self, cli_throttle_mb_s: Option<u64>) -> EffectiveScanSettings {
        let defaults = PolicyGlobals::default();

        let hash_algorithm = match self.globals.default_hash.parse::<crate::HashAlgorithm>() {
            Ok(algo) if self.globals.default_hash != defaults.default_hash => Effective {
                value: algo,
                source: SettingSource::Policy,
            },
            Ok(algo) => Effective {
                value: algo,
                source: SettingSource::Default,
            },
            // An unparseable algorithm is caught by `policy lint`; fall back rather
            // than panicking in the sensor's startup path.
            Err(_) => Effective {
                value: crate::HashAlgorithm::Sha256,
                source: SettingSource::Default,
            },
        };

        let max_io_rate_mb_s = match cli_throttle_mb_s {
            Some(v) => Effective {
                value: v,
                source: SettingSource::CommandLine,
            },
            None if self.globals.max_io_rate_mb_s != defaults.max_io_rate_mb_s => Effective {
                value: self.globals.max_io_rate_mb_s,
                source: SettingSource::Policy,
            },
            None => Effective {
                value: defaults.max_io_rate_mb_s,
                source: SettingSource::Default,
            },
        };

        let scan_nice_priority = if self.globals.scan_nice_priority != defaults.scan_nice_priority {
            Effective {
                value: self.globals.scan_nice_priority,
                source: SettingSource::Policy,
            }
        } else {
            Effective {
                value: defaults.scan_nice_priority,
                source: SettingSource::Default,
            }
        };

        let sweep_interval_secs = if self.globals.realtime_fallback_sweep_interval
            != defaults.realtime_fallback_sweep_interval
        {
            Effective {
                value: self.globals.realtime_fallback_sweep_interval,
                source: SettingSource::Policy,
            }
        } else {
            Effective {
                value: defaults.realtime_fallback_sweep_interval,
                source: SettingSource::Default,
            }
        };

        EffectiveScanSettings {
            hash_algorithm,
            max_io_rate_mb_s,
            scan_nice_priority,
            sweep_interval_secs,
        }
    }

    /// Deserializes a Policy from a YAML string
    pub fn from_yaml_str(yaml_str: &str) -> Result<Self> {
        let policy: Policy = serde_yaml::from_str(yaml_str)?;
        Ok(policy)
    }

    /// Reads and deserializes a Policy from a YAML file
    pub fn from_yaml_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path.as_ref()).map_err(|e| OpenFimError::IoError {
            path: path.as_ref().to_path_buf(),
            source: e,
        })?;
        Self::from_yaml_str(&content)
    }

    /// Serializes the Policy to a canonical YAML formatted string
    pub fn to_yaml_string(&self) -> Result<String> {
        let s = serde_yaml::to_string(self)?;
        Ok(s)
    }

    /// Evaluates which rule applies to a given file path based on specificity precedence.
    ///
    /// This is the convenience / one-shot path: it compiles the policy's glob patterns
    /// on every call. Code that evaluates many paths — the sensor's event loop, a
    /// baseline sweep — must build a [`CompiledPolicy`] once and reuse it, otherwise
    /// every single filesystem event re-parses every pattern in the policy.
    pub fn find_matching_rule<'a>(&'a self, path: &Path) -> Option<&'a PolicyRule> {
        let compiled = CompiledPolicy::compile_rules(&self.rules);
        let cwd = std::env::current_dir().ok();
        CompiledPolicy::best_match_in(&compiled, &self.rules, cwd.as_deref(), path)
            .map(|idx| &self.rules[idx])
    }

    /// Returns true if the path is covered by any rule and not ignored
    pub fn is_monitored(&self, path: &Path) -> bool {
        self.find_matching_rule(path).is_some()
    }

    /// Gathers all distinct root base paths declared across rules for crawler/fanotify attachment
    pub fn get_monitored_roots(&self) -> Vec<PathBuf> {
        let mut roots = Vec::new();
        for rule in &self.rules {
            for p in &rule.paths {
                // If path has a glob wildcard like *, trim to base directory
                let clean_path = if let Some(idx) = p.find('*') {
                    p[..idx].trim_end_matches(['/', '\\']).to_string()
                } else {
                    p.clone()
                };
                let pb = PathBuf::from(clean_path);
                if !roots.contains(&pb) {
                    roots.push(pb);
                }
            }
        }
        roots
    }
}

/// A single rule target with its glob pattern and prefix forms precompiled.
#[derive(Debug, Clone)]
struct CompiledTarget {
    /// Normalized target text (forward slashes; lowercased on case-insensitive platforms).
    normalized: String,
    /// Normalized target with a trailing separator, for recursive prefix tests.
    with_slash: String,
    /// Absolute form, when the target was written relative to the working directory.
    absolute: Option<String>,
    /// Absolute form with a trailing separator.
    absolute_with_slash: Option<String>,
    /// Compiled glob, present only when the target actually contains wildcards.
    glob: Option<Pattern>,
    /// Specificity score used for precedence: longer target text wins.
    specificity: usize,
}

/// A rule with its ignore globs and targets compiled once.
#[derive(Debug, Clone)]
struct CompiledRule {
    recursive: bool,
    ignore: Vec<Pattern>,
    targets: Vec<CompiledTarget>,
}

/// A policy with every glob pattern compiled and the working directory resolved once.
///
/// Build this once and reuse it for every path evaluation. The naive alternative —
/// recompiling each rule's patterns and calling `std::env::current_dir()` inside the
/// match function — costs a syscall and a pattern parse per rule per filesystem
/// event, which dominates the sensor's cost under write-heavy load.
#[derive(Debug, Clone)]
pub struct CompiledPolicy {
    policy: Policy,
    rules: Vec<CompiledRule>,
    cwd: Option<PathBuf>,
}

/// Normalizes a path or pattern for comparison: forward slashes, and lowercase on
/// platforms whose filesystems are case-insensitive.
///
/// Case folding matters on Windows: `C:\Data\app.conf` and a policy target of
/// `C:/data/app.conf` name the same file, and a case-sensitive comparison would
/// leave it unmonitored.
fn normalize(text: &str) -> String {
    let s = text.replace('\\', "/");
    if cfg!(windows) {
        s.to_lowercase()
    } else {
        s
    }
}

fn normalize_path(path: &Path) -> String {
    normalize(&path.to_string_lossy())
}

impl CompiledPolicy {
    /// Compiles a policy for repeated evaluation.
    pub fn new(policy: Policy) -> Self {
        let rules = Self::compile_rules(&policy.rules);
        Self {
            cwd: std::env::current_dir().ok(),
            rules,
            policy,
        }
    }

    fn compile_rules(rules: &[PolicyRule]) -> Vec<CompiledRule> {
        let cwd = std::env::current_dir().ok();
        rules
            .iter()
            .map(|rule| {
                let ignore = rule
                    .ignore
                    .iter()
                    .filter_map(|pat| Pattern::new(&normalize(pat)).ok())
                    .collect();

                let targets = rule
                    .paths
                    .iter()
                    .map(|target| {
                        let normalized = normalize(target).trim_start_matches("./").to_string();
                        let with_slash = format!("{}/", normalized.trim_end_matches('/'));

                        let absolute = if Path::new(target).is_absolute() {
                            None
                        } else {
                            cwd.as_ref().map(|cd| normalize_path(&cd.join(target)))
                        };
                        let absolute_with_slash = absolute
                            .as_ref()
                            .map(|abs| format!("{}/", abs.trim_end_matches('/')));

                        let glob = if normalized.contains('*')
                            || normalized.contains('?')
                            || normalized.contains('[')
                        {
                            Pattern::new(&normalized).ok()
                        } else {
                            None
                        };

                        CompiledTarget {
                            specificity: normalized.len(),
                            normalized,
                            with_slash,
                            absolute,
                            absolute_with_slash,
                            glob,
                        }
                    })
                    .collect();

                CompiledRule {
                    recursive: rule.recursive,
                    ignore,
                    targets,
                }
            })
            .collect()
    }

    /// The underlying policy.
    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// Evaluates which rule applies to a path, honouring specificity precedence.
    pub fn find_matching_rule(&self, path: &Path) -> Option<&PolicyRule> {
        Self::best_match_in(&self.rules, &self.policy.rules, self.cwd.as_deref(), path)
            .map(|idx| &self.policy.rules[idx])
    }

    /// True when the path is covered by any rule and not ignored.
    pub fn is_monitored(&self, path: &Path) -> bool {
        self.find_matching_rule(path).is_some()
    }

    /// Returns the index of the winning rule, if any.
    ///
    /// Precedence: the longest matching target text wins (most specific), and
    /// severity breaks ties. Resolved in a single pass without allocating or
    /// sorting a candidate list, since this runs once per filesystem event.
    fn best_match_in(
        compiled_rules: &[CompiledRule],
        rules: &[PolicyRule],
        cwd: Option<&Path>,
        path: &Path,
    ) -> Option<usize> {
        let norm_path = normalize_path(path);
        let clean_path = norm_path.trim_start_matches("./");

        let rel_to_cwd = cwd.and_then(|cd| path.strip_prefix(cd).ok().map(normalize_path));

        let mut best: Option<(usize, usize, u32)> = None; // (rule index, specificity, severity)

        for (idx, compiled) in compiled_rules.iter().enumerate() {
            let rule = match rules.get(idx) {
                Some(r) => r,
                None => continue,
            };

            // 1. Ignore patterns are evaluated as globs only.
            //
            // A substring test here would be a security defect: an ignore entry of
            // `log` would silently stop monitoring `/etc/catalog.conf`, and the
            // operator would see nothing to indicate the path had been excluded.
            let ignored = compiled.ignore.iter().any(|pattern| {
                pattern.matches(&norm_path)
                    || pattern.matches(clean_path)
                    || rel_to_cwd.as_deref().is_some_and(|r| pattern.matches(r))
                    || path
                        .file_name()
                        .is_some_and(|n| pattern.matches(&normalize(&n.to_string_lossy())))
            });
            if ignored {
                continue;
            }

            // 2. Target matching.
            let mut rule_specificity: Option<usize> = None;
            for target in &compiled.targets {
                let exact = norm_path == target.normalized
                    || clean_path == target.normalized
                    || rel_to_cwd.as_deref() == Some(target.normalized.as_str())
                    || target.absolute.as_deref() == Some(norm_path.as_str());

                let prefix = compiled.recursive
                    && (norm_path.starts_with(&target.with_slash)
                        || clean_path.starts_with(&target.with_slash)
                        || rel_to_cwd
                            .as_deref()
                            .is_some_and(|r| r.starts_with(&target.with_slash))
                        || target
                            .absolute_with_slash
                            .as_deref()
                            .is_some_and(|abs| norm_path.starts_with(abs)));

                let globbed = target
                    .glob
                    .as_ref()
                    .is_some_and(|g| g.matches(&norm_path) || g.matches(clean_path));

                if exact || prefix || globbed {
                    rule_specificity = Some(
                        rule_specificity
                            .map_or(target.specificity, |s: usize| s.max(target.specificity)),
                    );
                }
            }

            if let Some(specificity) = rule_specificity {
                let candidate = (idx, specificity, rule.severity);
                best = match best {
                    None => Some(candidate),
                    Some((_, best_spec, best_sev))
                        if specificity > best_spec
                            || (specificity == best_spec && rule.severity > best_sev) =>
                    {
                        Some(candidate)
                    }
                    other => other,
                };
            }
        }

        best.map(|(idx, _, _)| idx)
    }
}

/// Ed25519 Policy Signer and Key Utility
pub struct PolicySigner;

impl PolicySigner {
    /// Generates a cryptographically secure fresh Ed25519 signing keypair
    pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();
        (signing_key, verifying_key)
    }

    /// Signs policy byte data using Ed25519
    pub fn sign(data: &[u8], signing_key: &SigningKey) -> Signature {
        signing_key.sign(data)
    }

    /// Signs a policy file on disk and returns the raw signature
    pub fn sign_file<P: AsRef<Path>>(
        policy_path: P,
        signing_key: &SigningKey,
    ) -> Result<Signature> {
        let data = fs::read(policy_path.as_ref()).map_err(|e| OpenFimError::IoError {
            path: policy_path.as_ref().to_path_buf(),
            source: e,
        })?;
        Ok(Self::sign(&data, signing_key))
    }

    /// Converts a VerifyingKey (public key) to a 64-character lowercase hex string
    pub fn pubkey_to_hex(key: &VerifyingKey) -> String {
        hex::encode(key.as_bytes())
    }

    /// Parses a VerifyingKey from a 64-character hex string
    pub fn pubkey_from_hex(hex_str: &str) -> Result<VerifyingKey> {
        let clean = hex_str.trim();
        let bytes = hex::decode(clean)?;
        if bytes.len() != 32 {
            return Err(OpenFimError::InvalidKeyFormat(format!(
                "Expected 32-byte Ed25519 public key, got {} bytes",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        VerifyingKey::from_bytes(&arr).map_err(|e| OpenFimError::InvalidKeyFormat(e.to_string()))
    }

    /// Converts a SigningKey (private key) to a 64-character lowercase hex string
    pub fn privkey_to_hex(key: &SigningKey) -> String {
        hex::encode(key.as_bytes())
    }

    /// Parses a SigningKey from a 64-character hex string
    pub fn privkey_from_hex(hex_str: &str) -> Result<SigningKey> {
        let clean = hex_str.trim();
        let bytes = hex::decode(clean)?;
        if bytes.len() != 32 {
            return Err(OpenFimError::InvalidKeyFormat(format!(
                "Expected 32-byte Ed25519 private key seed, got {} bytes",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(SigningKey::from_bytes(&arr))
    }

    /// Formats signature as a 128-character lowercase hex string
    pub fn signature_to_hex(sig: &Signature) -> String {
        hex::encode(sig.to_bytes())
    }

    /// Parses a Signature from a 128-character hex string
    pub fn signature_from_hex(hex_str: &str) -> Result<Signature> {
        let clean = hex_str.trim();
        let bytes = hex::decode(clean)?;
        if bytes.len() != 64 {
            return Err(OpenFimError::InvalidSignatureFormat(format!(
                "Expected 64-byte Ed25519 signature, got {} bytes",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&bytes);
        Ok(Signature::from_bytes(&arr))
    }
}

/// Ed25519 Cryptographic Policy Verifier
pub struct PolicyVerifier;

impl PolicyVerifier {
    /// Verifies policy byte slice against an Ed25519 signature and public verifying key
    pub fn verify(data: &[u8], signature: &Signature, verifying_key: &VerifyingKey) -> Result<()> {
        verifying_key
            .verify(data, signature)
            .map_err(|e| OpenFimError::SignatureVerificationFailed(e.to_string()))
    }

    /// Verifies a policy file against a detached signature file (.sig)
    pub fn verify_file<P: AsRef<Path>, S: AsRef<Path>>(
        policy_path: P,
        sig_path: S,
        verifying_key: &VerifyingKey,
    ) -> Result<Policy> {
        let policy_bytes = fs::read(policy_path.as_ref()).map_err(|e| OpenFimError::IoError {
            path: policy_path.as_ref().to_path_buf(),
            source: e,
        })?;

        let sig_raw = fs::read(sig_path.as_ref()).map_err(|e| OpenFimError::IoError {
            path: sig_path.as_ref().to_path_buf(),
            source: e,
        })?;

        let signature = if sig_raw.len() == 64 {
            let mut arr = [0u8; 64];
            arr.copy_from_slice(&sig_raw);
            Signature::from_bytes(&arr)
        } else {
            // Attempt hex string parsing
            let sig_str = String::from_utf8_lossy(&sig_raw);
            PolicySigner::signature_from_hex(&sig_str)?
        };

        Self::verify(&policy_bytes, &signature, verifying_key)?;

        let yaml_str = String::from_utf8_lossy(&policy_bytes);
        Policy::from_yaml_str(&yaml_str)
    }

    /// Verifies a policy file by checking the default `<policy_path>.sig` sibling file
    pub fn verify_file_auto<P: AsRef<Path>>(
        policy_path: P,
        verifying_key: &VerifyingKey,
    ) -> Result<Policy> {
        let mut sig_path = policy_path.as_ref().to_path_buf();
        let ext = sig_path.extension().map_or("sig".to_string(), |e| {
            format!("{}.sig", e.to_string_lossy())
        });
        sig_path.set_extension(ext);

        Self::verify_file(policy_path, sig_path, verifying_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_ENTERPRISE_POLICY: &str = r#"
version: "1.0"
policy_id: "pol-linux-enterprise-server-v1"
name: "CIS Benchmark & PCI DSS 11.5 Defensive Linux Policy"
author: "Principal Security Architect"
signature_algorithm: "ed25519"

globals:
  default_hash: "sha256"
  max_io_rate_mb_s: 25
  scan_nice_priority: 10
  realtime_fallback_sweep_interval: 7200

rules:
  - id: "ETC_AUTH_CRITICAL"
    description: "Monitors core authentication credentials and privilege escalation gates"
    paths:
      - "/etc/passwd"
      - "/etc/shadow"
      - "/etc/sudoers"
      - "/etc/pam.d"
    recursive: true
    mode: "realtime"
    checks:
      hash: true
      size: true
      permissions: true
      ownership: true
      timestamps: false
      attributes: true
      xattrs: true
    nodiff: true
    severity: 10
    whodata: true
    active_response:
      action: "none"

  - id: "SYSTEM_BINARIES_IMMUTABLE"
    description: "Guards root-owned system binaries against rootkits and trojans"
    paths:
      - "/bin"
      - "/sbin"
      - "/usr/bin"
      - "/usr/lib"
    recursive: true
    mode: "realtime"
    checks:
      hash: true
      size: true
      permissions: true
      ownership: true
      timestamps: false
      attributes: true
      xattrs: true
    nodiff: true
    ignore:
      - "/usr/lib/locale/**"
    severity: 9
    whodata: true
    active_response:
      action: "quarantine"

  - id: "SSH_AUTHORIZED_KEYS"
    description: "Detects unauthorized root authorized_keys injection"
    paths:
      - "/root/.ssh"
      - "/home/*/.ssh"
    recursive: true
    mode: "realtime"
    checks:
      hash: true
      size: true
      permissions: true
      ownership: true
      timestamps: false
      attributes: true
      xattrs: true
    nodiff: false
    ignore:
      - "**/.ssh/known_hosts*"
    severity: 9
    whodata: true
    active_response:
      action: "restore_baseline"
"#;

    #[test]
    fn test_parse_enterprise_policy_yaml() {
        let policy =
            Policy::from_yaml_str(SAMPLE_ENTERPRISE_POLICY).expect("Failed to parse policy YAML");

        assert_eq!(policy.version, "1.0");
        assert_eq!(policy.policy_id, "pol-linux-enterprise-server-v1");
        assert_eq!(policy.globals.default_hash, "sha256");
        assert_eq!(policy.globals.max_io_rate_mb_s, 25);
        assert_eq!(policy.rules.len(), 3);

        // Check Rule 1
        let r1 = &policy.rules[0];
        assert_eq!(r1.id, "ETC_AUTH_CRITICAL");
        assert_eq!(r1.severity, 10);
        assert!(r1.nodiff);
        assert!(r1.checks.hash);
        assert!(!r1.checks.timestamps);
        assert_eq!(r1.active_response.action, ActiveResponseAction::None);

        // Check Rule 2
        let r2 = &policy.rules[1];
        assert_eq!(r2.id, "SYSTEM_BINARIES_IMMUTABLE");
        assert_eq!(r2.severity, 9);
        assert_eq!(r2.active_response.action, ActiveResponseAction::Quarantine);
        assert_eq!(r2.ignore, vec!["/usr/lib/locale/**"]);

        // Check Rule 3
        let r3 = &policy.rules[2];
        assert_eq!(r3.id, "SSH_AUTHORIZED_KEYS");
        assert!(!r3.nodiff);
        assert_eq!(
            r3.active_response.action,
            ActiveResponseAction::RestoreBaseline
        );
    }

    #[test]
    fn test_ed25519_sign_and_verify_policy() {
        let (signing_key, verifying_key) = PolicySigner::generate_keypair();
        let policy_bytes = SAMPLE_ENTERPRISE_POLICY.as_bytes();

        // 1. Sign policy
        let signature = PolicySigner::sign(policy_bytes, &signing_key);
        let sig_hex = PolicySigner::signature_to_hex(&signature);
        let pub_hex = PolicySigner::pubkey_to_hex(&verifying_key);

        assert_eq!(sig_hex.len(), 128);
        assert_eq!(pub_hex.len(), 64);

        // 2. Verify with valid key
        let parsed_sig = PolicySigner::signature_from_hex(&sig_hex).expect("Valid signature hex");
        let parsed_pub = PolicySigner::pubkey_from_hex(&pub_hex).expect("Valid pubkey hex");

        PolicyVerifier::verify(policy_bytes, &parsed_sig, &parsed_pub)
            .expect("Valid signature must pass");

        // 3. Reject tampered policy data
        let mut tampered = SAMPLE_ENTERPRISE_POLICY.to_string();
        tampered.push_str("\n# Unauthorized injected comment");
        let verify_result = PolicyVerifier::verify(tampered.as_bytes(), &parsed_sig, &parsed_pub);
        assert!(
            verify_result.is_err(),
            "Tampered policy must fail signature verification"
        );

        // 4. Reject signature verified against mismatched public key
        let (_other_signing, other_verifying) = PolicySigner::generate_keypair();
        let wrong_key_result = PolicyVerifier::verify(policy_bytes, &parsed_sig, &other_verifying);
        assert!(
            wrong_key_result.is_err(),
            "Verifying with unrelated key must fail"
        );
    }

    #[test]
    fn test_rule_path_matching_and_precedence() {
        let policy = Policy::from_yaml_str(SAMPLE_ENTERPRISE_POLICY).expect("Parse error");

        // 1. /etc/shadow should match ETC_AUTH_CRITICAL
        let r_shadow = policy
            .find_matching_rule(Path::new("/etc/shadow"))
            .expect("Should match");
        assert_eq!(r_shadow.id, "ETC_AUTH_CRITICAL");
        assert!(r_shadow.nodiff);

        // 2. /usr/bin/curl should match SYSTEM_BINARIES_IMMUTABLE
        let r_bin = policy
            .find_matching_rule(Path::new("/usr/bin/curl"))
            .expect("Should match");
        assert_eq!(r_bin.id, "SYSTEM_BINARIES_IMMUTABLE");

        // 3. /usr/lib/locale/en_US should be IGNORED by SYSTEM_BINARIES_IMMUTABLE
        assert!(!policy.is_monitored(Path::new("/usr/lib/locale/en_US/LC_MESSAGES")));

        // 4. /root/.ssh/authorized_keys should match SSH_AUTHORIZED_KEYS
        let r_ssh = policy
            .find_matching_rule(Path::new("/root/.ssh/authorized_keys"))
            .expect("Should match");
        assert_eq!(r_ssh.id, "SSH_AUTHORIZED_KEYS");

        // 5. /root/.ssh/known_hosts should be IGNORED
        assert!(!policy.is_monitored(Path::new("/root/.ssh/known_hosts")));

        // 6. An unmonitored path
        assert!(!policy.is_monitored(Path::new("/opt/custom_app/data.txt")));
    }

    fn policy_with_ignore(ignore: &[&str]) -> Policy {
        Policy {
            version: "1.0".to_string(),
            policy_id: "test".to_string(),
            name: "test".to_string(),
            author: "test".to_string(),
            signature_algorithm: "ed25519".to_string(),
            globals: PolicyGlobals::default(),
            rules: vec![PolicyRule {
                id: "R1".to_string(),
                description: "d".to_string(),
                paths: vec!["/etc".to_string()],
                recursive: true,
                mode: RuleMode::default(),
                checks: RuleChecks::default(),
                nodiff: false,
                ignore: ignore.iter().map(|s| s.to_string()).collect(),
                severity: 7,
                whodata: true,
                active_response: ActiveResponseConfig::default(),
            }],
        }
    }

    #[test]
    fn test_ignore_entry_is_not_treated_as_a_substring() {
        // Regression guard for a security defect: a substring-based ignore test made a
        // bare token such as "log" silently unmonitor every path containing it, e.g.
        // /etc/catalog.conf. Ignore entries are globs and must match as globs only.
        let policy = policy_with_ignore(&["log"]);

        assert!(
            policy.is_monitored(Path::new("/etc/catalog.conf")),
            "an unrelated path was excluded because the ignore entry appeared as a substring"
        );
        assert!(
            policy.is_monitored(Path::new("/etc/rsyslog.conf")),
            "an unrelated path was excluded because the ignore entry appeared as a substring"
        );
        // A literal, exact filename still matches.
        assert!(!policy.is_monitored(Path::new("log")));
    }

    #[test]
    fn test_glob_ignore_entries_still_work() {
        let policy = policy_with_ignore(&["*.tmp", "**/cache/**"]);
        assert!(!policy.is_monitored(Path::new("/etc/session.tmp")));
        assert!(!policy.is_monitored(Path::new("/etc/cache/objects.bin")));
        assert!(policy.is_monitored(Path::new("/etc/passwd")));
    }

    #[test]
    fn test_longest_target_wins_precedence() {
        let mut policy = policy_with_ignore(&[]);
        policy.rules[0].severity = 1;
        policy.rules.push(PolicyRule {
            id: "SPECIFIC".to_string(),
            description: "d".to_string(),
            paths: vec!["/etc/ssh".to_string()],
            recursive: true,
            mode: RuleMode::default(),
            checks: RuleChecks::default(),
            nodiff: false,
            ignore: vec![],
            severity: 1,
            whodata: true,
            active_response: ActiveResponseConfig::default(),
        });

        let hit = policy
            .find_matching_rule(Path::new("/etc/ssh/sshd_config"))
            .unwrap();
        assert_eq!(hit.id, "SPECIFIC", "the more specific rule must win");
    }

    #[test]
    fn test_severity_breaks_specificity_ties() {
        let mut policy = policy_with_ignore(&[]);
        policy.rules[0].severity = 3;
        let mut high = policy.rules[0].clone();
        high.id = "HIGH".to_string();
        high.severity = 9;
        policy.rules.push(high);

        let hit = policy.find_matching_rule(Path::new("/etc/passwd")).unwrap();
        assert_eq!(hit.id, "HIGH");
    }

    #[cfg(windows)]
    #[test]
    fn test_windows_path_matching_is_case_insensitive() {
        // NTFS is case-insensitive, so a case-sensitive comparison would leave
        // C:\Data\app.conf unmonitored under a policy target of C:/data.
        let mut policy = policy_with_ignore(&[]);
        policy.rules[0].paths = vec!["C:/data".to_string()];

        assert!(policy.is_monitored(Path::new(r"C:\Data\app.conf")));
        assert!(policy.is_monitored(Path::new(r"c:\DATA\sub\other.conf")));
    }

    #[test]
    fn test_compiled_policy_agrees_with_one_shot_matching() {
        let policy = policy_with_ignore(&["*.tmp"]);
        let compiled = CompiledPolicy::new(policy.clone());

        for probe in [
            "/etc/passwd",
            "/etc/ssh/sshd_config",
            "/etc/scratch.tmp",
            "/var/log/syslog",
        ] {
            let p = Path::new(probe);
            assert_eq!(
                policy.find_matching_rule(p).map(|r| r.id.clone()),
                compiled.find_matching_rule(p).map(|r| r.id.clone()),
                "compiled and one-shot matching disagreed on {}",
                probe
            );
        }
    }

    // ---------------- Active response ----------------

    #[test]
    fn test_restore_baseline_declines_rather_than_quarantining() {
        // The dangerous case: a restore with no pristine copy available must NOT fall
        // back to quarantine, because quarantine moves the live file away. That turns
        // "put the good copy back" into "delete the file".
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("production.env");
        std::fs::write(&target, b"live production data").unwrap();

        let empty_store = BackupStore::open_or_create(dir.path().join("store")).unwrap();

        let outcome = ActiveResponseAction::RestoreBaseline
            .execute(&target, Some(&empty_store))
            .unwrap();

        assert!(
            !outcome.was_applied(),
            "a restore with no backup must not report success"
        );
        assert!(
            target.exists(),
            "the live file was moved away by a failed restore; this is data loss"
        );
        assert_eq!(
            std::fs::read(&target).unwrap(),
            b"live production data",
            "file contents were altered by a declined restore"
        );
    }

    #[test]
    fn test_restore_baseline_restores_from_backup() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("app.conf");
        std::fs::write(&target, b"pristine").unwrap();

        let mut store = BackupStore::open_or_create(dir.path().join("store")).unwrap();
        store.store_file(&target, "v1").unwrap();

        std::fs::write(&target, b"TAMPERED BY ADVERSARY").unwrap();

        let outcome = ActiveResponseAction::RestoreBaseline
            .execute(&target, Some(&store))
            .unwrap();

        assert!(outcome.was_applied(), "{}", outcome.message());
        assert_eq!(std::fs::read(&target).unwrap(), b"pristine");
    }

    #[test]
    fn test_restore_leaves_no_temporary_file_behind() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("app.conf");
        std::fs::write(&target, b"good").unwrap();

        let mut store = BackupStore::open_or_create(dir.path().join("store")).unwrap();
        store.store_file(&target, "v1").unwrap();
        std::fs::write(&target, b"bad").unwrap();

        ActiveResponseAction::RestoreBaseline
            .execute(&target, Some(&store))
            .unwrap();

        let strays: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains("openfim-restore"))
            .collect();
        assert!(strays.is_empty(), "restore left a temporary file behind");
    }

    #[test]
    fn test_quarantine_moves_the_file_aside() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("malware.bin");
        std::fs::write(&target, b"payload").unwrap();

        let outcome = ActiveResponseAction::Quarantine
            .execute(&target, None)
            .unwrap();

        assert!(outcome.was_applied(), "{}", outcome.message());
        assert!(
            !target.exists(),
            "quarantined file should no longer be at its path"
        );
        assert!(dir.path().join(".quarantine").is_dir());
    }

    #[test]
    fn test_kill_process_does_not_claim_false_success() {
        // Reporting "dispatched" for work never performed would write a false
        // containment record into the audit trail.
        let outcome = ActiveResponseAction::KillProcess
            .execute("/tmp/whatever", None)
            .unwrap();
        assert!(!outcome.was_applied());
        assert!(outcome.message().contains("attribution"));
    }

    #[test]
    fn test_remediation_circuit_breaker_opens_after_limit() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("f.conf");
        std::fs::write(&target, b"good").unwrap();

        let mut store = BackupStore::open_or_create(dir.path().join("store")).unwrap();
        store.store_file(&target, "v1").unwrap();

        let mut guard = RemediationGuard::new(3);
        let mut applied = 0;
        let mut declined = 0;

        for _ in 0..6 {
            std::fs::write(&target, b"bad").unwrap();
            let outcome = guard
                .execute(ActiveResponseAction::RestoreBaseline, &target, Some(&store))
                .unwrap();
            if outcome.was_applied() {
                applied += 1;
            } else {
                declined += 1;
            }
        }

        assert_eq!(
            applied, 3,
            "circuit breaker did not cap remediations at the limit"
        );
        assert_eq!(declined, 3);
        assert_eq!(guard.remaining(), 0);
    }

    #[test]
    fn test_remediation_guard_window_expiry_restores_budget() {
        let mut guard = RemediationGuard::with_window(1, std::time::Duration::from_millis(80));
        assert!(guard.try_consume());
        assert!(
            !guard.try_consume(),
            "second attempt inside the window must be refused"
        );
        std::thread::sleep(std::time::Duration::from_millis(120));
        assert!(
            guard.try_consume(),
            "budget should be available again once the window has rolled over"
        );
    }

    #[test]
    fn test_remediation_guard_zero_limit_disables_response() {
        let mut guard = RemediationGuard::new(0);
        let outcome = guard
            .execute(ActiveResponseAction::Quarantine, "/tmp/x", None)
            .unwrap();
        assert!(!outcome.was_applied());
    }

    #[test]
    fn test_remediation_guard_passes_through_none_without_spending_budget() {
        let mut guard = RemediationGuard::new(1);
        let outcome = guard
            .execute(ActiveResponseAction::None, "/tmp/x", None)
            .unwrap();
        assert_eq!(outcome, RemediationOutcome::NotConfigured);
        assert_eq!(
            guard.remaining(),
            1,
            "a no-op action must not consume circuit-breaker budget"
        );
    }
}
