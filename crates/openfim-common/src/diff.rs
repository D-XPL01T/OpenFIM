//! Bounded content diff capture, and the suppression that must accompany it.
//!
//! # The hazard
//!
//! Diff capture is the one feature in this project that makes OpenFIM *write monitored
//! file contents into its own database*. Everything else stores digests. That inverts
//! the usual risk: a monitor watching `/etc/shadow`, `*.pem` and `.env` would copy
//! exactly the material it exists to protect into an unencrypted SQLite file, and into
//! an audit log designed to be exported off-host.
//!
//! This is why the plan requires diff capture and `nodiff` to land together
//! (§18.6.4 constraint 4). Shipping capture first would create a window in which the
//! tool leaks secrets by design.
//!
//! # The guarantees
//!
//! 1. **Opt-out is the default for secret-shaped paths.** [`Policy`] resolves
//!    `nodiff` through [`crate::policy::PolicyRule::nodiff_effective`], which returns
//!    true for paths matching a secret heuristic unless the operator explicitly wrote
//!    `nodiff: false`. Forgetting to set it fails safe.
//! 2. **Suppression happens before capture, not after.** When `nodiff` is in force no
//!    diff is produced at all, so there is no window in which the content exists in
//!    memory destined for the database.
//! 3. **Binary content is never captured.** A NUL byte in either side disables the
//!    diff; a binary diff is useless to a human and is just an exfiltration channel.
//! 4. **Output is bounded.** Diffs are truncated to [`MAX_DIFF_BYTES`], so a large
//!    file cannot be siphoned through the event log a few kilobytes at a time.
//!
//! # Where the "before" content comes from
//!
//! The baseline stores digests, not contents, so there is nothing to diff against on
//! its own. The pristine copy in the [`crate::backup::BackupStore`] is the only source
//! of the previous bytes. Without a backup store configured, OpenFIM reports *that* a
//! file changed and by which digests, with no line detail — which is the honest
//! outcome, not a silent omission.

use crate::policy::PolicyRule;

/// Hard cap on a captured diff, in bytes.
///
/// Bounds how much file content can ever reach the database through one event.
pub const MAX_DIFF_BYTES: usize = 4096;

/// Maximum size of either side considered for diffing.
///
/// Beyond this, a line-level diff is not useful to an operator and the work is wasted.
pub const MAX_DIFFABLE_FILE_BYTES: usize = 1024 * 1024;

/// Why no diff was captured. Recorded instead of the diff, so the absence is explained
/// rather than looking like an oversight.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiffOutcome {
    /// A bounded textual diff.
    Captured { diff: String, truncated: bool },
    /// Suppressed because the rule is (or defaults to) `nodiff`.
    SuppressedByPolicy,
    /// One or both sides are binary.
    BinaryContent,
    /// No pristine copy was available to diff against.
    NoPreviousContent,
    /// One or both sides exceed the diffable size limit.
    TooLarge,
    /// The content is identical, so there is nothing to show.
    Identical,
}

impl DiffOutcome {
    /// The diff text, when one was captured.
    pub fn diff(&self) -> Option<&str> {
        match self {
            DiffOutcome::Captured { diff, .. } => Some(diff.as_str()),
            _ => None,
        }
    }

    /// True when file content was placed in the result.
    pub fn contains_content(&self) -> bool {
        matches!(self, DiffOutcome::Captured { .. })
    }

    /// Operator-facing explanation, suitable for the event record.
    pub fn explain(&self) -> &'static str {
        match self {
            DiffOutcome::Captured { .. } => "content diff captured",
            DiffOutcome::SuppressedByPolicy => {
                "content diff suppressed: this path is marked nodiff, so its contents \
                 are never written to the event log"
            }
            DiffOutcome::BinaryContent => "content diff skipped: binary content",
            DiffOutcome::NoPreviousContent => {
                "content diff unavailable: no pristine copy of the previous content \
                 exists to compare against"
            }
            DiffOutcome::TooLarge => "content diff skipped: file exceeds the diffable size limit",
            DiffOutcome::Identical => "content is identical",
        }
    }
}

/// True when the bytes look binary, using the same NUL-byte heuristic as `diff(1)`.
fn looks_binary(bytes: &[u8]) -> bool {
    bytes.contains(&0)
}

/// Produces a bounded line diff between two byte buffers.
///
/// `rule` decides suppression: this function must be given the rule so that the
/// `nodiff` decision is made *before* any content is assembled.
pub fn capture_for_rule(rule: &PolicyRule, path: &str, old: &[u8], new: &[u8]) -> DiffOutcome {
    // Suppression first, always. No content is touched for a nodiff path.
    if rule.nodiff_effective(path) {
        return DiffOutcome::SuppressedByPolicy;
    }
    capture(old, new)
}

/// Produces a bounded line diff, with no policy consultation.
///
/// Prefer [`capture_for_rule`]. This exists for callers that have already resolved
/// suppression, and for tests.
pub fn capture(old: &[u8], new: &[u8]) -> DiffOutcome {
    if old == new {
        return DiffOutcome::Identical;
    }
    if old.len() > MAX_DIFFABLE_FILE_BYTES || new.len() > MAX_DIFFABLE_FILE_BYTES {
        return DiffOutcome::TooLarge;
    }
    if looks_binary(old) || looks_binary(new) {
        return DiffOutcome::BinaryContent;
    }

    let old_text = String::from_utf8_lossy(old);
    let new_text = String::from_utf8_lossy(new);

    let old_lines: Vec<&str> = old_text.lines().collect();
    let new_lines: Vec<&str> = new_text.lines().collect();

    let mut out = String::new();
    let mut truncated = false;

    // A simple line-level diff: common prefix, common suffix, and the changed middle.
    // Deliberately not a full Myers diff — the goal is to show an operator what
    // changed, and every additional line of output is more monitored content crossing
    // into the database.
    let prefix = old_lines
        .iter()
        .zip(new_lines.iter())
        .take_while(|(a, b)| a == b)
        .count();

    let max_suffix = (old_lines.len().min(new_lines.len())) - prefix;
    let suffix = (0..max_suffix)
        .take_while(|i| old_lines[old_lines.len() - 1 - i] == new_lines[new_lines.len() - 1 - i])
        .count();

    let old_changed = &old_lines[prefix..old_lines.len() - suffix];
    let new_changed = &new_lines[prefix..new_lines.len() - suffix];

    let header = format!(
        "@@ -{},{} +{},{} @@\n",
        prefix + 1,
        old_changed.len(),
        prefix + 1,
        new_changed.len()
    );
    out.push_str(&header);

    for line in old_changed {
        if !push_bounded(&mut out, '-', line) {
            truncated = true;
            break;
        }
    }
    if !truncated {
        for line in new_changed {
            if !push_bounded(&mut out, '+', line) {
                truncated = true;
                break;
            }
        }
    }

    if truncated {
        out.push_str("... [diff truncated to stay within the event size limit]\n");
    }

    DiffOutcome::Captured {
        diff: out,
        truncated,
    }
}

/// Appends one diff line, refusing to exceed the byte cap.
fn push_bounded(out: &mut String, marker: char, line: &str) -> bool {
    // +2 for the marker and the newline.
    if out.len() + line.len() + 2 > MAX_DIFF_BYTES {
        return false;
    }
    out.push(marker);
    out.push_str(line);
    out.push('\n');
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{ActiveResponseConfig, RuleChecks, RuleMode};

    fn rule_with_nodiff(nodiff: Option<bool>) -> PolicyRule {
        PolicyRule {
            id: "R1".to_string(),
            description: "d".to_string(),
            paths: vec!["/etc".to_string()],
            recursive: true,
            mode: RuleMode::Realtime,
            checks: RuleChecks::default(),
            nodiff,
            ignore: vec![],
            severity: 5,
            whodata: false,
            active_response: ActiveResponseConfig::default(),
        }
    }

    // ---- The security property that gates this whole feature ----

    #[test]
    fn secret_paths_are_suppressed_by_default() {
        // Forgetting to set nodiff must fail safe. This is the guarantee that makes it
        // acceptable for OpenFIM to write file contents anywhere at all.
        let rule = rule_with_nodiff(None);

        for path in [
            "/etc/shadow",
            "/root/.ssh/id_rsa",
            "/app/.env",
            "/certs/server.pem",
            "/secrets/db_password.txt",
            "C:/keys/private.pfx",
        ] {
            let outcome = capture_for_rule(&rule, path, b"old secret\n", b"new secret\n");
            assert_eq!(
                outcome,
                DiffOutcome::SuppressedByPolicy,
                "{} was not suppressed by default; its contents would reach the database",
                path
            );
            assert!(!outcome.contains_content());
        }
    }

    #[test]
    fn no_secret_value_appears_in_a_suppressed_outcome() {
        // The strongest form of the check: the literal secret must not appear anywhere
        // in the result, including in an explanatory message.
        let rule = rule_with_nodiff(None);
        let secret = b"ENCRYPTION_KEY=0xDEADBEEFCAFE\n";
        let outcome = capture_for_rule(&rule, "/app/.env", b"ENCRYPTION_KEY=old\n", secret);

        let rendered = format!("{:?} {}", outcome, outcome.explain());
        assert!(
            !rendered.contains("DEADBEEFCAFE"),
            "a suppressed diff leaked secret content: {}",
            rendered
        );
        assert_eq!(outcome.diff(), None);
    }

    #[test]
    fn explicit_nodiff_false_overrides_the_heuristic() {
        // An operator who deliberately wants diffs on a secret-shaped path can have
        // them; the default is safe, not immovable.
        let rule = rule_with_nodiff(Some(false));
        let outcome = capture_for_rule(&rule, "/etc/shadow", b"a\n", b"b\n");
        assert!(outcome.contains_content());
    }

    #[test]
    fn explicit_nodiff_true_suppresses_an_ordinary_path() {
        let rule = rule_with_nodiff(Some(true));
        let outcome = capture_for_rule(&rule, "/etc/hosts", b"a\n", b"b\n");
        assert_eq!(outcome, DiffOutcome::SuppressedByPolicy);
    }

    #[test]
    fn ordinary_paths_are_diffed_when_unset() {
        let rule = rule_with_nodiff(None);
        let outcome = capture_for_rule(&rule, "/etc/hosts", b"127.0.0.1 a\n", b"127.0.0.1 b\n");
        assert!(outcome.contains_content());
    }

    // ---- Bounding and content safety ----

    #[test]
    fn binary_content_is_never_captured() {
        // A binary diff is useless to a human and is purely an exfiltration channel.
        let outcome = capture(b"text\n", b"bin\0ary\n");
        assert_eq!(outcome, DiffOutcome::BinaryContent);
        assert!(!outcome.contains_content());

        assert_eq!(capture(b"\0old", b"new\n"), DiffOutcome::BinaryContent);
    }

    #[test]
    fn output_is_bounded_even_for_a_wholly_rewritten_file() {
        // Without a cap, a large file could be siphoned through the event log.
        let old: Vec<u8> = (0..5000)
            .map(|i| format!("old line {}\n", i))
            .collect::<String>()
            .into_bytes();
        let new: Vec<u8> = (0..5000)
            .map(|i| format!("new line {}\n", i))
            .collect::<String>()
            .into_bytes();

        let outcome = capture(&old, &new);
        let diff = outcome.diff().expect("a bounded diff should be produced");
        assert!(
            diff.len() <= MAX_DIFF_BYTES + 80,
            "diff was {} bytes, exceeding the {} byte cap",
            diff.len(),
            MAX_DIFF_BYTES
        );
        assert!(
            matches!(
                outcome,
                DiffOutcome::Captured {
                    truncated: true,
                    ..
                }
            ),
            "a capped diff must report that it was truncated"
        );
        assert!(diff.contains("truncated"));
    }

    #[test]
    fn oversized_files_are_refused_outright() {
        let big = vec![b'a'; MAX_DIFFABLE_FILE_BYTES + 1];
        assert_eq!(capture(&big, b"small\n"), DiffOutcome::TooLarge);
        assert_eq!(capture(b"small\n", &big), DiffOutcome::TooLarge);
    }

    #[test]
    fn identical_content_reports_identical() {
        assert_eq!(capture(b"same\n", b"same\n"), DiffOutcome::Identical);
    }

    // ---- Diff correctness ----

    #[test]
    fn diff_shows_only_the_changed_lines() {
        let old = b"keep one\nkeep two\nCHANGE ME\nkeep three\n";
        let new = b"keep one\nkeep two\nCHANGED\nkeep three\n";

        let diff = capture(old, new).diff().unwrap().to_string();
        assert!(diff.contains("-CHANGE ME"), "{}", diff);
        assert!(diff.contains("+CHANGED"), "{}", diff);
        assert!(
            !diff.contains("keep one"),
            "unchanged context was included, needlessly copying content: {}",
            diff
        );
    }

    #[test]
    fn appended_line_is_shown_as_an_addition() {
        let diff = capture(b"one\n", b"one\ntwo\n").diff().unwrap().to_string();
        assert!(diff.contains("+two"), "{}", diff);
        assert!(!diff.contains("-one"), "{}", diff);
    }

    #[test]
    fn removed_line_is_shown_as_a_deletion() {
        let diff = capture(b"one\ntwo\n", b"one\n").diff().unwrap().to_string();
        assert!(diff.contains("-two"), "{}", diff);
    }

    #[test]
    fn diff_has_a_hunk_header() {
        let diff = capture(b"a\n", b"b\n").diff().unwrap().to_string();
        assert!(diff.starts_with("@@ "), "{}", diff);
    }

    #[test]
    fn empty_to_content_is_handled() {
        let outcome = capture(b"", b"new content\n");
        assert!(outcome.contains_content());
        assert!(outcome.diff().unwrap().contains("+new content"));
    }

    #[test]
    fn content_to_empty_is_handled() {
        let outcome = capture(b"old content\n", b"");
        assert!(outcome.contains_content());
        assert!(outcome.diff().unwrap().contains("-old content"));
    }

    #[test]
    fn invalid_utf8_does_not_panic() {
        // Lossy conversion, not a panic: a mangled text file is still worth diffing.
        let outcome = capture(b"valid\n", b"inv\xffalid\n");
        assert!(outcome.contains_content() || outcome == DiffOutcome::BinaryContent);
    }

    #[test]
    fn every_outcome_explains_itself() {
        for outcome in [
            DiffOutcome::SuppressedByPolicy,
            DiffOutcome::BinaryContent,
            DiffOutcome::NoPreviousContent,
            DiffOutcome::TooLarge,
            DiffOutcome::Identical,
            DiffOutcome::Captured {
                diff: String::new(),
                truncated: false,
            },
        ] {
            assert!(
                !outcome.explain().is_empty(),
                "an absent diff must be explained, not silently omitted"
            );
        }
    }
}
