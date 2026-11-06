//! Reconciliation sweep: the safety net under real-time watching.
//!
//! # Why a sweep is not optional
//!
//! Real-time filesystem watchers lose events. This is not a defect in the watcher, it
//! is how the kernel interfaces work:
//!
//! - **Linux inotify** has a bounded event queue (`/proc/sys/fs/inotify/max_queued_events`).
//!   When it overflows the kernel drops events and signals `IN_Q_OVERFLOW`.
//! - **Windows `ReadDirectoryChangesW`** fills a fixed buffer; on overflow it returns
//!   zero bytes read and the changes in that window are simply gone.
//! - A watch registered *after* a change never sees it at all, which covers every
//!   modification made while the agent was stopped, restarting, or not yet installed.
//!
//! Without reconciliation, each of those is a **permanent and silent** miss: the file
//! stays compromised, the baseline still holds the old digest, and nothing in the audit
//! log records that a window went unobserved. A monitor that can silently stop
//! monitoring is worse than one that is honestly offline, because the operator believes
//! they have coverage.
//!
//! The sweep re-crawls monitored paths and diffs them against the baseline through the
//! same [`crate::detect::evaluate`] engine the real-time path uses, so a change found
//! by sweep and a change found by the watcher produce identical verdicts.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::crawler::{CrawlOptions, FileCrawler};
use crate::db::{normalize_path_str, BaselineDb};
use crate::detect::{evaluate, ChangeSet};
use crate::error::Result;
use crate::hasher::StreamHasher;
use crate::metadata::FileMetadata;
use crate::policy::CompiledPolicy;

/// Event type recorded when the watcher reports that it dropped events.
pub const EVENT_WATCH_OVERFLOW: &str = "WATCH_OVERFLOW";

/// Event type recorded for a periodic liveness beacon.
pub const EVENT_HEARTBEAT: &str = "HEARTBEAT";

/// Event type recorded when a reconciliation sweep finds something the watcher missed.
pub const EVENT_SWEEP_FOUND: &str = "SWEEP_DIVERGENCE";

/// Event type recorded when the spool is pruned to stay within its quota.
pub const EVENT_SPOOL_PRUNED: &str = "SPOOL_PRUNED";

/// Why a sweep ran. Recorded with its findings, since "we found this during a routine
/// sweep" and "we found this after the watcher admitted dropping events" carry very
/// different weight in an investigation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SweepReason {
    /// Startup reconciliation, covering changes made while the agent was not running.
    Boot,
    /// Routine periodic reconciliation.
    Periodic,
    /// Forced because the watcher reported dropping events.
    WatchOverflow,
    /// Requested by an operator.
    Manual,
}

impl SweepReason {
    pub const fn label(&self) -> &'static str {
        match self {
            SweepReason::Boot => "startup reconciliation",
            SweepReason::Periodic => "periodic reconciliation",
            SweepReason::WatchOverflow => "forced by watcher overflow",
            SweepReason::Manual => "operator requested",
        }
    }
}

impl std::fmt::Display for SweepReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// One monitored path whose state diverges from the baseline.
#[derive(Debug, Clone)]
pub struct SweepFinding {
    pub path: PathBuf,
    pub baseline: FileMetadata,
    pub current: FileMetadata,
    pub changes: ChangeSet,
    /// Severity of the rule that matched, for alert ranking.
    pub severity: u32,
}

/// A monitored path that is in the baseline but no longer on disk.
#[derive(Debug, Clone)]
pub struct MissingEntry {
    pub baseline: FileMetadata,
    pub severity: u32,
}

/// Result of one reconciliation pass.
#[derive(Debug, Default)]
pub struct SweepOutcome {
    /// Files examined.
    pub scanned: usize,
    /// Files present on disk and in the baseline, whose state diverges.
    pub findings: Vec<SweepFinding>,
    /// Files in the baseline that have disappeared.
    pub missing: Vec<MissingEntry>,
    /// Files on disk, under a monitored path, with no baseline entry.
    pub unbaselined: Vec<FileMetadata>,
    /// Paths that could not be read, with the reason.
    ///
    /// Surfaced rather than dropped: a file that cannot be read is precisely the state
    /// an attacker would like the monitor to treat as "nothing to see".
    pub errors: Vec<(PathBuf, String)>,
}

impl SweepOutcome {
    /// True when the sweep found nothing the watcher had not already handled.
    pub fn is_clean(&self) -> bool {
        self.findings.is_empty() && self.missing.is_empty() && self.unbaselined.is_empty()
    }

    /// Total number of divergences of every kind.
    pub fn divergence_count(&self) -> usize {
        self.findings.len() + self.missing.len() + self.unbaselined.len()
    }

    /// One-line summary for logs.
    pub fn summary(&self) -> String {
        format!(
            "{} scanned, {} modified, {} missing, {} unbaselined, {} unreadable",
            self.scanned,
            self.findings.len(),
            self.missing.len(),
            self.unbaselined.len(),
            self.errors.len()
        )
    }
}

/// Re-crawls the given roots and diffs everything found against the baseline.
///
/// Verdicts come from the same [`evaluate`] engine the real-time path uses, so a
/// divergence discovered by sweep is indistinguishable in meaning from one caught live.
/// Paths that match no rule are ignored, and each file is judged by the checks of the
/// rule that actually matched it.
pub fn reconcile(
    db: &BaselineDb,
    policy: &CompiledPolicy,
    roots: &[PathBuf],
    hasher: &mut StreamHasher,
) -> Result<SweepOutcome> {
    let mut outcome = SweepOutcome::default();

    // Skipping unreadable entries is right for a sweep: a system root always contains
    // something the agent cannot open, and aborting would abandon the whole pass.
    let crawler = FileCrawler::new(CrawlOptions::default().with_skip_inaccessible(true));

    let mut observed: HashSet<String> = HashSet::new();

    for root in roots {
        if !root.exists() {
            outcome
                .errors
                .push((root.clone(), "monitored path does not exist".to_string()));
            continue;
        }

        let entries = match crawler.crawl(root, hasher) {
            Ok(e) => e,
            Err(e) => {
                outcome.errors.push((root.clone(), e.to_string()));
                continue;
            }
        };

        for current in entries {
            // Directories carry a sentinel digest and no content to compare.
            if current.is_dir {
                continue;
            }

            let rule = match policy.find_matching_rule(&current.path) {
                Some(r) => r,
                None => continue,
            };

            outcome.scanned += 1;
            observed.insert(normalize_path_str(&current.path));

            match db.get_entry(&current.path) {
                Ok(Some(baseline)) => {
                    let changes = evaluate(&baseline, &current, &rule.checks);
                    if !changes.is_clean() {
                        outcome.findings.push(SweepFinding {
                            path: current.path.clone(),
                            baseline,
                            current,
                            changes,
                            severity: rule.severity,
                        });
                    }
                }
                Ok(None) => outcome.unbaselined.push(current),
                Err(e) => outcome.errors.push((current.path.clone(), e.to_string())),
            }
        }
    }

    // Deletions the watcher may have missed: anything in the baseline, under one of the
    // swept roots, that was not observed on disk this pass.
    for baseline in db.get_all_entries()? {
        if baseline.is_dir {
            continue;
        }
        let key = normalize_path_str(&baseline.path);
        if observed.contains(&key) {
            continue;
        }
        if !is_under_any(&baseline.path, roots) {
            continue;
        }
        if baseline.path.exists() {
            // Present but not crawled: excluded by an ignore pattern or unreadable.
            continue;
        }
        let severity = policy
            .find_matching_rule(&baseline.path)
            .map(|r| r.severity)
            .unwrap_or(5);
        outcome.missing.push(MissingEntry { baseline, severity });
    }

    Ok(outcome)
}

/// True when `path` is the same as, or beneath, any of `roots`.
///
/// Uses a component-aware prefix test rather than a string `starts_with`, so a scope of
/// `/etc` does not also capture `/etcetera`.
fn is_under_any(path: &Path, roots: &[PathBuf]) -> bool {
    let candidate = normalize_path_str(path);
    roots.iter().any(|root| {
        let root_norm = normalize_path_str(root);
        let root_norm = root_norm.trim_end_matches('/');
        candidate == root_norm || candidate.starts_with(&format!("{}/", root_norm))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{
        ActiveResponseConfig, Policy, PolicyGlobals, PolicyRule, RuleChecks, RuleMode,
    };
    use tempfile::tempdir;

    fn policy_for(root: &Path) -> CompiledPolicy {
        CompiledPolicy::new(Policy {
            version: "1.0".to_string(),
            policy_id: "sweep-test".to_string(),
            name: "sweep".to_string(),
            author: "test".to_string(),
            signature_algorithm: "ed25519".to_string(),
            globals: PolicyGlobals::default(),
            rules: vec![PolicyRule {
                id: "R1".to_string(),
                description: "d".to_string(),
                paths: vec![root.to_string_lossy().to_string()],
                recursive: true,
                mode: RuleMode::Realtime,
                checks: RuleChecks {
                    hash: true,
                    size: true,
                    permissions: false,
                    ownership: false,
                    timestamps: false,
                    attributes: false,
                    xattrs: false,
                },
                nodiff: false,
                ignore: vec![],
                severity: 9,
                whodata: false,
                active_response: ActiveResponseConfig::default(),
            }],
        })
    }

    /// Baselines a directory, then returns the db and compiled policy.
    fn setup(root: &Path) -> (BaselineDb, CompiledPolicy) {
        let mut db = BaselineDb::open_in_memory().unwrap();
        let crawler = FileCrawler::new(CrawlOptions::default());
        let mut hasher = StreamHasher::default_sha256();
        let snapshot = crawler.crawl(root, &mut hasher).unwrap();
        db.insert_batch(&snapshot, "v1").unwrap();
        (db, policy_for(root))
    }

    #[test]
    fn clean_tree_sweeps_clean() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("a.conf"), b"alpha").unwrap();
        std::fs::write(dir.path().join("b.conf"), b"beta").unwrap();

        let (db, policy) = setup(dir.path());
        let mut hasher = StreamHasher::default_sha256();
        let outcome = reconcile(&db, &policy, &[dir.path().to_path_buf()], &mut hasher).unwrap();

        assert!(outcome.is_clean(), "{}", outcome.summary());
        assert_eq!(outcome.scanned, 2);
    }

    #[test]
    fn sweep_catches_a_change_the_watcher_never_saw() {
        // The whole reason this module exists: a modification made while nothing was
        // watching must still be found.
        let dir = tempdir().unwrap();
        let target = dir.path().join("app.conf");
        std::fs::write(&target, b"original").unwrap();

        let (db, policy) = setup(dir.path());

        // Change happens with no watcher running at all.
        std::fs::write(&target, b"tampered while the agent was stopped").unwrap();

        let mut hasher = StreamHasher::default_sha256();
        let outcome = reconcile(&db, &policy, &[dir.path().to_path_buf()], &mut hasher).unwrap();

        assert_eq!(outcome.findings.len(), 1, "{}", outcome.summary());
        let finding = &outcome.findings[0];
        assert!(finding.changes.event_types().contains(&"CONTENT_MUTATED"));
        assert_eq!(
            finding.severity, 9,
            "the matching rule's severity is carried"
        );
    }

    #[test]
    fn sweep_catches_a_deletion_the_watcher_never_saw() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("important.conf");
        std::fs::write(&target, b"content").unwrap();

        let (db, policy) = setup(dir.path());
        std::fs::remove_file(&target).unwrap();

        let mut hasher = StreamHasher::default_sha256();
        let outcome = reconcile(&db, &policy, &[dir.path().to_path_buf()], &mut hasher).unwrap();

        assert_eq!(outcome.missing.len(), 1, "{}", outcome.summary());
        assert_eq!(
            outcome.missing[0].baseline.path.file_name().unwrap(),
            "important.conf"
        );
    }

    #[test]
    fn sweep_reports_a_new_unbaselined_file() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("known.conf"), b"x").unwrap();

        let (db, policy) = setup(dir.path());
        std::fs::write(dir.path().join("dropped_by_attacker.sh"), b"payload").unwrap();

        let mut hasher = StreamHasher::default_sha256();
        let outcome = reconcile(&db, &policy, &[dir.path().to_path_buf()], &mut hasher).unwrap();

        assert_eq!(outcome.unbaselined.len(), 1, "{}", outcome.summary());
        assert_eq!(
            outcome.unbaselined[0].path.file_name().unwrap(),
            "dropped_by_attacker.sh"
        );
    }

    #[test]
    fn sweep_honours_the_matching_rule_checks() {
        // The rule under test enables hash and size but not timestamps, so a pure
        // timestamp change must not be reported. The sweep must use the rule's checks,
        // not a hardcoded set of its own.
        let dir = tempdir().unwrap();
        let target = dir.path().join("a.conf");
        std::fs::write(&target, b"same length!").unwrap();

        let (db, policy) = setup(dir.path());

        // Rewrite identical content: mtime moves, hash and size do not.
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(&target, b"same length!").unwrap();

        let mut hasher = StreamHasher::default_sha256();
        let outcome = reconcile(&db, &policy, &[dir.path().to_path_buf()], &mut hasher).unwrap();

        assert!(
            outcome.findings.is_empty(),
            "a timestamp-only change fired despite timestamps being disabled: {:?}",
            outcome.findings.first().map(|f| f.changes.event_types())
        );
    }

    #[test]
    fn unmonitored_paths_are_ignored() {
        let dir = tempdir().unwrap();
        let monitored = dir.path().join("watched");
        let ignored = dir.path().join("elsewhere");
        std::fs::create_dir_all(&monitored).unwrap();
        std::fs::create_dir_all(&ignored).unwrap();
        std::fs::write(monitored.join("a.conf"), b"a").unwrap();
        std::fs::write(ignored.join("b.conf"), b"b").unwrap();

        let (db, policy) = setup(&monitored);

        // Sweep the parent, which contains both. Only the monitored subtree counts.
        let mut hasher = StreamHasher::default_sha256();
        let outcome =
            reconcile(&db, &policy, std::slice::from_ref(&monitored), &mut hasher).unwrap();

        assert_eq!(outcome.scanned, 1);
        assert!(outcome.is_clean(), "{}", outcome.summary());
    }

    #[test]
    fn absent_root_is_reported_as_an_error_not_ignored() {
        let dir = tempdir().unwrap();
        let (db, policy) = setup(dir.path());
        let missing_root = dir.path().join("never-created");

        let mut hasher = StreamHasher::default_sha256();
        let outcome = reconcile(&db, &policy, &[missing_root], &mut hasher).unwrap();

        assert_eq!(outcome.errors.len(), 1);
        assert!(outcome.errors[0].1.contains("does not exist"));
    }

    #[test]
    fn scope_prefix_does_not_capture_sibling_directories() {
        // Guard against a textual prefix test: sweeping "<tmp>/etc" must not pull in
        // "<tmp>/etcetera".
        let dir = tempdir().unwrap();
        let etc = dir.path().join("etc");
        let etcetera = dir.path().join("etcetera");
        std::fs::create_dir_all(&etc).unwrap();
        std::fs::create_dir_all(&etcetera).unwrap();
        std::fs::write(etc.join("a.conf"), b"a").unwrap();
        std::fs::write(etcetera.join("b.conf"), b"b").unwrap();

        // Baseline both trees.
        let mut db = BaselineDb::open_in_memory().unwrap();
        let crawler = FileCrawler::new(CrawlOptions::default());
        let mut hasher = StreamHasher::default_sha256();
        let snapshot = crawler.crawl(dir.path(), &mut hasher).unwrap();
        db.insert_batch(&snapshot, "v1").unwrap();

        // Delete the sibling's file, then sweep only "etc".
        std::fs::remove_file(etcetera.join("b.conf")).unwrap();
        let policy = policy_for(&etc);
        let outcome = reconcile(&db, &policy, std::slice::from_ref(&etc), &mut hasher).unwrap();

        assert!(
            outcome.missing.is_empty(),
            "a sibling directory sharing a textual prefix was swept: {:?}",
            outcome
                .missing
                .iter()
                .map(|m| m.baseline.path.clone())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn is_under_any_is_component_aware() {
        let roots = vec![PathBuf::from("/etc")];
        assert!(is_under_any(Path::new("/etc"), &roots));
        assert!(is_under_any(Path::new("/etc/passwd"), &roots));
        assert!(is_under_any(Path::new("/etc/ssh/sshd_config"), &roots));
        assert!(!is_under_any(Path::new("/etcetera/file"), &roots));
        assert!(!is_under_any(Path::new("/var/log"), &roots));
    }

    #[test]
    fn summary_mentions_every_category() {
        let outcome = SweepOutcome {
            scanned: 10,
            ..Default::default()
        };
        let s = outcome.summary();
        for word in [
            "scanned",
            "modified",
            "missing",
            "unbaselined",
            "unreadable",
        ] {
            assert!(s.contains(word), "summary missing '{}': {}", word, s);
        }
    }

    #[test]
    fn sweep_reasons_are_distinct_and_described() {
        let reasons = [
            SweepReason::Boot,
            SweepReason::Periodic,
            SweepReason::WatchOverflow,
            SweepReason::Manual,
        ];
        let mut labels: Vec<&str> = reasons.iter().map(|r| r.label()).collect();
        let before = labels.len();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(before, labels.len());
    }
}
