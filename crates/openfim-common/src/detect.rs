//! The single change-detection engine.
//!
//! # Why one engine
//!
//! Before this module existed, the baseline-versus-current comparison was written
//! three times: inline in the sensor daemon, again in the interactive console's
//! in-process watcher, and a third time in the CLI's diff. Each checked a different
//! subset — the daemon looked only at `hash` and then `permissions`, and ignored the
//! other five checks a rule can request.
//!
//! Two consequences, both bad:
//!
//! 1. **Five of seven checks did nothing.** `size`, `ownership`, `timestamps`,
//!    `attributes` and `xattrs` parsed, validated, and displayed as active while being
//!    ignored by the engine.
//! 2. **The CLI and the daemon could disagree** about whether a file was compromised,
//!    because they implemented the same security decision twice.
//!
//! A security decision duplicated is a security decision that will drift. Everything
//! now routes through [`evaluate`].
//!
//! # Honest skipping
//!
//! A check the platform cannot perform is reported in
//! [`ChangeSet::skipped_unsupported`], never silently treated as "no change". The
//! difference matters: "I compared it and it is fine" and "I could not compare it" are
//! not the same statement, and only one of them is true.

use crate::capabilities::{support_for, Check};
use crate::metadata::FileMetadata;
use crate::policy::RuleChecks;

/// One observed difference between the recorded baseline and the current state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChangeKind {
    /// File contents differ.
    Content { old: String, new: String },
    /// File length differs.
    Size { old: u64, new: u64 },
    /// POSIX permission bits differ.
    Permissions { old: u32, new: u32 },
    /// Owning user or group differs.
    Ownership {
        old_uid: u32,
        new_uid: u32,
        old_gid: u32,
        new_gid: u32,
    },
    /// Modification time differs.
    Timestamps {
        old_mtime: i64,
        new_mtime: i64,
        old_mtime_nsec: i64,
        new_mtime_nsec: i64,
    },
    /// Filesystem attribute flags differ.
    Attributes { old: u32, new: u32 },
    /// Extended attributes, labels or alternate data streams differ.
    Xattrs {
        old: Option<String>,
        new: Option<String>,
    },
    /// The file was replaced by a different filesystem object, or vice versa.
    ///
    /// Detected independently of the requested checks, because a path that now names a
    /// different inode is a stronger signal than any single attribute comparison and a
    /// classic way to slip a change past a content hash.
    IdentityChanged {
        old_dev: u64,
        old_ino: u64,
        new_dev: u64,
        new_ino: u64,
    },
    /// The path changed kind: a regular file became a symlink or a directory.
    KindChanged {
        old: &'static str,
        new: &'static str,
    },
    /// A symlink now points somewhere else.
    SymlinkTargetChanged {
        old: Option<String>,
        new: Option<String>,
    },
}

impl ChangeKind {
    /// Event type recorded in the tamper-evident spool.
    pub const fn event_type(&self) -> &'static str {
        match self {
            ChangeKind::Content { .. } => "CONTENT_MUTATED",
            ChangeKind::Size { .. } => "SIZE_CHANGED",
            ChangeKind::Permissions { .. } => "PERMISSIONS_CHANGED",
            ChangeKind::Ownership { .. } => "OWNERSHIP_CHANGED",
            ChangeKind::Timestamps { .. } => "TIMESTAMP_CHANGED",
            ChangeKind::Attributes { .. } => "ATTRIBUTES_CHANGED",
            ChangeKind::Xattrs { .. } => "XATTRS_CHANGED",
            ChangeKind::IdentityChanged { .. } => "FILE_REPLACED",
            ChangeKind::KindChanged { .. } => "FILE_KIND_CHANGED",
            ChangeKind::SymlinkTargetChanged { .. } => "SYMLINK_RETARGETED",
        }
    }

    /// Relative seriousness, used to pick the headline alert when several changes land
    /// together.
    ///
    /// Content replacement and object substitution outrank metadata edits because they
    /// change what actually executes or is read; a timestamp edit on its own is most
    /// often noise, and is also the classic cover for something else.
    pub const fn rank(&self) -> u8 {
        match self {
            ChangeKind::Content { .. } => 100,
            ChangeKind::IdentityChanged { .. } => 95,
            ChangeKind::KindChanged { .. } => 90,
            ChangeKind::SymlinkTargetChanged { .. } => 85,
            ChangeKind::Permissions { .. } => 70,
            ChangeKind::Ownership { .. } => 65,
            ChangeKind::Xattrs { .. } => 60,
            ChangeKind::Attributes { .. } => 55,
            ChangeKind::Size { .. } => 50,
            ChangeKind::Timestamps { .. } => 20,
        }
    }

    /// One-line human-readable description.
    pub fn describe(&self) -> String {
        match self {
            ChangeKind::Content { old, new } => format!(
                "contents changed: {} -> {}",
                short_hash(old),
                short_hash(new)
            ),
            ChangeKind::Size { old, new } => format!("size changed: {} -> {} bytes", old, new),
            ChangeKind::Permissions { old, new } => {
                format!("permissions changed: 0o{:o} -> 0o{:o}", old, new)
            }
            ChangeKind::Ownership {
                old_uid,
                new_uid,
                old_gid,
                new_gid,
            } => format!(
                "ownership changed: uid {} -> {}, gid {} -> {}",
                old_uid, new_uid, old_gid, new_gid
            ),
            ChangeKind::Timestamps {
                old_mtime,
                new_mtime,
                old_mtime_nsec,
                new_mtime_nsec,
            } => {
                // When only the sub-second component moved, printing seconds alone
                // renders as "X -> X", which reads like a bug rather than a change.
                if old_mtime == new_mtime {
                    format!(
                        "modification time changed within the same second: {}.{:09} -> {}.{:09}",
                        old_mtime, old_mtime_nsec, new_mtime, new_mtime_nsec
                    )
                } else {
                    format!(
                        "modification time changed: {} -> {} (unix seconds)",
                        old_mtime, new_mtime
                    )
                }
            }
            ChangeKind::Attributes { old, new } => {
                format!("attribute flags changed: 0x{:x} -> 0x{:x}", old, new)
            }
            ChangeKind::Xattrs { .. } => "extended attributes changed".to_string(),
            ChangeKind::IdentityChanged {
                old_dev,
                old_ino,
                new_dev,
                new_ino,
            } => format!(
                "path now names a different filesystem object: (dev {}, inode {}) -> (dev {}, inode {})",
                old_dev, old_ino, new_dev, new_ino
            ),
            ChangeKind::KindChanged { old, new } => {
                format!("path kind changed: {} -> {}", old, new)
            }
            ChangeKind::SymlinkTargetChanged { old, new } => format!(
                "symlink retargeted: {} -> {}",
                old.as_deref().unwrap_or("(none)"),
                new.as_deref().unwrap_or("(none)")
            ),
        }
    }

    /// The pre-change and post-change content digests, where the change carries them.
    pub fn hashes(&self) -> (Option<&str>, Option<&str>) {
        match self {
            ChangeKind::Content { old, new } => (Some(old.as_str()), Some(new.as_str())),
            _ => (None, None),
        }
    }
}

fn short_hash(h: &str) -> &str {
    &h[..h.len().min(16)]
}

/// A check that was requested but could not be performed, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedCheck {
    pub check: Check,
    pub reason: &'static str,
}

/// The full result of comparing a baseline entry against current state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChangeSet {
    pub changes: Vec<ChangeKind>,
    /// Checks the rule asked for that this platform or build cannot perform.
    ///
    /// Never folded into "no change": an uncomparable field is an unknown, not a pass.
    pub skipped_unsupported: Vec<SkippedCheck>,
}

impl ChangeSet {
    /// True when nothing changed among the checks that actually ran.
    pub fn is_clean(&self) -> bool {
        self.changes.is_empty()
    }

    /// Number of observed differences.
    pub fn len(&self) -> usize {
        self.changes.len()
    }

    /// True when no differences were observed.
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }

    /// The most serious change, which becomes the headline of an alert.
    pub fn most_severe(&self) -> Option<&ChangeKind> {
        self.changes.iter().max_by_key(|c| c.rank())
    }

    /// True when any change indicates the content or the object itself changed, as
    /// opposed to only its metadata. Used to decide whether a rollback is warranted.
    pub fn is_substantive(&self) -> bool {
        self.changes.iter().any(|c| {
            matches!(
                c,
                ChangeKind::Content { .. }
                    | ChangeKind::IdentityChanged { .. }
                    | ChangeKind::KindChanged { .. }
                    | ChangeKind::SymlinkTargetChanged { .. }
            )
        })
    }

    /// Event types for every observed change, most serious first.
    pub fn event_types(&self) -> Vec<&'static str> {
        let mut sorted: Vec<&ChangeKind> = self.changes.iter().collect();
        sorted.sort_by_key(|c| std::cmp::Reverse(c.rank()));
        sorted.into_iter().map(|c| c.event_type()).collect()
    }
}

/// Describes the kind of a filesystem entry, for `KindChanged`.
const fn kind_of(meta: &FileMetadata) -> &'static str {
    if meta.is_dir {
        "directory"
    } else if meta.is_symlink {
        "symlink"
    } else {
        "regular file"
    }
}

/// Records a skip when a requested check cannot run here.
fn note_if_unsupported(check: Check, requested: bool, out: &mut Vec<SkippedCheck>) -> bool {
    if !requested {
        return false;
    }
    let support = support_for(check);
    if support.is_active() {
        return true;
    }
    out.push(SkippedCheck {
        check,
        reason: support
            .note()
            .unwrap_or("not supported on this platform or in this build"),
    });
    false
}

/// Compares a baseline entry against current state, honouring exactly the checks the
/// rule enables and the platform supports.
///
/// Unconditional checks — object identity, entry kind and symlink target — run
/// regardless of `checks`, because they describe *what the path is* rather than one of
/// its attributes. A regular file silently replaced by a symlink to somewhere else is
/// a compromise whether or not the operator happened to enable `permissions`.
pub fn evaluate(baseline: &FileMetadata, current: &FileMetadata, checks: &RuleChecks) -> ChangeSet {
    let mut set = ChangeSet::default();
    let skipped = &mut set.skipped_unsupported;

    // ---- Unconditional structural checks ----

    if kind_of(baseline) != kind_of(current) {
        set.changes.push(ChangeKind::KindChanged {
            old: kind_of(baseline),
            new: kind_of(current),
        });
    }

    // Only meaningful when both sides carry a resolvable identity; a zeroed identity
    // means the platform could not supply one, and comparing it would fire constantly.
    if baseline.has_stable_identity()
        && current.has_stable_identity()
        && baseline.identity_key() != current.identity_key()
    {
        set.changes.push(ChangeKind::IdentityChanged {
            old_dev: baseline.st_dev,
            old_ino: baseline.st_ino,
            new_dev: current.st_dev,
            new_ino: current.st_ino,
        });
    }

    if baseline.is_symlink
        && current.is_symlink
        && baseline.symlink_target != current.symlink_target
    {
        set.changes.push(ChangeKind::SymlinkTargetChanged {
            old: baseline.symlink_target.clone(),
            new: current.symlink_target.clone(),
        });
    }

    // ---- Requested checks ----

    if note_if_unsupported(Check::Hash, checks.hash, skipped) && baseline.sha256 != current.sha256 {
        set.changes.push(ChangeKind::Content {
            old: baseline.sha256.clone(),
            new: current.sha256.clone(),
        });
    }

    if note_if_unsupported(Check::Size, checks.size, skipped) && baseline.st_size != current.st_size
    {
        set.changes.push(ChangeKind::Size {
            old: baseline.st_size,
            new: current.st_size,
        });
    }

    // `permissions` and `attributes` both live in `st_mode`, but mean different things
    // per platform, so each is gated by its own capability. On Unix st_mode holds POSIX
    // permission bits; on Windows it holds Win32 attribute flags and the real access
    // control policy is in the DACL, which is why `permissions` is unsupported there.
    if note_if_unsupported(Check::Permissions, checks.permissions, skipped) {
        if let (Some(old), Some(new)) = (baseline.permission_bits(), current.permission_bits()) {
            if old != new {
                set.changes.push(ChangeKind::Permissions { old, new });
            }
        }
    }

    if note_if_unsupported(Check::Attributes, checks.attributes, skipped) {
        if let (Some(old), Some(new)) = (baseline.attribute_flags(), current.attribute_flags()) {
            if old != new {
                set.changes.push(ChangeKind::Attributes { old, new });
            }
        }
    }

    if note_if_unsupported(Check::Ownership, checks.ownership, skipped)
        && (baseline.st_uid != current.st_uid || baseline.st_gid != current.st_gid)
    {
        set.changes.push(ChangeKind::Ownership {
            old_uid: baseline.st_uid,
            new_uid: current.st_uid,
            old_gid: baseline.st_gid,
            new_gid: current.st_gid,
        });
    }

    if note_if_unsupported(Check::Timestamps, checks.timestamps, skipped)
        && (baseline.st_mtime != current.st_mtime
            || baseline.st_mtime_nsec != current.st_mtime_nsec)
    {
        set.changes.push(ChangeKind::Timestamps {
            old_mtime: baseline.st_mtime,
            new_mtime: current.st_mtime,
            old_mtime_nsec: baseline.st_mtime_nsec,
            new_mtime_nsec: current.st_mtime_nsec,
        });
    }

    if note_if_unsupported(Check::Xattrs, checks.xattrs, skipped)
        && baseline.xattrs_hash != current.xattrs_hash
    {
        set.changes.push(ChangeKind::Xattrs {
            old: baseline.xattrs_hash.clone(),
            new: current.xattrs_hash.clone(),
        });
    }

    set
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn meta(path: &str) -> FileMetadata {
        FileMetadata {
            path: PathBuf::from(path),
            st_dev: 1,
            st_ino: 42,
            st_mode: if cfg!(unix) { 0o100644 } else { 0x20 },
            st_nlink: 1,
            st_uid: 0,
            st_gid: 0,
            st_size: 100,
            st_mtime: 1_700_000_000,
            st_mtime_nsec: 0,
            st_ctime: 1_700_000_000,
            st_btime: None,
            sha256: "a".repeat(64),
            blake3: None,
            xattrs_hash: None,
            acl_hash: None,
            symlink_target: None,
            is_symlink: false,
            is_dir: false,
        }
    }

    fn all_checks() -> RuleChecks {
        RuleChecks {
            hash: true,
            size: true,
            permissions: true,
            ownership: true,
            timestamps: true,
            attributes: true,
            xattrs: true,
        }
    }

    fn no_checks() -> RuleChecks {
        RuleChecks {
            hash: false,
            size: false,
            permissions: false,
            ownership: false,
            timestamps: false,
            attributes: false,
            xattrs: false,
        }
    }

    #[test]
    fn identical_metadata_is_clean() {
        let a = meta("/etc/passwd");
        let set = evaluate(&a, &a.clone(), &all_checks());
        assert!(set.is_clean(), "{:?}", set.changes);
    }

    #[test]
    fn content_change_is_detected_when_requested() {
        let base = meta("/etc/passwd");
        let mut cur = base.clone();
        cur.sha256 = "b".repeat(64);

        let set = evaluate(&base, &cur, &all_checks());
        assert_eq!(set.event_types(), vec!["CONTENT_MUTATED"]);
        assert!(set.is_substantive());
    }

    #[test]
    fn content_change_is_ignored_when_not_requested() {
        // The whole point of the `checks` block: a disabled check must not fire.
        let base = meta("/etc/passwd");
        let mut cur = base.clone();
        cur.sha256 = "b".repeat(64);

        let mut checks = no_checks();
        checks.size = true; // something enabled, but not hash
        let set = evaluate(&base, &cur, &checks);
        assert!(
            set.is_clean(),
            "a disabled check still fired: {:?}",
            set.changes
        );
    }

    #[test]
    fn size_change_is_detected_independently_of_hash() {
        // Previously `size` was parsed and ignored, caught only incidentally by `hash`.
        // With hashing off, a length change must still be reported.
        let base = meta("/var/log/app.log");
        let mut cur = base.clone();
        cur.st_size = 999;

        let mut checks = no_checks();
        checks.size = true;
        let set = evaluate(&base, &cur, &checks);
        assert_eq!(set.event_types(), vec!["SIZE_CHANGED"]);
    }

    #[test]
    fn timestamp_change_is_detected_when_requested() {
        let base = meta("/etc/hosts");
        let mut cur = base.clone();
        cur.st_mtime = 1_600_000_000; // backdated: classic timestomp

        let mut checks = no_checks();
        checks.timestamps = true;
        let set = evaluate(&base, &cur, &checks);
        assert_eq!(set.event_types(), vec!["TIMESTAMP_CHANGED"]);
    }

    #[test]
    fn nanosecond_only_timestamp_change_is_detected() {
        let base = meta("/etc/hosts");
        let mut cur = base.clone();
        cur.st_mtime_nsec = 500;

        let mut checks = no_checks();
        checks.timestamps = true;
        assert_eq!(
            evaluate(&base, &cur, &checks).event_types(),
            vec!["TIMESTAMP_CHANGED"]
        );
    }

    #[test]
    fn timestamps_default_off_do_not_fire() {
        let base = meta("/etc/hosts");
        let mut cur = base.clone();
        cur.st_mtime = 1_600_000_000;
        // RuleChecks::default() has timestamps: false, since mtime churn is noisy.
        let set = evaluate(&base, &cur, &RuleChecks::default());
        assert!(set.is_clean(), "{:?}", set.changes);
    }

    #[test]
    fn object_substitution_is_detected_regardless_of_checks() {
        // A path repointed at a different inode is a compromise even if every optional
        // check is off, so this must not be gated behind `checks`.
        let base = meta("/usr/bin/sudo");
        let mut cur = base.clone();
        cur.st_ino = 9999;

        let set = evaluate(&base, &cur, &no_checks());
        assert_eq!(set.event_types(), vec!["FILE_REPLACED"]);
        assert!(set.is_substantive());
    }

    #[test]
    fn unresolvable_identity_does_not_fire() {
        // A zeroed identity means the platform could not supply one. Comparing it would
        // raise an alert on every single evaluation.
        let mut base = meta("/etc/passwd");
        let mut cur = base.clone();
        base.st_dev = 0;
        base.st_ino = 0;
        cur.st_dev = 0;
        cur.st_ino = 0;

        assert!(evaluate(&base, &cur, &no_checks()).is_clean());

        // ...and a half-known identity is still inconclusive, not an alert.
        cur.st_ino = 7;
        assert!(evaluate(&base, &cur, &no_checks()).is_clean());
    }

    #[test]
    fn file_replaced_by_symlink_is_detected() {
        let base = meta("/etc/resolv.conf");
        let mut cur = base.clone();
        cur.is_symlink = true;
        cur.symlink_target = Some("/tmp/attacker".to_string());

        let set = evaluate(&base, &cur, &no_checks());
        assert!(set.event_types().contains(&"FILE_KIND_CHANGED"));
        assert!(set.is_substantive());
    }

    #[test]
    fn symlink_retargeting_is_detected() {
        let mut base = meta("/etc/resolv.conf");
        base.is_symlink = true;
        base.symlink_target = Some("/run/systemd/resolve/stub-resolv.conf".to_string());

        let mut cur = base.clone();
        cur.symlink_target = Some("/tmp/evil-resolv.conf".to_string());

        let set = evaluate(&base, &cur, &no_checks());
        assert_eq!(set.event_types(), vec!["SYMLINK_RETARGETED"]);
    }

    #[test]
    fn several_changes_are_all_reported_and_ranked() {
        let base = meta("/etc/shadow");
        let mut cur = base.clone();
        cur.sha256 = "b".repeat(64);
        cur.st_size = 200;
        cur.st_mtime = 1_800_000_000;

        let set = evaluate(&base, &cur, &all_checks());
        assert_eq!(set.len(), 3, "{:?}", set.changes);
        // Content outranks size, which outranks a timestamp edit.
        assert_eq!(set.event_types()[0], "CONTENT_MUTATED");
        assert_eq!(
            set.most_severe().unwrap().event_type(),
            "CONTENT_MUTATED",
            "the headline alert must be the most serious change"
        );
    }

    #[test]
    fn unsupported_requested_check_is_reported_not_silently_passed() {
        // The core honesty property. `xattrs` cannot be compared in this build, so
        // asking for it must yield a recorded skip rather than a clean verdict.
        let base = meta("/etc/passwd");
        let set = evaluate(&base, &base.clone(), &all_checks());

        assert!(
            set.skipped_unsupported
                .iter()
                .any(|s| s.check == Check::Xattrs),
            "requesting an unsupported check must be reported: {:?}",
            set.skipped_unsupported
        );
        for skip in &set.skipped_unsupported {
            assert!(
                !skip.reason.is_empty(),
                "{} was skipped without a reason",
                skip.check
            );
        }
    }

    #[test]
    fn unrequested_unsupported_check_is_not_reported() {
        // Only checks the operator actually asked for are worth warning about.
        let base = meta("/etc/passwd");
        let set = evaluate(&base, &base.clone(), &no_checks());
        assert!(set.skipped_unsupported.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn unix_detects_permission_and_ownership_changes() {
        let base = meta("/etc/passwd");

        let mut perm = base.clone();
        perm.st_mode = 0o100777;
        assert_eq!(
            evaluate(&base, &perm, &all_checks()).event_types(),
            vec!["PERMISSIONS_CHANGED"]
        );

        let mut own = base.clone();
        own.st_uid = 1000;
        assert_eq!(
            evaluate(&base, &own, &all_checks()).event_types(),
            vec!["OWNERSHIP_CHANGED"]
        );
    }

    #[cfg(unix)]
    #[test]
    fn unix_ignores_file_type_bits_when_comparing_permissions() {
        // st_mode mixes the file type into the high bits. Comparing the whole word
        // would make a regular-file-to-symlink change look like a permission edit, in
        // addition to the KindChanged it already raises.
        let mut base = meta("/etc/passwd");
        let mut cur = base.clone();
        base.st_mode = 0o100644; // regular file, rw-r--r--
        cur.st_mode = 0o120644; // symlink, same permission bits
        let set = evaluate(&base, &cur, &all_checks());
        assert!(
            !set.event_types().contains(&"PERMISSIONS_CHANGED"),
            "file type bits leaked into the permission comparison: {:?}",
            set.changes
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_reports_permissions_as_unsupported_rather_than_comparing_st_mode() {
        // On Windows st_mode holds attribute flags, not an access control policy.
        // Comparing it under the name "permissions" would tell the operator their ACLs
        // are monitored when they are not.
        let base = meta("C:/data/app.conf");
        let set = evaluate(&base, &base.clone(), &all_checks());
        assert!(set
            .skipped_unsupported
            .iter()
            .any(|s| s.check == Check::Permissions));
        assert!(set
            .skipped_unsupported
            .iter()
            .any(|s| s.check == Check::Ownership));
    }

    #[cfg(windows)]
    #[test]
    fn windows_detects_attribute_flag_changes() {
        let base = meta("C:/data/app.conf");
        let mut cur = base.clone();
        cur.st_mode = 0x22; // + FILE_ATTRIBUTE_HIDDEN
        assert_eq!(
            evaluate(&base, &cur, &all_checks()).event_types(),
            vec!["ATTRIBUTES_CHANGED"]
        );
    }

    #[test]
    fn every_change_kind_has_a_distinct_event_type() {
        let samples = [
            ChangeKind::Content {
                old: "a".repeat(64),
                new: "b".repeat(64),
            },
            ChangeKind::Size { old: 1, new: 2 },
            ChangeKind::Permissions { old: 1, new: 2 },
            ChangeKind::Ownership {
                old_uid: 0,
                new_uid: 1,
                old_gid: 0,
                new_gid: 1,
            },
            ChangeKind::Timestamps {
                old_mtime: 1,
                new_mtime: 2,
                old_mtime_nsec: 0,
                new_mtime_nsec: 0,
            },
            ChangeKind::Attributes { old: 1, new: 2 },
            ChangeKind::Xattrs {
                old: None,
                new: Some("x".into()),
            },
            ChangeKind::IdentityChanged {
                old_dev: 1,
                old_ino: 1,
                new_dev: 1,
                new_ino: 2,
            },
            ChangeKind::KindChanged {
                old: "regular file",
                new: "symlink",
            },
            ChangeKind::SymlinkTargetChanged {
                old: None,
                new: Some("/tmp/x".into()),
            },
        ];

        let mut types: Vec<&str> = samples.iter().map(|c| c.event_type()).collect();
        let before = types.len();
        types.sort_unstable();
        types.dedup();
        assert_eq!(before, types.len(), "duplicate event type");

        for s in &samples {
            assert!(!s.describe().is_empty());
            assert!(s.rank() > 0);
        }
    }

    #[test]
    fn describe_does_not_panic_on_short_hashes() {
        // `describe` truncates digests for display; a short or empty value must not
        // panic on a slice boundary.
        let c = ChangeKind::Content {
            old: String::new(),
            new: "abc".to_string(),
        };
        assert!(c.describe().contains("contents changed"));
    }

    #[test]
    fn metadata_only_change_is_not_substantive() {
        let base = meta("/etc/passwd");
        let mut cur = base.clone();
        cur.st_mtime = 1_800_000_000;
        let mut checks = no_checks();
        checks.timestamps = true;
        let set = evaluate(&base, &cur, &checks);
        assert!(!set.is_clean());
        assert!(
            !set.is_substantive(),
            "a timestamp edit alone should not justify a content rollback"
        );
    }
}
