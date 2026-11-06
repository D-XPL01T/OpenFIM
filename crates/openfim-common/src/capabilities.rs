//! What this build can actually enforce, on this platform.
//!
//! # Why this exists
//!
//! A policy field that parses cleanly, validates, displays as active in
//! `openfim-cli policy check`, and then does nothing is worse than a missing feature.
//! A missing feature is visible. A silently inert control produces **false assurance**:
//! the operator believes a protection is in place when it is not, and nothing in the
//! tool's output contradicts them.
//!
//! This module is the single source of truth for which controls are real. It is
//! consumed by:
//!
//! - [`crate::detect::evaluate`], which refuses to compare a field it cannot read and
//!   reports the skip rather than silently returning "no change";
//! - `openfim-cli policy lint`, which warns when a policy requests an unenforceable
//!   control and exits non-zero so it can gate CI;
//! - the sensor daemon's startup banner, so the limitation is stated before an incident
//!   rather than discovered during one.
//!
//! The rule it enforces: **a policy field must be enforced, or the tool must refuse to
//! pretend otherwise.**

use serde::{Deserialize, Serialize};

/// The integrity checks a rule can request.
///
/// Mirrors the fields of [`crate::policy::RuleChecks`] one-to-one; a new check must be
/// added here, which is what forces its capability to be declared.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Check {
    Hash,
    Size,
    Permissions,
    Ownership,
    Timestamps,
    Attributes,
    Xattrs,
}

impl Check {
    /// Every check, for exhaustive iteration by lint and reporting code.
    pub const ALL: [Check; 7] = [
        Check::Hash,
        Check::Size,
        Check::Permissions,
        Check::Ownership,
        Check::Timestamps,
        Check::Attributes,
        Check::Xattrs,
    ];

    /// The policy YAML field name, so diagnostics name what the operator wrote.
    pub const fn field_name(&self) -> &'static str {
        match self {
            Check::Hash => "hash",
            Check::Size => "size",
            Check::Permissions => "permissions",
            Check::Ownership => "ownership",
            Check::Timestamps => "timestamps",
            Check::Attributes => "attributes",
            Check::Xattrs => "xattrs",
        }
    }

    /// What the check is for, in one line.
    pub const fn purpose(&self) -> &'static str {
        match self {
            Check::Hash => "detects any change to file contents",
            Check::Size => "detects a change in file length",
            Check::Permissions => "detects a change to the access control policy on the file",
            Check::Ownership => "detects a change of owning user or group",
            Check::Timestamps => "detects modification-time changes, including timestomping",
            Check::Attributes => "detects filesystem attribute flag changes",
            Check::Xattrs => "detects extended attribute, label or alternate stream changes",
        }
    }
}

impl std::fmt::Display for Check {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.field_name())
    }
}

/// How well a control is supported here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Support {
    /// Fully implemented: a change of this kind is detected.
    Enforced,
    /// Implemented, but narrower than the name suggests. The note says how.
    Partial(&'static str),
    /// Not implemented, or impossible on this platform. The note says why.
    Unsupported(&'static str),
}

impl Support {
    /// True when the check will actually compare something.
    pub fn is_active(&self) -> bool {
        matches!(self, Support::Enforced | Support::Partial(_))
    }

    /// The caveat or reason, when there is one.
    pub fn note(&self) -> Option<&'static str> {
        match self {
            Support::Enforced => None,
            Support::Partial(n) | Support::Unsupported(n) => Some(n),
        }
    }

    /// Short label for tables and reports.
    pub const fn label(&self) -> &'static str {
        match self {
            Support::Enforced => "enforced",
            Support::Partial(_) => "partial",
            Support::Unsupported(_) => "unsupported",
        }
    }
}

impl std::fmt::Display for Support {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.note() {
            Some(note) => write!(f, "{} ({})", self.label(), note),
            None => f.write_str(self.label()),
        }
    }
}

/// The platform this build targets, as reported in diagnostics.
pub const fn platform_name() -> &'static str {
    if cfg!(target_os = "linux") {
        "Linux"
    } else if cfg!(windows) {
        "Windows"
    } else if cfg!(target_os = "macos") {
        "macOS"
    } else if cfg!(unix) {
        "Unix"
    } else {
        "unknown"
    }
}

/// Support for one check on the current platform.
///
/// Every arm states a concrete reason, because "unsupported" without a reason reads as
/// an oversight and invites someone to enable the field anyway.
pub fn support_for(check: Check) -> Support {
    match check {
        Check::Hash => Support::Enforced,

        Check::Size => Support::Enforced,

        Check::Permissions => {
            if cfg!(unix) {
                Support::Enforced
            } else {
                Support::Unsupported(
                    "on Windows the access control policy lives in the security \
                     descriptor (the DACL), which this build does not yet read; \
                     st_mode holds Win32 attribute flags instead, so enable the \
                     `attributes` check for those",
                )
            }
        }

        Check::Ownership => {
            if cfg!(unix) {
                Support::Enforced
            } else {
                Support::Unsupported(
                    "on Windows ownership is a SID in the security descriptor, not a \
                     numeric uid/gid; those fields are recorded as 0, so a comparison \
                     would pass regardless of the real owner",
                )
            }
        }

        Check::Timestamps => Support::Enforced,

        Check::Attributes => {
            if cfg!(windows) {
                Support::Enforced
            } else {
                Support::Unsupported(
                    "Linux inode flags (the `chattr` set: immutable, append-only and \
                     friends) are not yet captured; FS_IOC_GETFLAGS is required",
                )
            }
        }

        Check::Xattrs => Support::Unsupported(
            "extended attributes are not yet captured, so xattrs_hash is always empty. \
             Linux needs listxattr/getxattr; Windows needs alternate data stream \
             enumeration",
        ),
    }
}

/// One row of the capability matrix.
#[derive(Debug, Clone, Copy)]
pub struct Capability {
    pub check: Check,
    pub support: Support,
}

/// The full capability matrix for the current platform.
pub fn capability_matrix() -> Vec<Capability> {
    Check::ALL
        .iter()
        .map(|&check| Capability {
            check,
            support: support_for(check),
        })
        .collect()
}

/// Checks that will not compare anything on this platform.
pub fn unsupported_checks() -> Vec<Capability> {
    capability_matrix()
        .into_iter()
        .filter(|c| !c.support.is_active())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_check_declares_a_capability() {
        // The point of the matrix is that nothing is left undeclared. If a new check
        // is added to `Check::ALL` without a `support_for` arm, this will not compile;
        // this test guards the weaker property that the matrix is complete.
        assert_eq!(capability_matrix().len(), Check::ALL.len());
        for cap in capability_matrix() {
            assert!(!cap.check.field_name().is_empty());
            assert!(!cap.check.purpose().is_empty());
        }
    }

    #[test]
    fn inactive_support_always_explains_itself() {
        // An unexplained "unsupported" reads as an oversight and invites an operator to
        // enable the field anyway. Every inactive control must say why.
        for cap in capability_matrix() {
            if !cap.support.is_active() {
                let note = cap
                    .support
                    .note()
                    .unwrap_or_else(|| panic!("{} is inactive with no reason", cap.check));
                assert!(
                    note.len() > 30,
                    "the reason given for `{}` is too terse to act on: {:?}",
                    cap.check,
                    note
                );
            }
        }
    }

    #[test]
    fn hash_is_always_enforced() {
        // Content hashing is the irreducible core of a file integrity monitor. If this
        // is ever not enforced, the tool has no reason to exist.
        assert_eq!(support_for(Check::Hash), Support::Enforced);
        assert!(support_for(Check::Hash).is_active());
    }

    #[test]
    fn field_names_match_the_policy_schema() {
        // These strings appear in operators' YAML. A rename here silently stops lint
        // diagnostics from naming the field the operator actually wrote.
        let names: Vec<&str> = Check::ALL.iter().map(|c| c.field_name()).collect();
        assert_eq!(
            names,
            vec![
                "hash",
                "size",
                "permissions",
                "ownership",
                "timestamps",
                "attributes",
                "xattrs"
            ]
        );
    }

    #[test]
    fn field_names_are_unique() {
        let mut names: Vec<&str> = Check::ALL.iter().map(|c| c.field_name()).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(before, names.len(), "duplicate check field name");
    }

    #[cfg(unix)]
    #[test]
    fn unix_enforces_posix_ownership_and_permissions() {
        assert_eq!(support_for(Check::Permissions), Support::Enforced);
        assert_eq!(support_for(Check::Ownership), Support::Enforced);
    }

    #[cfg(windows)]
    #[test]
    fn windows_refuses_posix_ownership_rather_than_passing_it() {
        // uid/gid are recorded as 0 on Windows, so an ownership comparison would
        // always succeed and report "unchanged" no matter who owns the file. Claiming
        // to enforce that is exactly the false assurance this module exists to stop.
        assert!(!support_for(Check::Ownership).is_active());
        assert!(!support_for(Check::Permissions).is_active());
        // Attribute flags, by contrast, really are readable on Windows.
        assert_eq!(support_for(Check::Attributes), Support::Enforced);
    }

    #[test]
    fn platform_name_is_known() {
        assert_ne!(platform_name(), "unknown");
    }

    #[test]
    fn display_includes_the_reason() {
        let s = Support::Unsupported("because of a specific documented reason").to_string();
        assert!(s.starts_with("unsupported"));
        assert!(s.contains("specific documented reason"));
        assert_eq!(Support::Enforced.to_string(), "enforced");
    }
}
