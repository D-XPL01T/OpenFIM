//! File protection for OpenFIM's own state.
//!
//! The baseline database and the chain key are not ordinary application files. The
//! database holds the digests that define "correct", and anyone who can write it can
//! redefine correct. The chain key lets its holder forge the audit log. Both were
//! previously created with whatever the process umask happened to be, which on a
//! default Linux setup means world-readable.
//!
//! Two things are enforced here:
//!
//! 1. **Create restrictively.** New state files are owner-only from the moment they
//!    exist, rather than being created permissively and tightened afterwards — a window
//!    in which another user can open a handle that survives the later `chmod`.
//! 2. **Refuse to use a key that others can read.** This is the behaviour OpenSSH has
//!    for private keys, for the same reason: a secret that the whole machine can read is
//!    not a secret, and silently proceeding teaches the operator that it is fine.

use std::path::Path;

use crate::error::{OpenFimError, Result};

/// How exposed a file is to other users on the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exposure {
    /// Only the owner can read it.
    OwnerOnly,
    /// The group can read it.
    GroupReadable,
    /// Any user on the host can read it.
    WorldReadable,
    /// Could not be determined on this platform.
    Unknown,
}

impl Exposure {
    /// True when someone other than the owner can read the file.
    pub fn is_exposed(&self) -> bool {
        matches!(self, Exposure::GroupReadable | Exposure::WorldReadable)
    }

    pub const fn label(&self) -> &'static str {
        match self {
            Exposure::OwnerOnly => "owner-only",
            Exposure::GroupReadable => "group-readable",
            Exposure::WorldReadable => "world-readable",
            Exposure::Unknown => "unknown",
        }
    }
}

impl std::fmt::Display for Exposure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// Reports how exposed a path's permissions are.
///
/// Returns [`Exposure::Unknown`] on Windows, where readability is governed by a DACL
/// that this function does not evaluate. Reporting `OwnerOnly` there would be a false
/// assurance, so the honest answer is that it was not checked.
pub fn exposure_of(path: &Path) -> Exposure {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(_) => return Exposure::Unknown,
        };
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o004 != 0 {
            Exposure::WorldReadable
        } else if mode & 0o040 != 0 {
            Exposure::GroupReadable
        } else {
            Exposure::OwnerOnly
        }
    }

    #[cfg(not(unix))]
    {
        let _ = path;
        Exposure::Unknown
    }
}

/// Tightens an existing file to owner-only access, best effort.
///
/// Returns whether the permissions were changed. Failure is not fatal: the caller warns
/// instead, because refusing to run over a permission bit the operator may not be able
/// to change would be worse than monitoring with a loud caveat.
pub fn restrict_to_owner(path: &Path) -> Result<bool> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(path).map_err(|e| OpenFimError::IoError {
            path: path.to_path_buf(),
            source: e,
        })?;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 == 0 {
            return Ok(false);
        }
        let mut perms = meta.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(path, perms).map_err(|e| OpenFimError::IoError {
            path: path.to_path_buf(),
            source: e,
        })?;
        Ok(true)
    }

    #[cfg(not(unix))]
    {
        // Windows inherits the directory ACL. Rewriting it correctly needs
        // SetNamedSecurityInfoW with a hand-built DACL, which is tracked as plan item
        // 2.5 rather than approximated here: a half-correct ACL is worse than an
        // inherited one, because it looks deliberate.
        let _ = path;
        Ok(false)
    }
}

/// Creates a file with owner-only permissions from the outset, writing `contents`.
///
/// Restrictive at creation rather than tightened afterwards: creating permissively and
/// fixing it later leaves a window in which another user can open a handle that the
/// subsequent permission change does not revoke.
pub fn write_protected(path: &Path, contents: &[u8]) -> Result<()> {
    use std::io::Write;

    #[cfg(unix)]
    let mut file = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| OpenFimError::IoError {
                path: path.to_path_buf(),
                source: e,
            })?
    };

    #[cfg(not(unix))]
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .map_err(|e| OpenFimError::IoError {
            path: path.to_path_buf(),
            source: e,
        })?;

    file.write_all(contents)
        .map_err(|e| OpenFimError::IoError {
            path: path.to_path_buf(),
            source: e,
        })?;
    file.sync_all().map_err(|e| OpenFimError::IoError {
        path: path.to_path_buf(),
        source: e,
    })?;
    Ok(())
}

/// Refuses to proceed when a secret file is readable by anyone but its owner.
///
/// Mirrors OpenSSH's behaviour for private keys, and for the same reason: a key the
/// whole host can read is not a key, and carrying on regardless teaches the operator
/// that the exposure is acceptable.
pub fn require_owner_only_secret(path: &Path) -> Result<()> {
    let exposure = exposure_of(path);
    if exposure.is_exposed() {
        return Err(OpenFimError::Other(format!(
            "refusing to use key material at '{}': it is {}. Anything able to read this \
             file can forge the audit chain. Fix it with `chmod 600 {}` and retry.",
            path.display(),
            exposure,
            path.display()
        )));
    }
    Ok(())
}

/// Warns, without refusing, when OpenFIM's own state is readable by others.
///
/// Returns the warning text when there is one. The database is not a secret in the way
/// a key is, but anyone who can *write* it can redefine what "unmodified" means, so the
/// operator should know.
pub fn warn_if_exposed(path: &Path, what: &str) -> Option<String> {
    let exposure = exposure_of(path);
    if exposure.is_exposed() {
        Some(format!(
            "{} at '{}' is {}. Anyone able to write it can redefine what this agent \
             considers unmodified. Restrict it to the account the agent runs as.",
            what,
            path.display(),
            exposure
        ))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn write_protected_creates_a_readable_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("state.key");
        write_protected(&path, b"secret-material").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"secret-material");
    }

    #[test]
    fn write_protected_truncates_on_rewrite() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("state.key");
        write_protected(&path, b"a-long-initial-value").unwrap();
        write_protected(&path, b"short").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"short");
    }

    #[test]
    fn exposure_of_a_missing_path_is_unknown() {
        assert_eq!(
            exposure_of(Path::new("openfim-no-such-path-for-exposure")),
            Exposure::Unknown
        );
    }

    #[test]
    fn warn_is_silent_for_a_protected_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("openfim.db");
        write_protected(&path, b"x").unwrap();

        // On Unix this is 0600 so there is nothing to warn about. On Windows the
        // exposure is Unknown, which also must not produce a false warning.
        assert_eq!(
            warn_if_exposed(&path, "baseline database"),
            None,
            "a protected (or unevaluated) file must not produce a warning"
        );
    }

    #[cfg(unix)]
    #[test]
    fn unix_write_protected_is_owner_only() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("chain.key");
        write_protected(&path, b"k").unwrap();
        assert_eq!(exposure_of(&path), Exposure::OwnerOnly);
        // And it is accepted as key material.
        assert!(require_owner_only_secret(&path).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn unix_world_readable_key_is_refused() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let path = dir.path().join("chain.key");
        std::fs::write(&path, b"k").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        assert_eq!(exposure_of(&path), Exposure::WorldReadable);
        let err = require_owner_only_secret(&path)
            .expect_err("a world-readable key must be refused, not used with a shrug");
        assert!(err.to_string().contains("world-readable"));
        assert!(
            err.to_string().contains("chmod 600"),
            "the error should tell the operator how to fix it: {}",
            err
        );
    }

    #[cfg(unix)]
    #[test]
    fn unix_group_readable_key_is_refused() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let path = dir.path().join("chain.key");
        std::fs::write(&path, b"k").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();

        assert_eq!(exposure_of(&path), Exposure::GroupReadable);
        assert!(require_owner_only_secret(&path).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn unix_restrict_tightens_and_reports() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let path = dir.path().join("openfim.db");
        std::fs::write(&path, b"x").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();

        assert!(restrict_to_owner(&path).unwrap(), "should report a change");
        assert_eq!(exposure_of(&path), Exposure::OwnerOnly);
        assert!(
            !restrict_to_owner(&path).unwrap(),
            "an already-restricted file should report no change"
        );
    }

    #[cfg(unix)]
    #[test]
    fn unix_exposed_database_produces_a_warning() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let path = dir.path().join("openfim.db");
        std::fs::write(&path, b"x").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let warning = warn_if_exposed(&path, "baseline database")
            .expect("an exposed database must be reported");
        assert!(warning.contains("world-readable"));
        assert!(warning.contains("redefine"));
    }

    #[cfg(windows)]
    #[test]
    fn windows_reports_unknown_rather_than_false_assurance() {
        // Readability on Windows is governed by a DACL this module does not evaluate.
        // Claiming "owner-only" would be a false assurance.
        let dir = tempdir().unwrap();
        let path = dir.path().join("chain.key");
        write_protected(&path, b"k").unwrap();

        assert_eq!(exposure_of(&path), Exposure::Unknown);
        assert!(!exposure_of(&path).is_exposed());
        // An unevaluated file is not refused: there is no evidence of exposure.
        assert!(require_owner_only_secret(&path).is_ok());
    }
}
