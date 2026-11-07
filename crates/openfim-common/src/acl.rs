//! Access control policy capture: ACLs and file ownership.
//!
//! # The gap this closes
//!
//! `st_mode` is not the access control policy on either platform:
//!
//! - **Windows** keeps it in the security descriptor's DACL. `st_mode` there holds
//!   Win32 attribute flags, so granting a new principal full control over a monitored
//!   file changes nothing a mode comparison can see. Ownership is a SID, not a numeric
//!   uid, which is why `st_uid`/`st_gid` are recorded as 0 and an ownership comparison
//!   based on them would pass regardless of the real owner.
//! - **Linux** can carry POSIX ACLs in `system.posix_acl_access` *in addition to* the
//!   mode bits. `setfacl -m u:attacker:rw file` grants access while leaving the mode
//!   bits, the owner and the contents untouched. The permission bits even keep looking
//!   correct, since the only visible trace is the `+` in `ls -l`.
//!
//! Both are real escalation paths that a content hash and a mode check miss entirely.
//!
//! # Hashing rather than parsing
//!
//! The ACL is reduced to a digest rather than interpreted. A hash answers "did the
//! access control policy change?", which is the question a file integrity monitor
//! exists to answer, without putting a parser for a complex, privilege-adjacent binary
//! format on the scanning hot path. The trade-off is that OpenFIM can say an ACL
//! changed but not which entry changed; that is recorded as **ADR-008** in the plan.
//!
//! The owner is hashed separately from the DACL on purpose. Folding them together would
//! make `chown` also trip the `permissions` check, reporting one change as two.

use std::path::Path;

use crate::hasher::{HashAlgorithm, StreamHasher};

/// Digest of the discretionary access control policy for a path.
///
/// Returns `None` when the platform has no separate ACL to report, or when it could not
/// be read. `None` is not "no restrictions" — it means unknown, and the caller must not
/// treat it as a clean comparison.
pub fn hash_access_control(path: &Path) -> Option<String> {
    platform::hash_access_control(path)
}

/// Platform-native owner identity, where numeric uid/gid are not meaningful.
///
/// Returns the owner SID string on Windows (for example
/// `S-1-5-21-1234567890-...-1001`) and `None` on Unix, where `st_uid`/`st_gid` already
/// carry the answer.
pub fn owner_identity(path: &Path) -> Option<String> {
    platform::owner_identity(path)
}

/// True when this platform reports ownership through [`owner_identity`] rather than
/// through numeric uid/gid.
pub const fn uses_string_owner_identity() -> bool {
    cfg!(windows)
}

// ---------------------------------------------------------------------------
// Linux: POSIX ACLs live in extended attributes
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod platform {
    use super::*;
    use crate::xattr;

    /// The two xattrs that carry POSIX ACLs. `access` governs the file itself; `default`
    /// governs what new children of a directory inherit, and changing it silently alters
    /// the permissions of everything created there afterwards.
    const ACL_XATTRS: [&str; 2] = ["system.posix_acl_access", "system.posix_acl_default"];

    pub fn hash_access_control(path: &Path) -> Option<String> {
        let attrs = xattr::read_attributes(path).ok()?;
        let acl: Vec<xattr::ExtendedAttribute> = attrs
            .into_iter()
            .filter(|a| ACL_XATTRS.contains(&a.name.as_str()))
            .collect();

        // No ACL xattr means the mode bits are the whole policy, which the
        // `permissions` check already compares. Reporting a digest of nothing would
        // make every plain file carry a redundant value.
        xattr::hash_attributes(acl)
    }

    pub fn owner_identity(_path: &Path) -> Option<String> {
        // st_uid / st_gid are authoritative on Unix.
        None
    }
}

// ---------------------------------------------------------------------------
// Windows: the security descriptor
// ---------------------------------------------------------------------------

#[cfg(windows)]
mod platform {
    use super::*;
    use std::os::windows::ffi::OsStrExt;

    use windows_sys::Win32::Foundation::{LocalFree, ERROR_SUCCESS};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        ACL, DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR, PSID,
    };

    fn wide(path: &Path) -> Vec<u16> {
        let mut w: Vec<u16> = path.as_os_str().encode_wide().collect();
        w.push(0);
        w
    }

    /// Fetches the security descriptor, invoking `f` with the owner, group and DACL.
    ///
    /// The descriptor is allocated by the OS and freed exactly once on every path out,
    /// including the error paths.
    fn with_security_info<T>(
        path: &Path,
        f: impl FnOnce(PSID, PSID, *const ACL) -> Option<T>,
    ) -> Option<T> {
        let w = wide(path);
        let mut owner: PSID = std::ptr::null_mut();
        let mut group: PSID = std::ptr::null_mut();
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();

        // SAFETY: `w` is NUL-terminated; the out-pointers are valid and the call either
        // fills them and allocates `descriptor`, or returns an error code.
        let rc = unsafe {
            GetNamedSecurityInfoW(
                w.as_ptr(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                &mut group,
                &mut dacl,
                std::ptr::null_mut(),
                &mut descriptor,
            )
        };

        if rc != ERROR_SUCCESS {
            // Access denied, path absent, or a filesystem without security descriptors.
            // Not an integrity failure: the caller sees None, meaning "unknown".
            if !descriptor.is_null() {
                // SAFETY: freeing an OS-allocated descriptor exactly once.
                unsafe { LocalFree(descriptor) };
            }
            return None;
        }

        let result = f(owner, group, dacl);

        if !descriptor.is_null() {
            // SAFETY: `descriptor` was allocated by GetNamedSecurityInfoW and is freed
            // exactly once here, after `f` has finished reading from it.
            unsafe { LocalFree(descriptor) };
        }

        result
    }

    fn sid_to_string(sid: PSID) -> Option<String> {
        if sid.is_null() {
            return None;
        }
        let mut raw: *mut u16 = std::ptr::null_mut();
        // SAFETY: `sid` is a valid SID pointer from the security descriptor; the call
        // allocates a string into `raw` on success.
        let ok = unsafe { ConvertSidToStringSidW(sid, &mut raw) };
        if ok == 0 || raw.is_null() {
            return None;
        }

        // SAFETY: `raw` is a NUL-terminated UTF-16 string allocated by the call.
        let len = unsafe {
            let mut n = 0usize;
            while *raw.add(n) != 0 {
                n += 1;
            }
            n
        };
        // SAFETY: `raw` has `len` readable u16s before its terminator.
        let slice = unsafe { std::slice::from_raw_parts(raw, len) };
        let s = String::from_utf16_lossy(slice);

        // SAFETY: freeing the string allocated by ConvertSidToStringSidW exactly once.
        unsafe { LocalFree(raw as *mut core::ffi::c_void) };
        Some(s)
    }

    pub fn hash_access_control(path: &Path) -> Option<String> {
        with_security_info(path, |_owner, _group, dacl| {
            if dacl.is_null() {
                // A NULL DACL means "everyone has full access", which is a meaningful
                // and dangerous state, so it gets its own stable digest rather than
                // being reported as unknown.
                return Some(StreamHasher::hash_bytes(
                    HashAlgorithm::Sha256,
                    b"openfim.acl.null-dacl",
                ));
            }

            // SAFETY: `dacl` is a valid ACL within the live security descriptor.
            let header = unsafe { *dacl };
            let size = header.AclSize as usize;
            if size == 0 {
                return None;
            }

            // Hash the ACL's raw bytes. The layout is stable for a given set of ACEs,
            // so this answers "did the access control policy change?" without parsing
            // a privilege-adjacent binary format on the scanning path.
            // SAFETY: the ACL structure is `AclSize` bytes long by definition.
            let bytes = unsafe { std::slice::from_raw_parts(dacl as *const u8, size) };
            Some(StreamHasher::hash_bytes(HashAlgorithm::Sha256, bytes))
        })
    }

    pub fn owner_identity(path: &Path) -> Option<String> {
        with_security_info(path, |owner, group, _dacl| {
            // Owner and group are combined into one identity string, so a change to
            // either is reported as an ownership change, mirroring uid+gid on Unix.
            let owner_sid = sid_to_string(owner)?;
            let group_sid = sid_to_string(group).unwrap_or_else(|| "none".to_string());
            Some(format!("{}:{}", owner_sid, group_sid))
        })
    }
}

// ---------------------------------------------------------------------------
// Other platforms
// ---------------------------------------------------------------------------

#[cfg(not(any(target_os = "linux", windows)))]
mod platform {
    use super::*;

    pub fn hash_access_control(_path: &Path) -> Option<String> {
        None
    }

    pub fn owner_identity(_path: &Path) -> Option<String> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn reading_a_plain_file_does_not_panic() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("plain.txt");
        std::fs::write(&path, b"content").unwrap();

        // The value is platform-dependent; what matters is that it is obtainable and
        // stable, and that nothing panics on a file with default security.
        let first = hash_access_control(&path);
        let second = hash_access_control(&path);
        assert_eq!(
            first, second,
            "the ACL digest must be stable across reads of an unchanged file"
        );
    }

    #[test]
    fn missing_path_reports_unknown_not_a_panic() {
        let absent = Path::new("openfim-no-such-path-for-acl");
        assert_eq!(hash_access_control(absent), None);
        assert_eq!(owner_identity(absent), None);
    }

    #[test]
    fn acl_digest_survives_a_content_change() {
        // Regression guard against hashing something content-derived: editing a file
        // must not look like an access control change.
        let dir = tempdir().unwrap();
        let path = dir.path().join("app.conf");
        std::fs::write(&path, b"before").unwrap();
        let before = hash_access_control(&path);

        std::fs::write(&path, b"after, with quite different content").unwrap();
        let after = hash_access_control(&path);

        assert_eq!(
            before, after,
            "an ordinary content edit changed the ACL digest, so the digest is not \
             derived from the access control policy alone"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_reports_an_owner_sid_and_a_dacl_digest() {
        // This is what makes `ownership` and `permissions` enforceable on Windows at
        // all: uid/gid are always 0 there, so without a SID there is nothing to compare.
        let dir = tempdir().unwrap();
        let path = dir.path().join("owned.txt");
        std::fs::write(&path, b"x").unwrap();

        let owner = owner_identity(&path).expect("owner SID should resolve for a local file");
        assert!(
            owner.starts_with("S-1-"),
            "expected a SID string, got {:?}",
            owner
        );
        assert!(
            owner.contains(':'),
            "owner and group should both be present"
        );

        assert!(
            hash_access_control(&path).is_some(),
            "a DACL digest should resolve for a local NTFS file"
        );
        assert!(uses_string_owner_identity());
    }

    #[cfg(windows)]
    #[test]
    fn windows_distinct_files_share_owner_but_hash_stably() {
        let dir = tempdir().unwrap();
        let a = dir.path().join("a.txt");
        let b = dir.path().join("b.txt");
        std::fs::write(&a, b"a").unwrap();
        std::fs::write(&b, b"b").unwrap();

        // Two files created by the same user inherit the same owner, which is correct:
        // ownership monitoring looks for *changes*, not for uniqueness.
        assert_eq!(owner_identity(&a), owner_identity(&b));
    }

    #[cfg(unix)]
    #[test]
    fn unix_defers_ownership_to_numeric_ids() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("plain.txt");
        std::fs::write(&path, b"x").unwrap();
        assert_eq!(
            owner_identity(&path),
            None,
            "on Unix st_uid/st_gid are authoritative, so no string identity is reported"
        );
        assert!(!uses_string_owner_identity());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_reports_no_acl_digest_for_a_plain_file() {
        // With no POSIX ACL set, the mode bits are the whole policy and the
        // `permissions` check already covers them.
        let dir = tempdir().unwrap();
        let path = dir.path().join("plain.txt");
        std::fs::write(&path, b"x").unwrap();
        assert_eq!(hash_access_control(&path), None);
    }
}
