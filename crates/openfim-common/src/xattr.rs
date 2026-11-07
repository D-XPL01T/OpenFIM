//! Extended attribute capture.
//!
//! "Extended attributes" means different things per platform, and both matter to a file
//! integrity monitor because both can carry security-relevant state that is invisible
//! to a content hash:
//!
//! - **Linux**: the `user.*`, `security.*`, `system.*` and `trusted.*` namespaces. This
//!   is where SELinux labels (`security.selinux`), file capabilities
//!   (`security.capability`) and POSIX ACLs live. A binary granted
//!   `cap_setuid` through `security.capability` has had its privileges escalated with
//!   its contents, mode and owner all untouched — a content hash sees nothing.
//! - **Windows**: NTFS alternate data streams. A payload hidden in
//!   `file.txt:evil` does not change `file.txt`'s size, its digest, or its
//!   modification time as reported for the default stream.
//!
//! Both are therefore real blind spots, which is why `checks.xattrs` exists in the
//! policy schema. Until now it parsed and did nothing, and `xattrs_hash` was
//! permanently `NULL`.
//!
//! # Canonical hashing
//!
//! Attributes are hashed as a sorted, length-prefixed sequence of name/value pairs.
//! Sorting matters because enumeration order is not guaranteed and is not stable across
//! filesystems; without it, the same set of attributes would hash differently from one
//! scan to the next and every file would look permanently modified. Length prefixing
//! prevents a rename from being disguised as a value change by shifting bytes across
//! the name/value boundary.

use std::path::Path;

use crate::error::Result;
use crate::hasher::{HashAlgorithm, StreamHasher};

/// Name and raw value of one extended attribute (or alternate data stream).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ExtendedAttribute {
    pub name: String,
    pub value: Vec<u8>,
}

/// Hashes a sorted, length-prefixed encoding of the attribute set.
///
/// Returns `None` for an empty set, so "this file has no extended attributes" is
/// distinguishable from "this file has attributes that hash to X" — and so the common
/// case of a plain file costs nothing to store.
pub fn hash_attributes(mut attrs: Vec<ExtendedAttribute>) -> Option<String> {
    if attrs.is_empty() {
        return None;
    }
    attrs.sort();

    let mut buf: Vec<u8> = Vec::new();
    for attr in &attrs {
        let name = attr.name.as_bytes();
        buf.extend_from_slice(&(name.len() as u64).to_le_bytes());
        buf.extend_from_slice(name);
        buf.extend_from_slice(&(attr.value.len() as u64).to_le_bytes());
        buf.extend_from_slice(&attr.value);
    }

    Some(StreamHasher::hash_bytes(HashAlgorithm::Sha256, &buf))
}

/// Reads a path's extended attributes, without following symlinks.
///
/// An unreadable attribute set is reported as `None` rather than as an error: on a real
/// system some paths deny attribute enumeration, and failing the whole metadata
/// extraction over it would abandon the content hash too.
pub fn read_attributes(path: &Path) -> Result<Vec<ExtendedAttribute>> {
    platform::read_attributes(path)
}

/// Convenience: read and hash in one step.
pub fn hash_path_attributes(path: &Path) -> Option<String> {
    match read_attributes(path) {
        Ok(attrs) => hash_attributes(attrs),
        Err(_) => None,
    }
}

// ---------------------------------------------------------------------------
// Linux
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod platform {
    use super::*;
    use std::ffi::{CStr, CString};
    use std::os::unix::ffi::OsStrExt;

    /// Attribute names and values are both bounded in the kernel; these caps stop a
    /// hostile or corrupt filesystem from driving an unbounded allocation.
    const MAX_LIST_BYTES: usize = 64 * 1024;
    const MAX_VALUE_BYTES: usize = 64 * 1024;

    pub fn read_attributes(path: &Path) -> Result<Vec<ExtendedAttribute>> {
        let c_path = match CString::new(path.as_os_str().as_bytes()) {
            Ok(p) => p,
            // A path with an interior NUL cannot be passed to the C API. Treat it as
            // having no attributes rather than failing the whole extraction.
            Err(_) => return Ok(Vec::new()),
        };

        // llistxattr, not listxattr: never traverse a symlink, matching the no-follow
        // behaviour of the rest of the metadata capture.
        // SAFETY: c_path is a valid NUL-terminated string; a null buffer with size 0 is
        // the documented way to query the required length.
        let needed = unsafe { libc::llistxattr(c_path.as_ptr(), std::ptr::null_mut(), 0) };
        if needed <= 0 {
            // 0 means no attributes; negative means the filesystem does not support
            // them, or access was denied. Neither is an integrity failure.
            return Ok(Vec::new());
        }

        let needed = (needed as usize).min(MAX_LIST_BYTES);
        let mut list = vec![0i8; needed];
        // SAFETY: `list` has `needed` writable bytes.
        let written = unsafe { libc::llistxattr(c_path.as_ptr(), list.as_mut_ptr(), list.len()) };
        if written <= 0 {
            return Ok(Vec::new());
        }
        list.truncate(written as usize);

        let mut attrs = Vec::new();
        // The list is a packed sequence of NUL-terminated names.
        for chunk in list.split(|&b| b == 0) {
            if chunk.is_empty() {
                continue;
            }
            let bytes: Vec<u8> = chunk.iter().map(|&c| c as u8).collect();
            let name = match CString::new(bytes) {
                Ok(n) => n,
                Err(_) => continue,
            };
            let name_str = match name.to_str() {
                Ok(s) => s.to_string(),
                Err(_) => continue,
            };

            if let Some(value) = read_one(&c_path, &name) {
                attrs.push(ExtendedAttribute {
                    name: name_str,
                    value,
                });
            }
        }

        Ok(attrs)
    }

    fn read_one(c_path: &CStr, name: &CStr) -> Option<Vec<u8>> {
        // SAFETY: both pointers are valid NUL-terminated strings; a null buffer with
        // size 0 queries the required length.
        let needed =
            unsafe { libc::lgetxattr(c_path.as_ptr(), name.as_ptr(), std::ptr::null_mut(), 0) };
        if needed < 0 {
            return None;
        }
        if needed == 0 {
            return Some(Vec::new());
        }

        let cap = (needed as usize).min(MAX_VALUE_BYTES);
        let mut value = vec![0u8; cap];
        // SAFETY: `value` has `cap` writable bytes.
        let got = unsafe {
            libc::lgetxattr(
                c_path.as_ptr(),
                name.as_ptr(),
                value.as_mut_ptr() as *mut libc::c_void,
                value.len(),
            )
        };
        if got < 0 {
            return None;
        }
        value.truncate(got as usize);
        Some(value)
    }
}

// ---------------------------------------------------------------------------
// Windows: NTFS alternate data streams
// ---------------------------------------------------------------------------

#[cfg(windows)]
mod platform {
    use super::*;
    use std::os::windows::ffi::OsStrExt;

    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_HANDLE_EOF, HANDLE, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        FindFirstStreamW, FindNextStreamW, FindStreamInfoStandard, WIN32_FIND_STREAM_DATA,
    };

    /// The unnamed default stream, which *is* the file's content and is already covered
    /// by the content hash. Including it would make every ordinary write look like an
    /// extended-attribute change as well.
    const DEFAULT_STREAM_SUFFIX: &str = "::$DATA";

    pub fn read_attributes(path: &Path) -> Result<Vec<ExtendedAttribute>> {
        let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
        wide.push(0);

        let mut data: WIN32_FIND_STREAM_DATA = unsafe { std::mem::zeroed() };

        // SAFETY: `wide` is NUL-terminated and `data` is a correctly sized POD struct
        // that the call fully initializes on success.
        let handle: HANDLE = unsafe {
            FindFirstStreamW(
                wide.as_ptr(),
                FindStreamInfoStandard,
                &mut data as *mut _ as *mut core::ffi::c_void,
                0,
            )
        };

        if handle == INVALID_HANDLE_VALUE {
            // Not an NTFS volume, access denied, or no streams. None of these is an
            // integrity failure.
            return Ok(Vec::new());
        }

        let mut attrs = Vec::new();
        loop {
            let name = wide_to_string(&data.cStreamName);
            // Record only the *existence and size* of each alternate stream, not its
            // contents. Reading the bytes would mean copying a hidden payload into the
            // baseline database, which is the opposite of what a monitor should do.
            if !name.is_empty() && !name.ends_with(DEFAULT_STREAM_SUFFIX) {
                attrs.push(ExtendedAttribute {
                    name,
                    value: data.StreamSize.to_le_bytes().to_vec(),
                });
            }

            // SAFETY: `handle` came from FindFirstStreamW and has not been closed.
            let more =
                unsafe { FindNextStreamW(handle, &mut data as *mut _ as *mut core::ffi::c_void) };
            if more == 0 {
                // ERROR_HANDLE_EOF is the normal end of enumeration.
                let _ = ERROR_HANDLE_EOF;
                break;
            }
        }

        // SAFETY: closing a handle obtained from FindFirstStreamW exactly once.
        unsafe {
            CloseHandle(handle);
        }

        Ok(attrs)
    }

    fn wide_to_string(buf: &[u16]) -> String {
        let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        String::from_utf16_lossy(&buf[..end])
    }
}

// ---------------------------------------------------------------------------
// Other platforms
// ---------------------------------------------------------------------------

#[cfg(not(any(target_os = "linux", windows)))]
mod platform {
    use super::*;

    pub fn read_attributes(_path: &Path) -> Result<Vec<ExtendedAttribute>> {
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn attr(name: &str, value: &[u8]) -> ExtendedAttribute {
        ExtendedAttribute {
            name: name.to_string(),
            value: value.to_vec(),
        }
    }

    #[test]
    fn empty_set_hashes_to_none() {
        // "No attributes" must be distinguishable from "attributes that hash to X".
        assert_eq!(hash_attributes(vec![]), None);
    }

    #[test]
    fn hash_is_order_independent() {
        // Enumeration order is not guaranteed and is not stable across filesystems.
        // Without sorting, the same attribute set would hash differently between scans
        // and every file with xattrs would look permanently modified.
        let a = hash_attributes(vec![
            attr("user.one", b"1"),
            attr("user.two", b"2"),
            attr("security.selinux", b"label"),
        ]);
        let b = hash_attributes(vec![
            attr("security.selinux", b"label"),
            attr("user.two", b"2"),
            attr("user.one", b"1"),
        ]);
        assert_eq!(a, b, "attribute hashing is sensitive to enumeration order");
        assert!(a.is_some());
    }

    #[test]
    fn value_change_changes_the_hash() {
        let before = hash_attributes(vec![attr("security.capability", b"cap_net_raw")]);
        let after = hash_attributes(vec![attr("security.capability", b"cap_setuid")]);
        assert_ne!(
            before, after,
            "a capability escalation must change the attribute hash"
        );
    }

    #[test]
    fn adding_an_attribute_changes_the_hash() {
        let before = hash_attributes(vec![attr("user.a", b"1")]);
        let after = hash_attributes(vec![attr("user.a", b"1"), attr("user.b", b"2")]);
        assert_ne!(before, after);
    }

    #[test]
    fn removing_an_attribute_changes_the_hash() {
        let before = hash_attributes(vec![attr("user.a", b"1"), attr("user.b", b"2")]);
        let after = hash_attributes(vec![attr("user.a", b"1")]);
        assert_ne!(before, after);
    }

    #[test]
    fn name_value_boundary_cannot_be_shifted() {
        // Without length prefixes, ("ab", "c") and ("a", "bc") produce identical hash
        // input, so a rename could be disguised as a value change.
        let a = hash_attributes(vec![attr("user.ab", b"c")]);
        let b = hash_attributes(vec![attr("user.a", b"bc")]);
        assert_ne!(a, b, "name/value boundary is not unambiguously encoded");
    }

    #[test]
    fn empty_value_differs_from_absent_attribute() {
        let present_empty = hash_attributes(vec![attr("user.flag", b"")]);
        let absent = hash_attributes(vec![]);
        assert!(present_empty.is_some());
        assert_ne!(present_empty, absent);
    }

    #[test]
    fn reading_a_plain_file_does_not_error() {
        // A file with no extended attributes is the common case and must be cheap and
        // quiet, not an error.
        let dir = tempdir().unwrap();
        let path = dir.path().join("plain.txt");
        std::fs::write(&path, b"content").unwrap();

        let attrs = read_attributes(&path).expect("reading attributes must not fail");
        // On Windows a freshly written file has only its default stream, which is
        // excluded; on Linux it has no xattrs. Either way the set is empty.
        assert!(
            attrs.is_empty(),
            "unexpected attributes on a plain file: {:?}",
            attrs.iter().map(|a| &a.name).collect::<Vec<_>>()
        );
        assert_eq!(hash_path_attributes(&path), None);
    }

    #[test]
    fn missing_path_is_not_an_error() {
        let attrs = read_attributes(Path::new("openfim-no-such-path-xattr")).unwrap();
        assert!(attrs.is_empty());
        assert_eq!(
            hash_path_attributes(Path::new("openfim-no-such-path")),
            None
        );
    }

    #[cfg(windows)]
    #[test]
    fn alternate_data_stream_is_detected() {
        // The Windows blind spot this closes: a payload in `file:hidden` changes
        // neither the file's digest nor its reported size.
        let dir = tempdir().unwrap();
        let path = dir.path().join("host.txt");
        std::fs::write(&path, b"ordinary content").unwrap();

        let clean = hash_path_attributes(&path);
        assert_eq!(clean, None, "a plain file should report no streams");

        // Write an alternate data stream.
        let ads = format!("{}:hidden", path.display());
        if std::fs::write(&ads, b"hidden payload").is_err() {
            // Not an NTFS volume; nothing to assert.
            return;
        }

        let attrs = read_attributes(&path).unwrap();
        assert!(
            !attrs.is_empty(),
            "an alternate data stream was not detected"
        );
        assert!(
            attrs.iter().any(|a| a.name.contains("hidden")),
            "stream names: {:?}",
            attrs.iter().map(|a| &a.name).collect::<Vec<_>>()
        );
        assert_ne!(
            hash_path_attributes(&path),
            clean,
            "adding a hidden stream must change the attribute hash"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_xattr_round_trip() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let dir = tempdir().unwrap();
        let path = dir.path().join("labelled.txt");
        std::fs::write(&path, b"content").unwrap();

        let c_path = CString::new(path.as_os_str().as_bytes()).unwrap();
        let name = CString::new("user.openfim_test").unwrap();
        let value = b"marker";

        // SAFETY: valid NUL-terminated strings and an in-bounds value buffer.
        let rc = unsafe {
            libc::lsetxattr(
                c_path.as_ptr(),
                name.as_ptr(),
                value.as_ptr() as *const libc::c_void,
                value.len(),
                0,
            )
        };
        if rc != 0 {
            // tmpfs without user_xattr support; nothing to assert.
            return;
        }

        let attrs = read_attributes(&path).unwrap();
        assert!(
            attrs.iter().any(|a| a.name == "user.openfim_test"),
            "set xattr was not read back: {:?}",
            attrs.iter().map(|a| &a.name).collect::<Vec<_>>()
        );
        assert!(hash_path_attributes(&path).is_some());
    }
}
