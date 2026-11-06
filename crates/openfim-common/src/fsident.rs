//! Platform filesystem identity resolution.
//!
//! A file integrity monitor needs a *stable* identity for every object it tracks:
//! one that survives ordinary content edits but changes when the path is repointed
//! at a different object. On Unix that is `(st_dev, st_ino)`. On Windows the
//! equivalent is the volume serial number plus the 64-bit NTFS file index, which
//! must be read from an open handle via `GetFileInformationByHandle` — the `std`
//! accessors for it remain unstable (`windows_by_handle`, rust-lang/rust#63010).
//!
//! Deriving identity from mutable attributes such as size or last-write time, as a
//! placeholder implementation may be tempted to do, is actively harmful: it makes
//! every legitimate write look like a file-substitution attack, and it makes two
//! unrelated files created in the same instant look like the same object, which
//! silently breaks both TOCTOU detection and crawler cycle detection.

use std::fs::File;
use std::path::Path;

/// Stable identity of a filesystem object, plus the hard-link count where available.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FsIdentity {
    pub device_id: u64,
    pub inode_or_index: u64,
    pub nlink: u64,
    /// True only when the platform supplied a genuinely stable identity.
    pub is_stable: bool,
}

impl FsIdentity {
    /// Identity placeholder for platforms or situations where none could be resolved.
    pub const UNAVAILABLE: FsIdentity = FsIdentity {
        device_id: 0,
        inode_or_index: 0,
        nlink: 1,
        is_stable: false,
    };

    /// True when both identities are stable and name the same filesystem object.
    ///
    /// When either side is unstable the answer is inconclusive and this returns `true`
    /// (fail-open), because raising a substitution alert on every single hash would be
    /// far more damaging than the check simply being unavailable.
    pub fn refers_to_same(&self, other: &FsIdentity) -> bool {
        if !self.is_stable || !other.is_stable {
            return true;
        }
        self.device_id == other.device_id && self.inode_or_index == other.inode_or_index
    }
}

impl std::fmt::Display for FsIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_stable {
            write!(
                f,
                "(dev={}, inode/index={})",
                self.device_id, self.inode_or_index
            )
        } else {
            write!(f, "(identity unavailable on this platform)")
        }
    }
}

// ---------------------------------------------------------------------------
// Unix
// ---------------------------------------------------------------------------

#[cfg(unix)]
pub fn identity_from_metadata(meta: &std::fs::Metadata) -> FsIdentity {
    use std::os::unix::fs::MetadataExt;
    FsIdentity {
        device_id: meta.dev(),
        inode_or_index: meta.ino(),
        nlink: meta.nlink(),
        is_stable: true,
    }
}

#[cfg(unix)]
pub fn identity_of_handle(file: &File) -> FsIdentity {
    match file.metadata() {
        Ok(meta) => identity_from_metadata(&meta),
        Err(_) => FsIdentity::UNAVAILABLE,
    }
}

/// Resolves the identity a path currently points at, without following symlinks.
#[cfg(unix)]
pub fn identity_of_path(path: &Path) -> FsIdentity {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => identity_from_metadata(&meta),
        Err(_) => FsIdentity::UNAVAILABLE,
    }
}

// ---------------------------------------------------------------------------
// Windows
// ---------------------------------------------------------------------------

#[cfg(windows)]
pub fn identity_of_handle(file: &File) -> FsIdentity {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };

    // SAFETY: `info` is a plain POD struct that the call fully initializes on
    // success, and the handle is owned by `file` and stays open for the call.
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle() as _, &mut info) };

    if ok == 0 {
        return FsIdentity::UNAVAILABLE;
    }

    let index = ((info.nFileIndexHigh as u64) << 32) | (info.nFileIndexLow as u64);
    FsIdentity {
        device_id: info.dwVolumeSerialNumber as u64,
        inode_or_index: index,
        nlink: info.nNumberOfLinks as u64,
        is_stable: true,
    }
}

/// Opens a path purely to interrogate its identity.
///
/// `FILE_FLAG_BACKUP_SEMANTICS` is required to obtain a handle to a directory, and
/// `FILE_FLAG_OPEN_REPARSE_POINT` keeps the open from traversing a symlink or
/// junction, matching the no-follow behaviour of `symlink_metadata` on Unix.
#[cfg(windows)]
fn open_for_identity(path: &Path) -> std::io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;

    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

    std::fs::OpenOptions::new()
        // Query-only access: this succeeds on files whose contents we may not read,
        // and avoids taking a sharing mode that could disturb the live workload.
        .access_mode(0)
        .share_mode(0x1 | 0x2 | 0x4) // FILE_SHARE_READ | WRITE | DELETE
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

#[cfg(windows)]
pub fn identity_of_path(path: &Path) -> FsIdentity {
    match open_for_identity(path) {
        Ok(file) => identity_of_handle(&file),
        Err(_) => FsIdentity::UNAVAILABLE,
    }
}

/// On Windows an identity cannot be derived from `Metadata` alone, so this resolves
/// it from the path the metadata was taken from.
#[cfg(windows)]
pub fn identity_from_metadata_and_path(_meta: &std::fs::Metadata, path: &Path) -> FsIdentity {
    identity_of_path(path)
}

#[cfg(unix)]
pub fn identity_from_metadata_and_path(meta: &std::fs::Metadata, _path: &Path) -> FsIdentity {
    identity_from_metadata(meta)
}

// ---------------------------------------------------------------------------
// Other platforms
// ---------------------------------------------------------------------------

#[cfg(not(any(unix, windows)))]
pub fn identity_of_handle(_file: &File) -> FsIdentity {
    FsIdentity::UNAVAILABLE
}

#[cfg(not(any(unix, windows)))]
pub fn identity_of_path(_path: &Path) -> FsIdentity {
    FsIdentity::UNAVAILABLE
}

#[cfg(not(any(unix, windows)))]
pub fn identity_from_metadata_and_path(_meta: &std::fs::Metadata, _path: &Path) -> FsIdentity {
    FsIdentity::UNAVAILABLE
}

// ---------------------------------------------------------------------------
// Windows FILETIME conversion
// ---------------------------------------------------------------------------

/// Number of 100-nanosecond intervals between 1601-01-01 and 1970-01-01.
#[cfg(windows)]
const FILETIME_UNIX_EPOCH_DELTA: u64 = 11_644_473_600 * 10_000_000;

/// Converts a Windows FILETIME (100 ns ticks since 1601-01-01 UTC) into a Unix
/// timestamp in seconds plus a nanosecond remainder.
///
/// Without this conversion a Windows timestamp stored in a field documented as a Unix
/// timestamp reads as a date roughly 369 years in the future, which makes every
/// human-readable report and every cross-platform manifest comparison wrong.
#[cfg(windows)]
pub fn filetime_to_unix(filetime: u64) -> (i64, i64) {
    if filetime == 0 {
        return (0, 0);
    }
    if filetime < FILETIME_UNIX_EPOCH_DELTA {
        // Pre-1970 timestamp: represent as a negative Unix time.
        let diff = FILETIME_UNIX_EPOCH_DELTA - filetime;
        let secs = (diff / 10_000_000) as i64;
        let ticks = (diff % 10_000_000) as i64;
        return (-secs, -ticks * 100);
    }
    let since_epoch = filetime - FILETIME_UNIX_EPOCH_DELTA;
    (
        (since_epoch / 10_000_000) as i64,
        ((since_epoch % 10_000_000) * 100) as i64,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn identity_is_stable_on_this_platform() {
        let temp = NamedTempFile::new().unwrap();
        let id = identity_of_path(temp.path());
        assert!(
            id.is_stable,
            "no stable filesystem identity available; TOCTOU and cycle detection \
             would silently degrade to no-ops"
        );
    }

    #[test]
    fn identity_survives_content_change() {
        let mut temp = NamedTempFile::new().unwrap();
        temp.write_all(b"before").unwrap();
        temp.flush().unwrap();
        let before = identity_of_path(temp.path());

        temp.write_all(b" after, with a different size and write time")
            .unwrap();
        temp.flush().unwrap();
        let after = identity_of_path(temp.path());

        assert!(
            before.refers_to_same(&after),
            "identity must not be derived from mutable attributes: {} -> {}",
            before,
            after
        );
    }

    #[test]
    fn distinct_files_have_distinct_identities() {
        let a = NamedTempFile::new().unwrap();
        let b = NamedTempFile::new().unwrap();
        let id_a = identity_of_path(a.path());
        let id_b = identity_of_path(b.path());
        assert!(
            !id_a.refers_to_same(&id_b),
            "two distinct files shared an identity: {} vs {}",
            id_a,
            id_b
        );
    }

    #[test]
    fn directory_identity_resolves() {
        // Directory handles need FILE_FLAG_BACKUP_SEMANTICS on Windows; if that is
        // missing, crawler cycle detection loses its key and can skip real directories.
        let dir = tempfile::tempdir().unwrap();
        let id = identity_of_path(dir.path());
        assert!(id.is_stable, "directory identity did not resolve");
    }

    #[test]
    fn distinct_directories_have_distinct_identities() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        assert!(
            !identity_of_path(a.path()).refers_to_same(&identity_of_path(b.path())),
            "two sibling directories collided; the crawler would skip one of them"
        );
    }

    #[test]
    fn missing_path_is_unavailable() {
        let id = identity_of_path(Path::new("this-path-does-not-exist-openfim-test"));
        assert!(!id.is_stable);
    }

    #[cfg(windows)]
    #[test]
    fn filetime_conversion_matches_known_values() {
        // The Unix epoch itself.
        assert_eq!(filetime_to_unix(FILETIME_UNIX_EPOCH_DELTA), (0, 0));
        // One second after the Unix epoch.
        assert_eq!(
            filetime_to_unix(FILETIME_UNIX_EPOCH_DELTA + 10_000_000),
            (1, 0)
        );
        // 2001-09-09T01:46:40Z == Unix 1_000_000_000.
        assert_eq!(
            filetime_to_unix(FILETIME_UNIX_EPOCH_DELTA + 1_000_000_000 * 10_000_000),
            (1_000_000_000, 0)
        );
        // Sub-second precision is preserved as nanoseconds.
        assert_eq!(
            filetime_to_unix(FILETIME_UNIX_EPOCH_DELTA + 1_234_567),
            (0, 123_456_700)
        );
        assert_eq!(filetime_to_unix(0), (0, 0));
    }

    #[cfg(windows)]
    #[test]
    fn filetime_conversion_is_plausible_for_a_real_file() {
        use std::os::windows::fs::MetadataExt;
        let temp = NamedTempFile::new().unwrap();
        let meta = std::fs::metadata(temp.path()).unwrap();
        let (secs, _) = filetime_to_unix(meta.last_write_time());
        // A file created moments ago must land after 2020 and before 2100.
        assert!(
            secs > 1_577_836_800 && secs < 4_102_444_800,
            "converted mtime {} is not a plausible present-day Unix timestamp",
            secs
        );
    }
}
