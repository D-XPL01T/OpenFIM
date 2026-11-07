use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::error::{OpenFimError, Result};
use crate::fsident;
use crate::hasher::{HashAlgorithm, StreamHasher};

/// Sentinel digest recorded for directory entries, which have no content to hash.
pub const DIRECTORY_SENTINEL_DIGEST: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Structured metadata representation for a monitored file entity.
///
/// Field semantics are normalized across platforms so that a manifest produced on
/// one host is comparable on another:
///
/// - `st_mtime` / `st_ctime` are **Unix timestamps in seconds**. On Windows the
///   native FILETIME (100 ns ticks since 1601) is converted, not stored raw.
/// - `st_dev` / `st_ino` are the genuine filesystem identity: `(st_dev, st_ino)` on
///   Unix, and the volume serial number plus 64-bit NTFS file index on Windows.
/// - `st_mode` is the POSIX mode on Unix and the Win32 file attribute bits on
///   Windows; the two are not comparable across platforms.
/// - `st_uid` / `st_gid` are always 0 on Windows, where ownership lives in the
///   security descriptor rather than in numeric ids. An ownership check therefore
///   has no effect on Windows; see `ownership_checks_supported`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileMetadata {
    pub path: PathBuf,
    pub st_dev: u64,
    pub st_ino: u64,
    pub st_mode: u32,
    pub st_nlink: u64,
    pub st_uid: u32,
    pub st_gid: u32,
    pub st_size: u64,
    pub st_mtime: i64,
    pub st_mtime_nsec: i64,
    pub st_ctime: i64,
    pub st_btime: Option<i64>,
    pub sha256: String,
    pub blake3: Option<String>,
    pub xattrs_hash: Option<String>,
    pub acl_hash: Option<String>,
    /// Platform-native owner identity, where numeric uid/gid are not meaningful.
    ///
    /// Holds the `owner-SID:group-SID` pair on Windows and `None` on Unix. Without it,
    /// ownership monitoring is impossible on Windows: `st_uid`/`st_gid` are always 0
    /// there, so comparing them would report "unchanged" whoever owns the file.
    #[serde(default)]
    pub owner_id: Option<String>,
    pub symlink_target: Option<String>,
    pub is_symlink: bool,
    pub is_dir: bool,
}

/// Reports whether numeric uid/gid ownership comparison is meaningful on this platform.
///
/// Returns false on Windows, where `st_uid`/`st_gid` are always 0 and an ownership
/// check would silently pass regardless of the real security descriptor.
pub const fn ownership_checks_supported() -> bool {
    cfg!(unix)
}

/// Reports whether `st_mode` carries POSIX permission bits on this platform.
///
/// Returns false on Windows, where `st_mode` holds Win32 attribute flags; a
/// permission check there detects attribute changes (read-only, hidden, system)
/// but not ACL changes.
pub const fn posix_mode_supported() -> bool {
    cfg!(unix)
}

impl FileMetadata {
    /// Extracts full metadata and cryptographic hashes for a given filesystem path
    pub fn extract<P: AsRef<Path>>(path: P, hasher: &mut StreamHasher) -> Result<Self> {
        let path_ref = path.as_ref();

        // Use symlink_metadata to avoid following symlinks blindly
        let meta = std::fs::symlink_metadata(path_ref).map_err(|e| OpenFimError::IoError {
            path: path_ref.to_path_buf(),
            source: e,
        })?;

        let is_symlink = meta.file_type().is_symlink();
        let is_dir = meta.file_type().is_dir();

        let symlink_target = if is_symlink {
            std::fs::read_link(path_ref)
                .ok()
                .map(|p| p.to_string_lossy().to_string())
        } else {
            None
        };

        // Compute hash for regular files; for symlinks, hash the target path string;
        // for directories, record the sentinel digest.
        let (sha256, blake3) = if is_dir {
            (DIRECTORY_SENTINEL_DIGEST.to_string(), None)
        } else if is_symlink {
            let target_bytes = symlink_target.as_deref().unwrap_or("").as_bytes();
            (
                StreamHasher::hash_bytes(HashAlgorithm::Sha256, target_bytes),
                Some(StreamHasher::hash_bytes(
                    HashAlgorithm::Blake3,
                    target_bytes,
                )),
            )
        } else {
            let hash_res = hasher.hash_file(path_ref)?;
            // Place the digest in the field matching the algorithm that produced it,
            // rather than unconditionally labelling it `sha256`.
            match hash_res.algorithm {
                HashAlgorithm::Blake3 => (
                    DIRECTORY_SENTINEL_DIGEST.to_string(),
                    Some(hash_res.hex_digest),
                ),
                _ => (hash_res.hex_digest, hash_res.blake3_digest),
            }
        };

        // Genuine filesystem identity, resolved through the shared platform helper so
        // the hasher's TOCTOU check and the crawler's cycle detection agree with it.
        let identity = fsident::identity_from_metadata_and_path(&meta, path_ref);

        // Security-relevant state that a content hash cannot see: extended attributes
        // (SELinux labels, file capabilities, NTFS alternate data streams), the access
        // control policy, and the platform-native owner identity.
        //
        // Directories are included: a `system.posix_acl_default` change silently alters
        // the permissions of everything created in the directory afterwards.
        let xattrs_hash = crate::xattr::hash_path_attributes(path_ref);
        let acl_hash = crate::acl::hash_access_control(path_ref);
        let owner_id = crate::acl::owner_identity(path_ref);

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            Ok(FileMetadata {
                path: path_ref.to_path_buf(),
                st_dev: identity.device_id,
                st_ino: identity.inode_or_index,
                st_mode: meta.mode(),
                st_nlink: identity.nlink,
                st_uid: meta.uid(),
                st_gid: meta.gid(),
                st_size: meta.size(),
                st_mtime: meta.mtime(),
                st_mtime_nsec: meta.mtime_nsec(),
                st_ctime: meta.ctime(),
                st_btime: None,
                sha256,
                blake3,
                xattrs_hash,
                acl_hash,
                owner_id,
                symlink_target,
                is_symlink,
                is_dir,
            })
        }

        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;

            // Convert native FILETIME values into Unix epoch seconds + nanoseconds.
            // Storing the raw FILETIME in a field documented as a Unix timestamp
            // yields dates roughly 369 years in the future.
            let (mtime, mtime_nsec) = fsident::filetime_to_unix(meta.last_write_time());
            let (ctime, _) = fsident::filetime_to_unix(meta.creation_time());

            Ok(FileMetadata {
                path: path_ref.to_path_buf(),
                st_dev: identity.device_id,
                st_ino: identity.inode_or_index,
                // Win32 attribute bits, not POSIX permissions. See the struct docs.
                st_mode: meta.file_attributes(),
                st_nlink: identity.nlink,
                st_uid: 0,
                st_gid: 0,
                st_size: meta.file_size(),
                st_mtime: mtime,
                st_mtime_nsec: mtime_nsec,
                st_ctime: ctime,
                st_btime: Some(ctime),
                sha256,
                blake3,
                xattrs_hash,
                acl_hash,
                owner_id,
                symlink_target,
                is_symlink,
                is_dir,
            })
        }

        #[cfg(not(any(unix, windows)))]
        {
            Ok(FileMetadata {
                path: path_ref.to_path_buf(),
                st_dev: identity.device_id,
                st_ino: identity.inode_or_index,
                st_mode: 0,
                st_nlink: identity.nlink,
                st_uid: 0,
                st_gid: 0,
                st_size: meta.len(),
                st_mtime: 0,
                st_mtime_nsec: 0,
                st_ctime: 0,
                st_btime: None,
                sha256,
                blake3,
                xattrs_hash,
                acl_hash,
                owner_id,
                symlink_target,
                is_symlink,
                is_dir,
            })
        }
    }

    /// POSIX permission bits, when `st_mode` carries them on this platform.
    ///
    /// Masked to the permission and set-id bits: `st_mode` also encodes the file type
    /// in its high bits, so comparing the whole word would make a regular file becoming
    /// a symlink look like a permission edit on top of the kind change already
    /// reported.
    ///
    /// Returns `None` on Windows, where `st_mode` holds Win32 attribute flags and the
    /// real access control policy lives in the security descriptor.
    pub fn permission_bits(&self) -> Option<u32> {
        if posix_mode_supported() {
            Some(self.st_mode & 0o7777)
        } else {
            None
        }
    }

    /// Filesystem attribute flags, when this platform records them.
    ///
    /// On Windows these are the Win32 attribute bits (read-only, hidden, system,
    /// archive, …). Returns `None` on Unix, where the equivalent inode flags (the
    /// `chattr` set) are not yet captured — rather than returning the POSIX mode,
    /// which would make an attribute check silently duplicate the permission check.
    pub fn attribute_flags(&self) -> Option<u32> {
        if cfg!(windows) {
            Some(self.st_mode)
        } else {
            None
        }
    }

    /// Returns the identity tuple used for cycle detection and hardlink tracking.
    pub fn identity_key(&self) -> (u64, u64) {
        (self.st_dev, self.st_ino)
    }

    /// True when this entry has a resolvable filesystem identity.
    ///
    /// Entries without one must not be used as cycle-detection keys, since every
    /// such entry would collide on `(0, 0)`.
    pub fn has_stable_identity(&self) -> bool {
        !(self.st_dev == 0 && self.st_ino == 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::{tempdir, NamedTempFile};

    #[test]
    fn test_extract_basic_file_metadata() {
        let mut temp = NamedTempFile::new().unwrap();
        temp.write_all(b"integrity payload").unwrap();
        temp.flush().unwrap();

        let mut hasher = StreamHasher::default_sha256();
        let meta = FileMetadata::extract(temp.path(), &mut hasher).unwrap();

        assert_eq!(meta.st_size, 17);
        assert!(!meta.is_dir);
        assert!(!meta.is_symlink);
        assert_eq!(
            meta.sha256,
            StreamHasher::hash_bytes(HashAlgorithm::Sha256, b"integrity payload")
        );
    }

    #[test]
    fn test_mtime_is_a_plausible_unix_timestamp() {
        // Regression guard: on Windows the native value is a FILETIME (100 ns ticks
        // since 1601). Storing it unconverted puts every mtime around the year 2395.
        let temp = NamedTempFile::new().unwrap();
        let mut hasher = StreamHasher::default_sha256();
        let meta = FileMetadata::extract(temp.path(), &mut hasher).unwrap();

        // 2020-01-01 .. 2100-01-01 in Unix seconds.
        assert!(
            meta.st_mtime > 1_577_836_800 && meta.st_mtime < 4_102_444_800,
            "st_mtime {} is not a plausible present-day Unix timestamp",
            meta.st_mtime
        );
        assert!(
            meta.st_ctime > 1_577_836_800 && meta.st_ctime < 4_102_444_800,
            "st_ctime {} is not a plausible present-day Unix timestamp",
            meta.st_ctime
        );
    }

    #[test]
    fn test_identity_is_resolved_not_fabricated() {
        let mut temp = NamedTempFile::new().unwrap();
        temp.write_all(b"v1").unwrap();
        temp.flush().unwrap();

        let mut hasher = StreamHasher::default_sha256();
        let first = FileMetadata::extract(temp.path(), &mut hasher).unwrap();
        assert!(
            first.has_stable_identity(),
            "no filesystem identity resolved for a regular file"
        );

        // Changing content must not change identity.
        temp.write_all(b" plus much more content").unwrap();
        temp.flush().unwrap();
        let second = FileMetadata::extract(temp.path(), &mut hasher).unwrap();

        assert_eq!(
            first.identity_key(),
            second.identity_key(),
            "identity changed after a content write, so it is derived from mutable \
             attributes rather than from the filesystem object"
        );
        assert_ne!(
            first.sha256, second.sha256,
            "content hash should have changed"
        );
    }

    #[test]
    fn test_sibling_files_do_not_share_identity() {
        let dir = tempdir().unwrap();
        let a = dir.path().join("a.conf");
        let b = dir.path().join("b.conf");
        std::fs::write(&a, b"same size!").unwrap();
        std::fs::write(&b, b"same size!").unwrap();

        let mut hasher = StreamHasher::default_sha256();
        let ma = FileMetadata::extract(&a, &mut hasher).unwrap();
        let mb = FileMetadata::extract(&b, &mut hasher).unwrap();

        assert_ne!(
            ma.identity_key(),
            mb.identity_key(),
            "two same-size files created together collided on identity"
        );
    }

    #[test]
    fn test_directory_entry_uses_sentinel_digest() {
        let dir = tempdir().unwrap();
        let mut hasher = StreamHasher::default_sha256();
        let meta = FileMetadata::extract(dir.path(), &mut hasher).unwrap();

        assert!(meta.is_dir);
        assert_eq!(meta.sha256, DIRECTORY_SENTINEL_DIGEST);
        assert!(meta.has_stable_identity());
    }

    #[test]
    fn test_secondary_blake3_is_recorded() {
        // The blake3 column is only populated when the hasher is asked for it; before
        // this was wired up the column was permanently NULL for every regular file.
        let mut temp = NamedTempFile::new().unwrap();
        temp.write_all(b"dual digest").unwrap();
        temp.flush().unwrap();

        let mut hasher = StreamHasher::default_sha256().with_secondary_blake3(true);
        let meta = FileMetadata::extract(temp.path(), &mut hasher).unwrap();

        assert_eq!(
            meta.blake3.as_deref(),
            Some(StreamHasher::hash_bytes(HashAlgorithm::Blake3, b"dual digest").as_str())
        );
    }

    #[test]
    fn test_missing_file_reports_io_error_with_path() {
        let mut hasher = StreamHasher::default_sha256();
        let err = FileMetadata::extract("definitely-not-a-real-openfim-path", &mut hasher)
            .expect_err("extracting a missing path must fail");
        assert!(matches!(err, OpenFimError::IoError { .. }));
    }
}
