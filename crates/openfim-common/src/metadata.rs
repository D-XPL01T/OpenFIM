use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};

use crate::error::{OpenFimError, Result};
use crate::hasher::{HashAlgorithm, StreamHasher};

/// Structured 64-byte metadata representation for a monitored file entity
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
    pub symlink_target: Option<String>,
    pub is_symlink: bool,
    pub is_dir: bool,
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

        // Compute hash for regular files; for symlinks, hash the target path string; for dirs, empty hash
        let (sha256, blake3) = if is_dir {
            ("0000000000000000000000000000000000000000000000000000000000000000".to_string(), None)
        } else if is_symlink {
            let target_bytes = symlink_target.as_deref().unwrap_or("").as_bytes();
            (
                StreamHasher::hash_bytes(HashAlgorithm::Sha256, target_bytes),
                Some(StreamHasher::hash_bytes(HashAlgorithm::Blake3, target_bytes)),
            )
        } else {
            let hash_res = hasher.hash_file(path_ref)?;
            (hash_res.hex_digest, None)
        };

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            Ok(FileMetadata {
                path: path_ref.to_path_buf(),
                st_dev: meta.dev(),
                st_ino: meta.ino(),
                st_mode: meta.mode(),
                st_nlink: meta.nlink(),
                st_uid: meta.uid(),
                st_gid: meta.gid(),
                st_size: meta.size(),
                st_mtime: meta.mtime(),
                st_mtime_nsec: meta.mtime_nsec(),
                st_ctime: meta.ctime(),
                st_btime: None,
                sha256,
                blake3,
                xattrs_hash: None,
                acl_hash: None,
                symlink_target,
                is_symlink,
                is_dir,
            })
        }

        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            let mtime = meta.last_write_time() as i64;
            let ctime = meta.creation_time() as i64;
            let dev = meta.creation_time() as u64;
            let ino = meta.file_size() ^ ((meta.last_write_time() as u64) << 16);
            let mode = meta.file_attributes();

            Ok(FileMetadata {
                path: path_ref.to_path_buf(),
                st_dev: dev,
                st_ino: ino,
                st_mode: mode,
                st_nlink: 1,
                st_uid: 0,
                st_gid: 0,
                st_size: meta.file_size(),
                st_mtime: mtime,
                st_mtime_nsec: 0,
                st_ctime: ctime,
                st_btime: Some(ctime),
                sha256,
                blake3,
                xattrs_hash: None,
                acl_hash: None,
                symlink_target,
                is_symlink,
                is_dir,
            })
        }

        #[cfg(not(any(unix, windows)))]
        {
            Ok(FileMetadata {
                path: path_ref.to_path_buf(),
                st_dev: 0,
                st_ino: 0,
                st_mode: 0,
                st_nlink: 1,
                st_uid: 0,
                st_gid: 0,
                st_size: meta.len(),
                st_mtime: 0,
                st_mtime_nsec: 0,
                st_ctime: 0,
                st_btime: None,
                sha256,
                blake3,
                xattrs_hash: None,
                acl_hash: None,
                symlink_target,
                is_symlink,
                is_dir,
            })
        }
    }
}
