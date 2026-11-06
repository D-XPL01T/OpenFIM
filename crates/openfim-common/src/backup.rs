//! Content-addressed pristine-copy store for baseline restoration.
//!
//! # Why this is not a flat directory
//!
//! The obvious implementation of "a directory of pristine copies" resolves a backup as
//! `backup_dir.join(path.file_name())`. That is a **flat namespace**, and it is wrong in
//! a way that destroys data rather than merely failing:
//!
//! ```text
//!   monitored:  /etc/nginx/conf.d/app.conf   ──┐
//!   monitored:  /opt/myapp/config/app.conf   ──┤ both map to
//!                                              └─► backups/app.conf
//! ```
//!
//! With one backup file serving two monitored paths, a restore triggered on either one
//! writes *the other file's contents* over a live file. The operator asked the tool to
//! put the good copy back and it silently replaced the file with unrelated data. A
//! single-file demo never reveals this; a real directory tree hits it immediately.
//!
//! # Layout
//!
//! Objects are addressed by the SHA-256 of their contents, so two monitored files can
//! never collide, and identical content is stored once:
//!
//! ```text
//!   <root>/backup_manifest.json        index: normalized path -> digest + metadata
//!   <root>/objects/<aa>/<full-digest>  content, sharded by the first byte
//! ```
//!
//! The two-character shard keeps directory sizes manageable on filesystems that degrade
//! with very large directories.
//!
//! # Integrity
//!
//! A restore re-hashes the bytes it just wrote and fails if they do not match the
//! recorded digest. A backup store that silently returns corrupt content would be worse
//! than having no backup at all, because the operator would believe the file had been
//! repaired.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::db::{canonical_path_key, path_lookup_candidates};
use crate::error::{OpenFimError, Result};
use crate::hasher::{HashAlgorithm, StreamHasher};

/// On-disk layout version, so a future change can be detected rather than misread.
pub const BACKUP_LAYOUT_VERSION: u32 = 1;

/// Subdirectory holding content-addressed objects.
pub const OBJECTS_DIR: &str = "objects";

/// Index file mapping monitored paths to the objects that back them.
pub const MANIFEST_FILE: &str = "backup_manifest.json";

/// One monitored path's pristine copy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupEntry {
    /// SHA-256 of the stored content; also its address in the object store.
    pub sha256: String,
    pub size: u64,
    /// Baseline manifest version this copy was captured under.
    pub manifest_version: String,
    /// Unix seconds at capture time.
    pub recorded_at: i64,
}

/// Index of every monitored path with a pristine copy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupManifest {
    pub layout_version: u32,
    pub created_at: i64,
    /// Normalized monitored path -> stored object. `BTreeMap` so the serialized
    /// manifest is byte-stable across writes, which makes it diffable and lets the
    /// store itself be integrity-checked.
    pub entries: BTreeMap<String, BackupEntry>,
}

impl Default for BackupManifest {
    fn default() -> Self {
        Self {
            layout_version: BACKUP_LAYOUT_VERSION,
            created_at: unix_now(),
            entries: BTreeMap::new(),
        }
    }
}

/// Result of restoring a monitored path from its pristine copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestoreOutcome {
    /// Content was written back and verified against the recorded digest.
    Restored { sha256: String, size: u64 },
    /// No pristine copy is available for this path.
    NoBackup,
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// A content-addressed store of pristine file copies.
#[derive(Debug, Clone)]
pub struct BackupStore {
    root: PathBuf,
    manifest: BackupManifest,
}

impl BackupStore {
    /// Opens an existing store, or initializes an empty one at `root`.
    ///
    /// Refuses to operate on a legacy flat backup directory rather than guessing: see
    /// [`BackupStore::is_legacy_flat_layout`].
    pub fn open_or_create<P: AsRef<Path>>(root: P) -> Result<Self> {
        let root = root.as_ref().to_path_buf();

        if Self::is_legacy_flat_layout(&root) {
            return Err(OpenFimError::Other(format!(
                "'{}' looks like a legacy flat backup directory (loose files, no '{}' \
                 index). That layout keys backups by filename alone, so two monitored \
                 files with the same name share one backup and a restore can write the \
                 wrong file's contents over a live file. Refusing to use it. Create a \
                 content-addressed store instead with: \
                 openfim-cli baseline backup --db <DB> --out <NEW_DIR>",
                root.display(),
                MANIFEST_FILE
            )));
        }

        std::fs::create_dir_all(root.join(OBJECTS_DIR)).map_err(|e| OpenFimError::IoError {
            path: root.join(OBJECTS_DIR),
            source: e,
        })?;

        let manifest_path = root.join(MANIFEST_FILE);
        let manifest = if manifest_path.exists() {
            let raw =
                std::fs::read_to_string(&manifest_path).map_err(|e| OpenFimError::IoError {
                    path: manifest_path.clone(),
                    source: e,
                })?;
            let parsed: BackupManifest = serde_json::from_str(&raw)?;
            if parsed.layout_version != BACKUP_LAYOUT_VERSION {
                return Err(OpenFimError::Other(format!(
                    "backup store at '{}' uses layout version {}, but this build \
                     understands version {}",
                    root.display(),
                    parsed.layout_version,
                    BACKUP_LAYOUT_VERSION
                )));
            }
            parsed
        } else {
            BackupManifest::default()
        };

        Ok(Self { root, manifest })
    }

    /// Opens an existing store, returning `None` when `root` holds no store.
    pub fn open_existing<P: AsRef<Path>>(root: P) -> Result<Option<Self>> {
        let root = root.as_ref();
        if !root.join(MANIFEST_FILE).exists() {
            return Ok(None);
        }
        Self::open_or_create(root).map(Some)
    }

    /// Heuristic: a directory that contains loose files but neither the manifest nor the
    /// object directory is the old flat layout.
    ///
    /// Detecting this matters because the old layout is not merely unsupported, it is
    /// unsafe. Treating it as an empty store would let a restore silently find nothing;
    /// treating it as valid would reintroduce the collision. Refusing is the only
    /// correct option.
    pub fn is_legacy_flat_layout<P: AsRef<Path>>(root: P) -> bool {
        let root = root.as_ref();
        if !root.is_dir() {
            return false;
        }
        if root.join(MANIFEST_FILE).exists() || root.join(OBJECTS_DIR).is_dir() {
            return false;
        }
        std::fs::read_dir(root)
            .map(|entries| {
                entries
                    .filter_map(|e| e.ok())
                    .any(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
            })
            .unwrap_or(false)
    }

    /// The store's root directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Number of monitored paths with a pristine copy.
    pub fn len(&self) -> usize {
        self.manifest.entries.len()
    }

    /// True when no pristine copies are recorded.
    pub fn is_empty(&self) -> bool {
        self.manifest.entries.is_empty()
    }

    /// Where a given digest lives on disk.
    pub fn object_path(&self, sha256: &str) -> PathBuf {
        let shard = if sha256.len() >= 2 {
            &sha256[..2]
        } else {
            "00"
        };
        self.root.join(OBJECTS_DIR).join(shard).join(sha256)
    }

    /// The recorded pristine copy for a monitored path, if any.
    ///
    /// Tries every plausible spelling of the path, because the same file is named
    /// relatively by a CLI crawl and absolutely by the real-time watcher. Matching only
    /// the exact string would make a restore triggered by the sensor miss a copy the
    /// CLI had captured — the failure mode that looks like "no backup configured" while
    /// a perfectly good copy sits in the store.
    pub fn lookup<P: AsRef<Path>>(&self, path: P) -> Option<&BackupEntry> {
        for candidate in path_lookup_candidates(path) {
            if let Some(entry) = self.manifest.entries.get(&candidate) {
                return Some(entry);
            }
        }
        None
    }

    /// Captures the current contents of `path` as its pristine copy.
    pub fn store_file<P: AsRef<Path>>(
        &mut self,
        path: P,
        manifest_version: &str,
    ) -> Result<BackupEntry> {
        let path = path.as_ref();

        let mut hasher = StreamHasher::default_sha256();
        let hash = hasher.hash_file(path)?;
        let object = self.object_path(&hash.hex_digest);

        if !object.exists() {
            if let Some(parent) = object.parent() {
                std::fs::create_dir_all(parent).map_err(|e| OpenFimError::IoError {
                    path: parent.to_path_buf(),
                    source: e,
                })?;
            }
            // Write to a temporary name then rename, so a concurrent reader never sees
            // a partially written object under its final digest-addressed name.
            let staging = object.with_extension("partial");
            std::fs::copy(path, &staging).map_err(|e| OpenFimError::IoError {
                path: staging.clone(),
                source: e,
            })?;
            std::fs::rename(&staging, &object).map_err(|e| OpenFimError::IoError {
                path: object.clone(),
                source: e,
            })?;
        }

        let entry = BackupEntry {
            sha256: hash.hex_digest,
            size: hash.bytes_read,
            manifest_version: manifest_version.to_string(),
            recorded_at: unix_now(),
        };

        // Keyed by the absolute form so the sensor and the CLI agree on the key.
        self.manifest
            .entries
            .insert(canonical_path_key(path), entry.clone());
        Ok(entry)
    }

    /// Restores `path` from its pristine copy, verifying the result.
    ///
    /// The bytes are staged beside the target and renamed into place, so the monitored
    /// path is never observed truncated or half-written by the live workload. The
    /// staged copy is re-hashed before the rename; a digest mismatch aborts the restore
    /// and leaves the original file untouched.
    pub fn restore<P: AsRef<Path>>(&self, path: P) -> Result<RestoreOutcome> {
        let path = path.as_ref();
        let entry = match self.lookup(path) {
            Some(e) => e,
            None => return Ok(RestoreOutcome::NoBackup),
        };

        let object = self.object_path(&entry.sha256);
        if !object.exists() {
            return Err(OpenFimError::Other(format!(
                "backup store is corrupt: '{}' is indexed with digest {} but that \
                 object is missing from the store",
                path.display(),
                entry.sha256
            )));
        }

        let staging = path.with_extension(format!(
            "{}.openfim-restore",
            path.extension()
                .map(|e| e.to_string_lossy().to_string())
                .unwrap_or_default()
        ));

        std::fs::copy(&object, &staging).map_err(|e| OpenFimError::IoError {
            path: staging.clone(),
            source: e,
        })?;

        // Verify what we are about to install, not what we read from the store.
        let mut hasher = StreamHasher::default_sha256();
        let staged_hash = match hasher.hash_file(&staging) {
            Ok(h) => h,
            Err(e) => {
                let _ = std::fs::remove_file(&staging);
                return Err(e);
            }
        };

        if staged_hash.hex_digest != entry.sha256 {
            let _ = std::fs::remove_file(&staging);
            return Err(OpenFimError::Other(format!(
                "refusing to restore '{}': staged copy hashes to {} but the store \
                 recorded {}. The backup store or the staged copy is corrupt; the live \
                 file has been left untouched.",
                path.display(),
                staged_hash.hex_digest,
                entry.sha256
            )));
        }

        if let Err(e) = std::fs::rename(&staging, path) {
            let _ = std::fs::remove_file(&staging);
            return Err(OpenFimError::IoError {
                path: path.to_path_buf(),
                source: e,
            });
        }

        Ok(RestoreOutcome::Restored {
            sha256: entry.sha256.clone(),
            size: entry.size,
        })
    }

    /// Persists the index.
    pub fn save(&self) -> Result<()> {
        let manifest_path = self.root.join(MANIFEST_FILE);
        let json = serde_json::to_string_pretty(&self.manifest)?;
        let staging = manifest_path.with_extension("json.partial");
        std::fs::write(&staging, json.as_bytes()).map_err(|e| OpenFimError::IoError {
            path: staging.clone(),
            source: e,
        })?;
        std::fs::rename(&staging, &manifest_path).map_err(|e| OpenFimError::IoError {
            path: manifest_path,
            source: e,
        })?;
        Ok(())
    }

    /// Re-hashes every object and reports paths whose content no longer matches.
    pub fn verify(&self) -> Result<Vec<String>> {
        let mut corrupt = Vec::new();
        for (path, entry) in &self.manifest.entries {
            let object = self.object_path(&entry.sha256);
            if !object.exists() {
                corrupt.push(format!("{} (object {} missing)", path, entry.sha256));
                continue;
            }
            let mut hasher = StreamHasher::default_sha256();
            match hasher.hash_file(&object) {
                Ok(h) if h.hex_digest == entry.sha256 => {}
                Ok(h) => corrupt.push(format!(
                    "{} (object content hashes to {}, expected {})",
                    path, h.hex_digest, entry.sha256
                )),
                Err(e) => corrupt.push(format!("{} (unreadable: {})", path, e)),
            }
        }
        Ok(corrupt)
    }
}

/// Hashing algorithm used to address objects. Fixed, so addresses stay stable.
pub const OBJECT_ADDRESS_ALGORITHM: HashAlgorithm = HashAlgorithm::Sha256;

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn same_named_files_in_different_directories_do_not_collide() {
        // This is the defect the content-addressed layout exists to prevent. A flat
        // `backup_dir.join(file_name)` store maps both of these to `backups/app.conf`,
        // and restoring either one writes the other's contents over a live file.
        let work = tempdir().unwrap();
        let store_root = work.path().join("store");

        let dir_a = work.path().join("nginx/conf.d");
        let dir_b = work.path().join("myapp/config");
        std::fs::create_dir_all(&dir_a).unwrap();
        std::fs::create_dir_all(&dir_b).unwrap();

        let file_a = dir_a.join("app.conf");
        let file_b = dir_b.join("app.conf");
        std::fs::write(&file_a, b"NGINX PRISTINE CONTENT").unwrap();
        std::fs::write(&file_b, b"MYAPP PRISTINE CONTENT").unwrap();

        let mut store = BackupStore::open_or_create(&store_root).unwrap();
        store.store_file(&file_a, "v1").unwrap();
        store.store_file(&file_b, "v1").unwrap();
        store.save().unwrap();
        assert_eq!(store.len(), 2, "both files must be tracked independently");

        // An adversary tampers with both.
        std::fs::write(&file_a, b"TAMPERED A").unwrap();
        std::fs::write(&file_b, b"TAMPERED B").unwrap();

        assert!(matches!(
            store.restore(&file_a).unwrap(),
            RestoreOutcome::Restored { .. }
        ));
        assert!(matches!(
            store.restore(&file_b).unwrap(),
            RestoreOutcome::Restored { .. }
        ));

        assert_eq!(
            std::fs::read(&file_a).unwrap(),
            b"NGINX PRISTINE CONTENT",
            "file A was restored from the wrong backup"
        );
        assert_eq!(
            std::fs::read(&file_b).unwrap(),
            b"MYAPP PRISTINE CONTENT",
            "file B was restored from the wrong backup"
        );
    }

    #[test]
    fn copy_captured_by_relative_path_is_found_by_absolute_path() {
        // Regression guard for a real failure caught by the end-to-end demo: the CLI
        // captures backups from a relative crawl ("demo/data/app.conf") while the
        // real-time sensor reports absolute paths. Keying on the raw spelling made the
        // sensor's restore miss a copy that was sitting in the store, and the
        // remediation declined with "no pristine copy" during a live incident.
        // The file must sit under the process working directory for a relative spelling
        // of it to exist at all. `target/` is build output and already gitignored.
        let cwd = std::env::current_dir().unwrap();
        let work = cwd.join("target").join(format!(
            "openfim-relkey-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&work);
        std::fs::create_dir_all(&work).unwrap();

        let target = work.join("app.conf");
        std::fs::write(&target, b"pristine").unwrap();

        let mut store = BackupStore::open_or_create(work.join("store")).unwrap();
        let entry = store.store_file(&target, "v1").unwrap();

        // Re-key the index to the working-directory-relative spelling, which is what a
        // CLI crawl of a relative directory produces. Done by rewriting the key rather
        // than by changing the process working directory, because cargo runs tests in
        // threads that share one cwd and mutating it would corrupt unrelated tests.
        let relative_key = crate::db::normalize_path_str(
            target
                .strip_prefix(&cwd)
                .expect("test path was constructed under cwd"),
        );
        assert!(
            !Path::new(&relative_key).is_absolute(),
            "test setup failed to produce a relative key"
        );
        store.manifest.entries.clear();
        store.manifest.entries.insert(relative_key, entry);

        // Look up using the absolute path, as the sensor would.
        assert!(
            store.lookup(&target).is_some(),
            "a copy captured by relative path must be findable by its absolute path"
        );

        std::fs::write(&target, b"tampered").unwrap();
        assert!(matches!(
            store.restore(&target).unwrap(),
            RestoreOutcome::Restored { .. }
        ));
        assert_eq!(std::fs::read(&target).unwrap(), b"pristine");

        let _ = std::fs::remove_dir_all(&work);
    }

    #[test]
    fn keys_are_stored_in_absolute_form() {
        let work = tempdir().unwrap();
        let target = work.path().join("app.conf");
        std::fs::write(&target, b"x").unwrap();

        let mut store = BackupStore::open_or_create(work.path().join("store")).unwrap();
        store.store_file(&target, "v1").unwrap();
        store.save().unwrap();

        let reopened = BackupStore::open_existing(work.path().join("store"))
            .unwrap()
            .unwrap();
        let key = reopened.manifest.entries.keys().next().unwrap();
        assert!(
            Path::new(key).is_absolute(),
            "store key '{}' is not absolute, so lookups will depend on the caller's cwd",
            key
        );
    }

    #[test]
    fn identical_content_is_stored_once() {
        let work = tempdir().unwrap();
        let a = work.path().join("a.conf");
        let b = work.path().join("b.conf");
        std::fs::write(&a, b"shared content").unwrap();
        std::fs::write(&b, b"shared content").unwrap();

        let mut store = BackupStore::open_or_create(work.path().join("store")).unwrap();
        let ea = store.store_file(&a, "v1").unwrap();
        let eb = store.store_file(&b, "v1").unwrap();

        assert_eq!(ea.sha256, eb.sha256);
        assert_eq!(store.len(), 2, "two paths");
        assert_eq!(
            store.object_path(&ea.sha256),
            store.object_path(&eb.sha256),
            "one object"
        );
    }

    #[test]
    fn restore_reports_no_backup_for_untracked_path() {
        let work = tempdir().unwrap();
        let store = BackupStore::open_or_create(work.path().join("store")).unwrap();
        assert_eq!(
            store
                .restore(work.path().join("never-tracked.conf"))
                .unwrap(),
            RestoreOutcome::NoBackup
        );
    }

    #[test]
    fn restore_leaves_no_staging_file_behind() {
        let work = tempdir().unwrap();
        let target = work.path().join("app.conf");
        std::fs::write(&target, b"good").unwrap();

        let mut store = BackupStore::open_or_create(work.path().join("store")).unwrap();
        store.store_file(&target, "v1").unwrap();
        std::fs::write(&target, b"bad").unwrap();
        store.restore(&target).unwrap();

        let strays: Vec<_> = std::fs::read_dir(work.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains("openfim-restore"))
            .collect();
        assert!(strays.is_empty(), "staging file left behind: {:?}", strays);
    }

    #[test]
    fn corrupt_object_is_refused_and_live_file_untouched() {
        // A backup store that silently returns corrupt content is worse than no store,
        // because the operator believes the file was repaired.
        let work = tempdir().unwrap();
        let target = work.path().join("app.conf");
        std::fs::write(&target, b"pristine").unwrap();

        let mut store = BackupStore::open_or_create(work.path().join("store")).unwrap();
        let entry = store.store_file(&target, "v1").unwrap();
        store.save().unwrap();

        // Corrupt the stored object behind the index's back.
        std::fs::write(store.object_path(&entry.sha256), b"CORRUPTED OBJECT").unwrap();

        std::fs::write(&target, b"tampered live content").unwrap();
        let err = store
            .restore(&target)
            .expect_err("corrupt restore must fail");
        assert!(err.to_string().contains("refusing to restore"));
        assert_eq!(
            std::fs::read(&target).unwrap(),
            b"tampered live content",
            "a refused restore must not modify the live file"
        );
    }

    #[test]
    fn missing_object_is_reported_as_corruption() {
        let work = tempdir().unwrap();
        let target = work.path().join("app.conf");
        std::fs::write(&target, b"pristine").unwrap();

        let mut store = BackupStore::open_or_create(work.path().join("store")).unwrap();
        let entry = store.store_file(&target, "v1").unwrap();
        std::fs::remove_file(store.object_path(&entry.sha256)).unwrap();

        assert!(store.restore(&target).is_err());
        assert_eq!(store.verify().unwrap().len(), 1);
    }

    #[test]
    fn legacy_flat_directory_is_refused_with_migration_guidance() {
        let work = tempdir().unwrap();
        let legacy = work.path().join("backups");
        std::fs::create_dir_all(&legacy).unwrap();
        std::fs::write(legacy.join("app.conf"), b"loose file").unwrap();

        assert!(BackupStore::is_legacy_flat_layout(&legacy));
        let err = BackupStore::open_or_create(&legacy)
            .expect_err("a legacy flat layout must be refused, not silently adopted");
        let msg = err.to_string();
        assert!(msg.contains("legacy flat backup directory"));
        assert!(
            msg.contains("baseline backup"),
            "the error should tell the operator how to migrate: {}",
            msg
        );
    }

    #[test]
    fn empty_directory_is_not_mistaken_for_legacy_layout() {
        let work = tempdir().unwrap();
        let fresh = work.path().join("fresh");
        std::fs::create_dir_all(&fresh).unwrap();
        assert!(!BackupStore::is_legacy_flat_layout(&fresh));
        assert!(BackupStore::open_or_create(&fresh).is_ok());
    }

    #[test]
    fn nonexistent_directory_is_not_legacy_and_is_created() {
        let work = tempdir().unwrap();
        let path = work.path().join("not-yet");
        assert!(!BackupStore::is_legacy_flat_layout(&path));
        let store = BackupStore::open_or_create(&path).unwrap();
        assert!(path.join(OBJECTS_DIR).is_dir());
        assert!(store.is_empty());
    }

    #[test]
    fn store_round_trips_through_disk() {
        let work = tempdir().unwrap();
        let root = work.path().join("store");
        let target = work.path().join("app.conf");
        std::fs::write(&target, b"persisted").unwrap();

        {
            let mut store = BackupStore::open_or_create(&root).unwrap();
            store.store_file(&target, "v7").unwrap();
            store.save().unwrap();
        }

        let reopened = BackupStore::open_existing(&root).unwrap().unwrap();
        assert_eq!(reopened.len(), 1);
        let entry = reopened
            .lookup(&target)
            .expect("entry should survive reload");
        assert_eq!(entry.manifest_version, "v7");
        assert_eq!(entry.size, 9);
    }

    #[test]
    fn open_existing_returns_none_without_a_manifest() {
        let work = tempdir().unwrap();
        assert!(BackupStore::open_existing(work.path().join("nothing"))
            .unwrap()
            .is_none());
    }

    #[test]
    fn verify_passes_on_a_healthy_store() {
        let work = tempdir().unwrap();
        let target = work.path().join("app.conf");
        std::fs::write(&target, b"healthy").unwrap();
        let mut store = BackupStore::open_or_create(work.path().join("store")).unwrap();
        store.store_file(&target, "v1").unwrap();
        assert!(store.verify().unwrap().is_empty());
    }

    #[test]
    fn recapturing_a_path_updates_its_digest() {
        let work = tempdir().unwrap();
        let target = work.path().join("app.conf");
        std::fs::write(&target, b"first").unwrap();

        let mut store = BackupStore::open_or_create(work.path().join("store")).unwrap();
        let first = store.store_file(&target, "v1").unwrap();

        std::fs::write(&target, b"second, approved change").unwrap();
        let second = store.store_file(&target, "v2").unwrap();

        assert_ne!(first.sha256, second.sha256);
        assert_eq!(store.lookup(&target).unwrap().sha256, second.sha256);
        assert_eq!(
            store.len(),
            1,
            "re-capture must not duplicate the path entry"
        );

        // Restoring now yields the newer approved content.
        std::fs::write(&target, b"tampered").unwrap();
        store.restore(&target).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"second, approved change");
    }
}
