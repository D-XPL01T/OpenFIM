use std::collections::HashMap;
use std::path::{Path, PathBuf};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::metadata::FileMetadata;

/// Change record representing a cryptographic hash divergence
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentChange {
    pub path: PathBuf,
    pub old_sha256: String,
    pub new_sha256: String,
    pub old_size: u64,
    pub new_size: u64,
}

/// Change record representing a permission, ownership, or attribute modification
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetadataChange {
    pub path: PathBuf,
    pub old_mode: u32,
    pub new_mode: u32,
    pub old_uid: u32,
    pub new_uid: u32,
    pub old_gid: u32,
    pub new_gid: u32,
}

/// Baseline Diff summary comparing current filesystem state against active baseline
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselineDiff {
    pub added: Vec<FileMetadata>,
    pub removed: Vec<FileMetadata>,
    pub modified_content: Vec<ContentChange>,
    pub modified_metadata: Vec<MetadataChange>,
}

impl BaselineDiff {
    /// Returns true if no changes were detected (clean integrity)
    pub fn is_clean(&self) -> bool {
        self.added.is_empty()
            && self.removed.is_empty()
            && self.modified_content.is_empty()
            && self.modified_metadata.is_empty()
    }

    /// Total count of all mutations detected
    pub fn total_changes(&self) -> usize {
        self.added.len()
            + self.removed.len()
            + self.modified_content.len()
            + self.modified_metadata.len()
    }
}

/// Spooled offline event entry stored in local circular buffer
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpoolEvent {
    pub sequence_id: Option<i64>,
    pub event_id: String,
    pub timestamp_nano: i64,
    pub event_type: String,
    pub path: String,
    pub severity: u32,
    pub whodata_pid: Option<u32>,
    pub whodata_uid: Option<u32>,
    pub whodata_comm: Option<String>,
    pub whodata_exe: Option<String>,
    pub whodata_cmdline: Option<String>,
    pub whodata_cgroup: Option<String>,
    pub old_sha256: Option<String>,
    pub new_sha256: Option<String>,
    pub diff_snippet: Option<String>,
    pub hmac_signature: String,
    pub sent_to_manager: bool,
}

/// Local SQLite Database for baseline management and offline spooling
pub struct BaselineDb {
    conn: Connection,
}

impl BaselineDb {
    /// Opens or creates an SQLite baseline database at the given path
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let conn = Connection::open(path)?;
        let db = Self { conn };
        db.init_schema()?;
        Ok(db)
    }

    /// Creates an in-memory SQLite baseline database (primarily for testing and fast diffing)
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let db = Self { conn };
        db.init_schema()?;
        Ok(db)
    }

    /// Initializes tables and indexes in WAL mode
    pub fn init_schema(&self) -> Result<()> {
        // Configure WAL mode and foreign keys for durability and concurrent reads
        self.conn.pragma_update(None, "journal_mode", "WAL")?;
        self.conn.pragma_update(None, "synchronous", "NORMAL")?;
        self.conn.pragma_update(None, "foreign_keys", "ON")?;

        self.conn.execute_batch(
            r#"
            -- Active Baseline File Records
            CREATE TABLE IF NOT EXISTS baseline_entries (
                path TEXT PRIMARY KEY NOT NULL,
                sha256 TEXT NOT NULL,
                blake3 TEXT,
                file_size INTEGER NOT NULL,
                mode INTEGER NOT NULL,
                uid INTEGER NOT NULL,
                gid INTEGER NOT NULL,
                inode INTEGER NOT NULL,
                dev INTEGER NOT NULL,
                nlink INTEGER NOT NULL,
                mtime INTEGER NOT NULL,
                mtime_nsec INTEGER NOT NULL DEFAULT 0,
                ctime INTEGER NOT NULL,
                xattrs_hash TEXT,
                acl_hash TEXT,
                symlink_target TEXT,
                is_symlink INTEGER NOT NULL DEFAULT 0,
                is_dir INTEGER NOT NULL DEFAULT 0,
                manifest_version TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_baseline_inode_dev ON baseline_entries(inode, dev);
            CREATE INDEX IF NOT EXISTS idx_baseline_hash ON baseline_entries(sha256);

            -- Offline Event Spool (Circular Ring Queue for Disconnected Mode)
            CREATE TABLE IF NOT EXISTS event_spool (
                sequence_id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT UNIQUE NOT NULL,
                timestamp_nano INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                path TEXT NOT NULL,
                severity INTEGER NOT NULL,
                whodata_pid INTEGER,
                whodata_uid INTEGER,
                whodata_comm TEXT,
                whodata_exe TEXT,
                whodata_cmdline TEXT,
                whodata_cgroup TEXT,
                old_sha256 TEXT,
                new_sha256 TEXT,
                diff_snippet TEXT,
                hmac_signature TEXT NOT NULL,
                sent_to_manager INTEGER NOT NULL DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_spool_unsent ON event_spool(sent_to_manager, sequence_id);
            "#,
        )?;

        Ok(())
    }

    /// Inserts or replaces a single baseline entry
    pub fn insert_entry(&self, entry: &FileMetadata, manifest_version: &str) -> Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let path_str = entry.path.to_string_lossy().to_string();

        self.conn.execute(
            r#"
            INSERT OR REPLACE INTO baseline_entries (
                path, sha256, blake3, file_size, mode, uid, gid, inode, dev, nlink,
                mtime, mtime_nsec, ctime, xattrs_hash, acl_hash, symlink_target,
                is_symlink, is_dir, manifest_version, created_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)
            "#,
            params![
                path_str,
                entry.sha256,
                entry.blake3,
                entry.st_size as i64,
                entry.st_mode as i64,
                entry.st_uid as i64,
                entry.st_gid as i64,
                entry.st_ino as i64,
                entry.st_dev as i64,
                entry.st_nlink as i64,
                entry.st_mtime,
                entry.st_mtime_nsec,
                entry.st_ctime,
                entry.xattrs_hash,
                entry.acl_hash,
                entry.symlink_target,
                entry.is_symlink as i32,
                entry.is_dir as i32,
                manifest_version,
                now,
            ],
        )?;

        Ok(())
    }

    /// Bulk inserts an array of baseline entries inside a single ACID transaction
    pub fn insert_batch(&mut self, entries: &[FileMetadata], manifest_version: &str) -> Result<usize> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let tx = self.conn.transaction()?;
        {
            let mut stmt = tx.prepare_cached(
                r#"
                INSERT OR REPLACE INTO baseline_entries (
                    path, sha256, blake3, file_size, mode, uid, gid, inode, dev, nlink,
                    mtime, mtime_nsec, ctime, xattrs_hash, acl_hash, symlink_target,
                    is_symlink, is_dir, manifest_version, created_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)
                "#,
            )?;

            for entry in entries {
                let path_str = entry.path.to_string_lossy().to_string();
                stmt.execute(params![
                    path_str,
                    entry.sha256,
                    entry.blake3,
                    entry.st_size as i64,
                    entry.st_mode as i64,
                    entry.st_uid as i64,
                    entry.st_gid as i64,
                    entry.st_ino as i64,
                    entry.st_dev as i64,
                    entry.st_nlink as i64,
                    entry.st_mtime,
                    entry.st_mtime_nsec,
                    entry.st_ctime,
                    entry.xattrs_hash,
                    entry.acl_hash,
                    entry.symlink_target,
                    entry.is_symlink as i32,
                    entry.is_dir as i32,
                    manifest_version,
                    now,
                ])?;
            }
        }
        tx.commit()?;
        Ok(entries.len())
    }

    /// Retrieves an entry by path from baseline
    pub fn get_entry<P: AsRef<Path>>(&self, path: P) -> Result<Option<FileMetadata>> {
        let path_str = path.as_ref().to_string_lossy().to_string();
        let mut stmt = self.conn.prepare(
            r#"
            SELECT path, sha256, blake3, file_size, mode, uid, gid, inode, dev, nlink,
                   mtime, mtime_nsec, ctime, xattrs_hash, acl_hash, symlink_target, is_symlink, is_dir
            FROM baseline_entries WHERE path = ?1
            "#,
        )?;

        let mut rows = stmt.query(params![path_str])?;
        if let Some(row) = rows.next()? {
            let p_str: String = row.get(0)?;
            Ok(Some(FileMetadata {
                path: PathBuf::from(p_str),
                sha256: row.get(1)?,
                blake3: row.get(2)?,
                st_size: row.get::<_, i64>(3)? as u64,
                st_mode: row.get::<_, i64>(4)? as u32,
                st_uid: row.get::<_, i64>(5)? as u32,
                st_gid: row.get::<_, i64>(6)? as u32,
                st_ino: row.get::<_, i64>(7)? as u64,
                st_dev: row.get::<_, i64>(8)? as u64,
                st_nlink: row.get::<_, i64>(9)? as u64,
                st_mtime: row.get(10)?,
                st_mtime_nsec: row.get(11)?,
                st_ctime: row.get(12)?,
                st_btime: None,
                xattrs_hash: row.get(13)?,
                acl_hash: row.get(14)?,
                symlink_target: row.get(15)?,
                is_symlink: row.get::<_, i32>(16)? == 1,
                is_dir: row.get::<_, i32>(17)? == 1,
            }))
        } else {
            Ok(None)
        }
    }

    /// Returns the total number of registered baseline entries
    pub fn count_entries(&self) -> Result<usize> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM baseline_entries", [], |r| r.get(0))?;
        Ok(count as usize)
    }

    /// Retrieves all registered baseline entries
    pub fn get_all_entries(&self) -> Result<Vec<FileMetadata>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT path, sha256, blake3, file_size, mode, uid, gid, inode, dev, nlink,
                   mtime, mtime_nsec, ctime, xattrs_hash, acl_hash, symlink_target, is_symlink, is_dir
            FROM baseline_entries
            "#,
        )?;

        let rows = stmt.query_map([], |row| {
            let p_str: String = row.get(0)?;
            Ok(FileMetadata {
                path: PathBuf::from(p_str),
                sha256: row.get(1)?,
                blake3: row.get(2)?,
                st_size: row.get::<_, i64>(3)? as u64,
                st_mode: row.get::<_, i64>(4)? as u32,
                st_uid: row.get::<_, i64>(5)? as u32,
                st_gid: row.get::<_, i64>(6)? as u32,
                st_ino: row.get::<_, i64>(7)? as u64,
                st_dev: row.get::<_, i64>(8)? as u64,
                st_nlink: row.get::<_, i64>(9)? as u64,
                st_mtime: row.get(10)?,
                st_mtime_nsec: row.get(11)?,
                st_ctime: row.get(12)?,
                st_btime: None,
                xattrs_hash: row.get(13)?,
                acl_hash: row.get(14)?,
                symlink_target: row.get(15)?,
                is_symlink: row.get::<_, i32>(16)? == 1,
                is_dir: row.get::<_, i32>(17)? == 1,
            })
        })?;

        let mut results = Vec::new();
        for r in rows {
            results.push(r?);
        }
        Ok(results)
    }

    /// Diffs the current filesystem snapshot against the active baseline
    pub fn diff_filesystem(&self, current_snapshot: &[FileMetadata]) -> Result<BaselineDiff> {
        let baseline_entries = self.get_all_entries()?;
        let mut baseline_map: HashMap<PathBuf, FileMetadata> = HashMap::new();
        for b in baseline_entries {
            baseline_map.insert(b.path.clone(), b);
        }

        let mut diff = BaselineDiff::default();
        let mut observed_paths = HashMap::new();

        for current in current_snapshot {
            observed_paths.insert(current.path.clone(), ());

            match baseline_map.get(&current.path) {
                None => {
                    // Path exists on disk but not in baseline -> Added
                    diff.added.push(current.clone());
                }
                Some(baseline) => {
                    // Check for content divergence
                    if current.sha256 != baseline.sha256 {
                        diff.modified_content.push(ContentChange {
                            path: current.path.clone(),
                            old_sha256: baseline.sha256.clone(),
                            new_sha256: current.sha256.clone(),
                            old_size: baseline.st_size,
                            new_size: current.st_size,
                        });
                    } else if current.st_mode != baseline.st_mode
                        || current.st_uid != baseline.st_uid
                        || current.st_gid != baseline.st_gid
                    {
                        // Check for metadata divergence (permissions or ownership altered)
                        diff.modified_metadata.push(MetadataChange {
                            path: current.path.clone(),
                            old_mode: baseline.st_mode,
                            new_mode: current.st_mode,
                            old_uid: baseline.st_uid,
                            new_uid: current.st_uid,
                            old_gid: baseline.st_gid,
                            new_gid: current.st_gid,
                        });
                    }
                }
            }
        }

        // Check for removed files (in baseline, but not observed in current scan)
        for (base_path, base_meta) in baseline_map {
            if !observed_paths.contains_key(&base_path) {
                diff.removed.push(base_meta);
            }
        }

        Ok(diff)
    }

    /// Appends an event to the local offline spool
    pub fn append_spool_event(&self, event: &SpoolEvent) -> Result<i64> {
        self.conn.execute(
            r#"
            INSERT INTO event_spool (
                event_id, timestamp_nano, event_type, path, severity,
                whodata_pid, whodata_uid, whodata_comm, whodata_exe,
                whodata_cmdline, whodata_cgroup, old_sha256, new_sha256,
                diff_snippet, hmac_signature, sent_to_manager
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)
            "#,
            params![
                event.event_id,
                event.timestamp_nano,
                event.event_type,
                event.path,
                event.severity,
                event.whodata_pid,
                event.whodata_uid,
                event.whodata_comm,
                event.whodata_exe,
                event.whodata_cmdline,
                event.whodata_cgroup,
                event.old_sha256,
                event.new_sha256,
                event.diff_snippet,
                event.hmac_signature,
                event.sent_to_manager as i32,
            ],
        )?;

        Ok(self.conn.last_insert_rowid())
    }

    /// Returns unacknowledged spool events to transmit to the manager
    pub fn get_unsent_spool_events(&self, limit: usize) -> Result<Vec<SpoolEvent>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT sequence_id, event_id, timestamp_nano, event_type, path, severity,
                   whodata_pid, whodata_uid, whodata_comm, whodata_exe, whodata_cmdline,
                   whodata_cgroup, old_sha256, new_sha256, diff_snippet, hmac_signature, sent_to_manager
            FROM event_spool
            WHERE sent_to_manager = 0
            ORDER BY sequence_id ASC
            LIMIT ?1
            "#,
        )?;

        let rows = stmt.query_map(params![limit as i64], |row| {
            Ok(SpoolEvent {
                sequence_id: Some(row.get(0)?),
                event_id: row.get(1)?,
                timestamp_nano: row.get(2)?,
                event_type: row.get(3)?,
                path: row.get(4)?,
                severity: row.get(5)?,
                whodata_pid: row.get(6)?,
                whodata_uid: row.get(7)?,
                whodata_comm: row.get(8)?,
                whodata_exe: row.get(9)?,
                whodata_cmdline: row.get(10)?,
                whodata_cgroup: row.get(11)?,
                old_sha256: row.get(12)?,
                new_sha256: row.get(13)?,
                diff_snippet: row.get(14)?,
                hmac_signature: row.get(15)?,
                sent_to_manager: row.get::<_, i32>(16)? == 1,
            })
        })?;

        let mut events = Vec::new();
        for r in rows {
            events.push(r?);
        }
        Ok(events)
    }

    /// Marks a batch of spooled events as successfully acknowledged by the manager
    pub fn mark_spool_events_sent(&self, sequence_ids: &[i64]) -> Result<usize> {
        if sequence_ids.is_empty() {
            return Ok(0);
        }

        let mut count = 0;
        let mut stmt = self
            .conn
            .prepare("UPDATE event_spool SET sent_to_manager = 1 WHERE sequence_id = ?1")?;

        for id in sequence_ids {
            count += stmt.execute(params![id])?;
        }

        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_file(path: &str, sha256: &str, size: u64, mode: u32) -> FileMetadata {
        FileMetadata {
            path: PathBuf::from(path),
            st_dev: 1,
            st_ino: 100,
            st_mode: mode,
            st_nlink: 1,
            st_uid: 0,
            st_gid: 0,
            st_size: size,
            st_mtime: 1700000000,
            st_mtime_nsec: 0,
            st_ctime: 1700000000,
            st_btime: None,
            sha256: sha256.to_string(),
            blake3: None,
            xattrs_hash: None,
            acl_hash: None,
            symlink_target: None,
            is_symlink: false,
            is_dir: false,
        }
    }

    #[test]
    fn test_baseline_db_lifecycle_and_diffing() {
        let mut db = BaselineDb::open_in_memory().unwrap();

        // Initial gold master baseline
        let f1 = dummy_file("/bin/login", "aaaa1111", 50000, 0o755);
        let f2 = dummy_file("/etc/shadow", "bbbb2222", 1400, 0o640);
        let f3 = dummy_file("/etc/sudoers", "cccc3333", 2200, 0o440);

        db.insert_batch(&[f1, f2, f3], "v1.0-gold").unwrap();
        assert_eq!(db.count_entries().unwrap(), 3);

        // Scenario 1: Clean scan (identical snapshot)
        let snap1 = vec![
            dummy_file("/bin/login", "aaaa1111", 50000, 0o755),
            dummy_file("/etc/shadow", "bbbb2222", 1400, 0o640),
            dummy_file("/etc/sudoers", "cccc3333", 2200, 0o440),
        ];
        let diff1 = db.diff_filesystem(&snap1).unwrap();
        assert!(diff1.is_clean());

        // Scenario 2: Intrusion Detection
        // - /etc/shadow modified (content change)
        // - /bin/login permissions altered to 0o777 (metadata change)
        // - /etc/sudoers deleted (removed)
        // - /tmp/webshell.php added
        let snap2 = vec![
            dummy_file("/bin/login", "aaaa1111", 50000, 0o777), // Perm change
            dummy_file("/etc/shadow", "MODIFIED_HASH", 1450, 0o640), // Hash change
            dummy_file("/tmp/webshell.php", "evil9999", 500, 0o755), // Added
        ];

        let diff2 = db.diff_filesystem(&snap2).unwrap();
        assert!(!diff2.is_clean());
        assert_eq!(diff2.total_changes(), 4);

        assert_eq!(diff2.added.len(), 1);
        assert_eq!(diff2.added[0].path, PathBuf::from("/tmp/webshell.php"));

        assert_eq!(diff2.removed.len(), 1);
        assert_eq!(diff2.removed[0].path, PathBuf::from("/etc/sudoers"));

        assert_eq!(diff2.modified_content.len(), 1);
        assert_eq!(diff2.modified_content[0].path, PathBuf::from("/etc/shadow"));
        assert_eq!(diff2.modified_content[0].old_sha256, "bbbb2222");
        assert_eq!(diff2.modified_content[0].new_sha256, "MODIFIED_HASH");

        assert_eq!(diff2.modified_metadata.len(), 1);
        assert_eq!(diff2.modified_metadata[0].path, PathBuf::from("/bin/login"));
        assert_eq!(diff2.modified_metadata[0].old_mode, 0o755);
        assert_eq!(diff2.modified_metadata[0].new_mode, 0o777);
    }

    #[test]
    fn test_event_spool_buffering() {
        let db = BaselineDb::open_in_memory().unwrap();

        let event = SpoolEvent {
            sequence_id: None,
            event_id: "evt-001".to_string(),
            timestamp_nano: 1700000000000,
            event_type: "MODIFIED".to_string(),
            path: "/etc/shadow".to_string(),
            severity: 10,
            whodata_pid: Some(4892),
            whodata_uid: Some(0),
            whodata_comm: Some("nano".to_string()),
            whodata_exe: Some("/usr/bin/nano".to_string()),
            whodata_cmdline: Some("nano /etc/shadow".to_string()),
            whodata_cgroup: None,
            old_sha256: Some("oldhash".to_string()),
            new_sha256: Some("newhash".to_string()),
            diff_snippet: None,
            hmac_signature: "hmac123".to_string(),
            sent_to_manager: false,
        };

        let seq_id = db.append_spool_event(&event).unwrap();
        assert_eq!(seq_id, 1);

        let unsent = db.get_unsent_spool_events(10).unwrap();
        assert_eq!(unsent.len(), 1);
        assert_eq!(unsent[0].path, "/etc/shadow");
        assert_eq!(unsent[0].sequence_id, Some(1));

        // Mark as sent
        let updated = db.mark_spool_events_sent(&[1]).unwrap();
        assert_eq!(updated, 1);

        let unsent_after = db.get_unsent_spool_events(10).unwrap();
        assert_eq!(unsent_after.len(), 0);
    }
}
