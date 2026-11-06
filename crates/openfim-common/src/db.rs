use hmac::{Hmac, Mac};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use crate::error::Result;
use crate::metadata::FileMetadata;

type HmacSha256 = Hmac<Sha256>;

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

/// Audit verification report for the tamper-evident offline spool
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpoolAuditReport {
    pub total_events: usize,
    pub is_valid: bool,
    pub tampered_sequence_id: Option<i64>,
    pub error_message: Option<String>,
}

/// Domain separation tag, so a chain from one schema version can never be replayed
/// as a valid chain under another.
const HMAC_CHAIN_DOMAIN: &[u8] = b"openfim.event_spool.v2";

/// Absorbs one named field into the MAC with an explicit length prefix.
///
/// Length prefixing is what makes the authenticated field set unambiguous. With bare
/// concatenation, the fields `("ab", "c")` and `("a", "bc")` produce identical MAC
/// input, so an attacker can shift bytes across a field boundary and keep the
/// signature valid. The presence tag distinguishes an absent optional field from an
/// empty one.
fn mac_field(mac: &mut HmacSha256, label: &[u8], value: Option<&[u8]>) {
    mac.update(&(label.len() as u64).to_le_bytes());
    mac.update(label);
    match value {
        Some(v) => {
            mac.update(&[1u8]);
            mac.update(&(v.len() as u64).to_le_bytes());
            mac.update(v);
        }
        None => {
            mac.update(&[0u8]);
            mac.update(&0u64.to_le_bytes());
        }
    }
}

/// Computes the HMAC-SHA256 signature for an event, chained from its predecessor.
///
/// Every security-relevant field of the event is authenticated, not just a handful.
/// Leaving fields out of the MAC — severity, the who-data attribution, the previous
/// hash — lets an attacker who reaches the database rewrite exactly the forensic
/// detail that matters (downgrade the severity, repoint the acting process, erase
/// the pre-tamper hash) while the chain still verifies as intact.
pub fn compute_event_hmac_for(key: &[u8], prev_hmac: &str, event: &SpoolEvent) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC supports arbitrary key length");

    mac_field(&mut mac, b"domain", Some(HMAC_CHAIN_DOMAIN));
    mac_field(&mut mac, b"prev", Some(prev_hmac.as_bytes()));
    mac_field(&mut mac, b"event_id", Some(event.event_id.as_bytes()));
    mac_field(
        &mut mac,
        b"timestamp_nano",
        Some(&event.timestamp_nano.to_le_bytes()),
    );
    mac_field(&mut mac, b"event_type", Some(event.event_type.as_bytes()));
    mac_field(&mut mac, b"path", Some(event.path.as_bytes()));
    mac_field(&mut mac, b"severity", Some(&event.severity.to_le_bytes()));
    mac_field(
        &mut mac,
        b"whodata_pid",
        event
            .whodata_pid
            .map(|v| v.to_le_bytes())
            .as_ref()
            .map(|b| &b[..]),
    );
    mac_field(
        &mut mac,
        b"whodata_uid",
        event
            .whodata_uid
            .map(|v| v.to_le_bytes())
            .as_ref()
            .map(|b| &b[..]),
    );
    mac_field(
        &mut mac,
        b"whodata_comm",
        event.whodata_comm.as_deref().map(|s| s.as_bytes()),
    );
    mac_field(
        &mut mac,
        b"whodata_exe",
        event.whodata_exe.as_deref().map(|s| s.as_bytes()),
    );
    mac_field(
        &mut mac,
        b"whodata_cmdline",
        event.whodata_cmdline.as_deref().map(|s| s.as_bytes()),
    );
    mac_field(
        &mut mac,
        b"whodata_cgroup",
        event.whodata_cgroup.as_deref().map(|s| s.as_bytes()),
    );
    mac_field(
        &mut mac,
        b"old_sha256",
        event.old_sha256.as_deref().map(|s| s.as_bytes()),
    );
    mac_field(
        &mut mac,
        b"new_sha256",
        event.new_sha256.as_deref().map(|s| s.as_bytes()),
    );
    mac_field(
        &mut mac,
        b"diff_snippet",
        event.diff_snippet.as_deref().map(|s| s.as_bytes()),
    );

    hex::encode(mac.finalize().into_bytes())
}

/// Legacy five-field chaining helper.
///
/// Retained so existing callers keep compiling, but it authenticates only a subset of
/// each event. Use [`compute_event_hmac_for`] for anything that must be
/// tamper-evident.
#[deprecated(
    since = "0.1.0",
    note = "authenticates only 5 of the event's fields; use compute_event_hmac_for"
)]
pub fn compute_event_hmac(
    key: &[u8],
    prev_hmac: &str,
    event_id: &str,
    ts: i64,
    path: &str,
    event_type: &str,
    new_hash: Option<&str>,
) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC supports arbitrary key length");
    mac.update(prev_hmac.as_bytes());
    mac.update(event_id.as_bytes());
    mac.update(&ts.to_le_bytes());
    mac.update(path.as_bytes());
    mac.update(event_type.as_bytes());
    if let Some(h) = new_hash {
        mac.update(h.as_bytes());
    }
    hex::encode(mac.finalize().into_bytes())
}

/// The genesis value that seeds the chain before any event has been written.
pub const CHAIN_GENESIS_HMAC: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Canonicalizes/normalizes a path string for consistent database keying across OS path separators
pub fn normalize_path_str<P: AsRef<Path>>(p: P) -> String {
    let s = p.as_ref().to_string_lossy().replace('\\', "/");
    let trimmed = s.strip_prefix("//?/").unwrap_or(&s);
    let clean = trimmed.trim_start_matches("./");
    clean.trim_end_matches('/').to_string()
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

    /// Access underlying SQLite connection (e.g. for testing and introspection)
    pub fn connection(&self) -> &Connection {
        &self.conn
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

        // Wait for a contended write lock instead of failing instantly.
        //
        // The sensor daemon holds the database open continuously while the CLI is
        // expected to run `audit verify` and `baseline diff` against the same file.
        // With SQLite's default zero timeout, those concurrent commands fail outright
        // with SQLITE_BUSY ("database is locked") rather than waiting their turn.
        self.conn.busy_timeout(std::time::Duration::from_secs(10))?;

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

            -- Append-only chain anchor.
            --
            -- Without a persisted record of where the chain head should be, deleting
            -- the most recent N rows leaves a shorter but internally consistent chain
            -- that verifies as clean. An attacker who trips an alert would simply
            -- delete the tail. This table records the expected head so truncation is
            -- detectable, and it is updated in the same transaction as each append.
            CREATE TABLE IF NOT EXISTS chain_meta (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                last_sequence_id INTEGER NOT NULL,
                last_hmac TEXT NOT NULL,
                event_count INTEGER NOT NULL
            );
            "#,
        )?;

        Ok(())
    }

    /// Reads the persisted chain anchor, if one exists.
    fn read_chain_anchor(&self) -> Result<Option<(i64, String, i64)>> {
        let mut stmt = self.conn.prepare(
            "SELECT last_sequence_id, last_hmac, event_count FROM chain_meta WHERE id = 1",
        )?;
        let mut rows = stmt.query([])?;
        if let Some(row) = rows.next()? {
            Ok(Some((row.get(0)?, row.get(1)?, row.get(2)?)))
        } else {
            Ok(None)
        }
    }

    /// Inserts or replaces a single baseline entry
    pub fn insert_entry(&self, entry: &FileMetadata, manifest_version: &str) -> Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let path_str = normalize_path_str(&entry.path);

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
    pub fn insert_batch(
        &mut self,
        entries: &[FileMetadata],
        manifest_version: &str,
    ) -> Result<usize> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let mut inserted = 0usize;
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
                let path_str = normalize_path_str(&entry.path);
                inserted += stmt.execute(params![
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
        // Report rows actually written rather than the input length, so a caller can
        // tell a partially-applied batch from a fully-applied one.
        Ok(inserted)
    }

    /// Retrieves an entry by path from baseline with cross-platform separator normalization
    pub fn get_entry<P: AsRef<Path>>(&self, path: P) -> Result<Option<FileMetadata>> {
        let path_ref = path.as_ref();
        let norm_str = normalize_path_str(path_ref);
        let abs_str = if let Ok(cur) = std::env::current_dir() {
            if path_ref.is_relative() {
                normalize_path_str(cur.join(path_ref))
            } else {
                norm_str.clone()
            }
        } else {
            norm_str.clone()
        };
        let rel_str = if let Ok(cur) = std::env::current_dir() {
            if let Ok(rel) = path_ref.strip_prefix(&cur) {
                normalize_path_str(rel)
            } else {
                norm_str.clone()
            }
        } else {
            norm_str.clone()
        };

        let mut stmt = self.conn.prepare(
            r#"
            SELECT path, sha256, blake3, file_size, mode, uid, gid, inode, dev, nlink,
                   mtime, mtime_nsec, ctime, xattrs_hash, acl_hash, symlink_target, is_symlink, is_dir
            FROM baseline_entries WHERE path = ?1 OR path = ?2 OR path = ?3
            -- Deterministic preference: the caller's own spelling first, then the
            -- absolute form, then the working-directory-relative form. Without this
            -- the row returned for an ambiguous lookup depends on storage order.
            ORDER BY CASE path WHEN ?1 THEN 0 WHEN ?2 THEN 1 ELSE 2 END
            LIMIT 1
            "#,
        )?;

        let mut rows = stmt.query(params![norm_str, abs_str, rel_str])?;
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
        self.diff_filesystem_scoped(current_snapshot, None::<&Path>)
    }

    /// Diffs the current filesystem snapshot against the baseline, optionally scoping removed-file detection to a root prefix
    pub fn diff_filesystem_scoped<P: AsRef<Path>>(
        &self,
        current_snapshot: &[FileMetadata],
        scope: Option<P>,
    ) -> Result<BaselineDiff> {
        let baseline_entries = self.get_all_entries()?;
        let mut baseline_map: HashMap<String, FileMetadata> =
            HashMap::with_capacity(baseline_entries.len());
        for b in baseline_entries {
            baseline_map.insert(normalize_path_str(&b.path), b);
        }

        let mut diff = BaselineDiff::default();
        let mut observed_paths: HashSet<String> = HashSet::with_capacity(current_snapshot.len());

        for current in current_snapshot {
            let norm_current = normalize_path_str(&current.path);
            observed_paths.insert(norm_current.clone());

            match baseline_map.get(&norm_current) {
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

        let scope_norm = scope
            .as_ref()
            .map(|s| normalize_path_str(s).trim_end_matches('/').to_string());
        let scope_prefix = scope_norm.as_ref().map(|sc| format!("{}/", sc));

        // Check for removed files (in baseline, but not observed in current scan)
        for (base_key, base_meta) in baseline_map {
            if let (Some(sc), Some(prefix)) = (scope_norm.as_ref(), scope_prefix.as_ref()) {
                // Must be the scope root itself or sit beneath it.
                //
                // A bare `starts_with(scope)` test also matches sibling paths that
                // merely share a textual prefix: scoping a diff to `/etc` would drag
                // in `/etcetera/...` and report its files as deleted.
                let in_scope = &base_key == sc || base_key.starts_with(prefix);
                if !in_scope {
                    continue;
                }
            }
            if !observed_paths.contains(&base_key) {
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

    /// Retrieves the most recent HMAC signature from the event spool (or 64 zeros for genesis)
    pub fn get_last_spool_hmac(&self) -> Result<String> {
        let mut stmt = self
            .conn
            .prepare("SELECT hmac_signature FROM event_spool ORDER BY sequence_id DESC LIMIT 1")?;
        let mut rows = stmt.query([])?;
        if let Some(row) = rows.next()? {
            Ok(row.get(0)?)
        } else {
            Ok(CHAIN_GENESIS_HMAC.to_string())
        }
    }

    /// Cryptographically signs and appends an event to the local append-only HMAC chain.
    ///
    /// The event row and the chain anchor are written in one transaction, so the
    /// anchor can never disagree with the chain because of a crash mid-append.
    pub fn append_spool_event_chained(
        &self,
        event: &mut SpoolEvent,
        hmac_key: &[u8],
    ) -> Result<i64> {
        let tx = self.conn.unchecked_transaction()?;

        // Chain from the anchor when present; it is the authoritative head.
        let (prev_hmac, prev_count) = match self.read_chain_anchor()? {
            Some((_, last_hmac, count)) => (last_hmac, count),
            None => (
                self.get_last_spool_hmac()?,
                self.count_spool_events()? as i64,
            ),
        };

        event.hmac_signature = compute_event_hmac_for(hmac_key, &prev_hmac, event);
        let seq = self.append_spool_event(event)?;

        tx.execute(
            r#"
            INSERT INTO chain_meta (id, last_sequence_id, last_hmac, event_count)
            VALUES (1, ?1, ?2, ?3)
            ON CONFLICT(id) DO UPDATE SET
                last_sequence_id = excluded.last_sequence_id,
                last_hmac        = excluded.last_hmac,
                event_count      = excluded.event_count
            "#,
            params![seq, event.hmac_signature, prev_count + 1],
        )?;

        tx.commit()?;
        event.sequence_id = Some(seq);
        Ok(seq)
    }

    /// Total number of rows currently in the event spool.
    pub fn count_spool_events(&self) -> Result<usize> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM event_spool", [], |r| r.get(0))?;
        Ok(count as usize)
    }

    /// Verifies the entire offline event spool HMAC chain, sequence continuity, and
    /// agreement with the persisted chain anchor.
    ///
    /// Three distinct tampering modes are detected:
    ///
    /// 1. **Payload edits** — any authenticated field changed, so the recomputed MAC
    ///    no longer matches the stored one.
    /// 2. **Interior deletion** — a gap appears in the autoincrement sequence.
    /// 3. **Tail truncation** — the surviving rows still chain correctly, but the head
    ///    no longer matches the anchor recorded when the last event was appended.
    ///    Without check 3 an attacker simply deletes the rows that incriminate them.
    pub fn verify_spool_chain(&self, hmac_key: &[u8]) -> Result<SpoolAuditReport> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT sequence_id, event_id, timestamp_nano, event_type, path, severity,
                   whodata_pid, whodata_uid, whodata_comm, whodata_exe, whodata_cmdline,
                   whodata_cgroup, old_sha256, new_sha256, diff_snippet, hmac_signature,
                   sent_to_manager
            FROM event_spool ORDER BY sequence_id ASC
            "#,
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                SpoolEvent {
                    sequence_id: Some(row.get::<_, i64>(0)?),
                    event_id: row.get(1)?,
                    timestamp_nano: row.get(2)?,
                    event_type: row.get(3)?,
                    path: row.get(4)?,
                    severity: row.get::<_, i64>(5)? as u32,
                    whodata_pid: row.get::<_, Option<i64>>(6)?.map(|v| v as u32),
                    whodata_uid: row.get::<_, Option<i64>>(7)?.map(|v| v as u32),
                    whodata_comm: row.get(8)?,
                    whodata_exe: row.get(9)?,
                    whodata_cmdline: row.get(10)?,
                    whodata_cgroup: row.get(11)?,
                    old_sha256: row.get(12)?,
                    new_sha256: row.get(13)?,
                    diff_snippet: row.get(14)?,
                    hmac_signature: row.get(15)?,
                    sent_to_manager: row.get::<_, i64>(16)? == 1,
                },
            ))
        })?;

        let mut prev_hmac = CHAIN_GENESIS_HMAC.to_string();
        let mut count = 0usize;
        let mut last_seq = 0i64;

        for (position, r) in rows.enumerate() {
            let (seq, event) = r?;
            // Autoincrement sequence ids start at 1 and must be contiguous.
            let expected_seq = position as i64 + 1;

            if seq != expected_seq {
                return Ok(SpoolAuditReport {
                    total_events: count,
                    is_valid: false,
                    tampered_sequence_id: Some(seq),
                    error_message: Some(format!(
                        "Sequence gap detected: expected {}, found {}. \
                         Event(s) were deleted from the middle of the append-only log.",
                        expected_seq, seq
                    )),
                });
            }

            let expected_hmac = compute_event_hmac_for(hmac_key, &prev_hmac, &event);
            if expected_hmac != event.hmac_signature {
                return Ok(SpoolAuditReport {
                    total_events: count,
                    is_valid: false,
                    tampered_sequence_id: Some(seq),
                    error_message: Some(format!(
                        "Cryptographic HMAC mismatch at sequence {}. \
                         An authenticated field of this event was modified after it was recorded.",
                        seq
                    )),
                });
            }

            prev_hmac = event.hmac_signature.clone();
            last_seq = seq;
            count += 1;
        }

        // Truncation check against the persisted anchor.
        if let Some((anchor_seq, anchor_hmac, anchor_count)) = self.read_chain_anchor()? {
            if (count as i64) < anchor_count || last_seq < anchor_seq {
                return Ok(SpoolAuditReport {
                    total_events: count,
                    is_valid: false,
                    tampered_sequence_id: Some(last_seq.max(0)),
                    error_message: Some(format!(
                        "Chain truncation detected: the anchor records {} event(s) up to \
                         sequence {}, but only {} event(s) up to sequence {} remain. \
                         Event(s) were deleted from the end of the append-only log.",
                        anchor_count, anchor_seq, count, last_seq
                    )),
                });
            }
            if count as i64 == anchor_count && prev_hmac != anchor_hmac {
                return Ok(SpoolAuditReport {
                    total_events: count,
                    is_valid: false,
                    tampered_sequence_id: Some(last_seq.max(0)),
                    error_message: Some(
                        "Chain head mismatch: the final event's signature does not match the \
                         recorded anchor. The log was rewritten."
                            .to_string(),
                    ),
                });
            }
        } else if count > 0 {
            return Ok(SpoolAuditReport {
                total_events: count,
                is_valid: false,
                tampered_sequence_id: Some(1),
                error_message: Some(
                    "Chain anchor is missing while events are present. Either the anchor row \
                     was deleted, or these events predate anchored chaining."
                        .to_string(),
                ),
            });
        }

        Ok(SpoolAuditReport {
            total_events: count,
            is_valid: true,
            tampered_sequence_id: None,
            error_message: None,
        })
    }

    /// Retrieves spool events for a specific path (most recent first)
    pub fn get_events_for_path<P: AsRef<Path>>(
        &self,
        path: P,
        limit: usize,
    ) -> Result<Vec<SpoolEvent>> {
        let path_ref = path.as_ref();
        let norm_str = normalize_path_str(path_ref);
        let abs_str = if let Ok(cur) = std::env::current_dir() {
            if path_ref.is_relative() {
                normalize_path_str(cur.join(path_ref))
            } else {
                norm_str.clone()
            }
        } else {
            norm_str.clone()
        };
        let rel_str = if let Ok(cur) = std::env::current_dir() {
            if let Ok(rel) = path_ref.strip_prefix(&cur) {
                normalize_path_str(rel)
            } else {
                norm_str.clone()
            }
        } else {
            norm_str.clone()
        };

        let mut stmt = self.conn.prepare(
            r#"
            SELECT sequence_id, event_id, timestamp_nano, event_type, path, severity,
                   whodata_pid, whodata_uid, whodata_comm, whodata_exe, whodata_cmdline,
                   whodata_cgroup, old_sha256, new_sha256, diff_snippet, hmac_signature, sent_to_manager
            FROM event_spool
            WHERE path = ?1 OR path = ?2 OR path = ?3
            ORDER BY sequence_id DESC
            LIMIT ?4
            "#,
        )?;

        let rows = stmt.query_map(params![norm_str, abs_str, rel_str, limit as i64], |row| {
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

    /// Exports the baseline database as a portable JSON or .sha256 manifest
    pub fn export_manifest(&self, format: &str) -> Result<String> {
        let entries = self.get_all_entries()?;
        if format.eq_ignore_ascii_case("sha256") {
            let mut out = String::new();
            for e in entries {
                out.push_str(&format!("{}  {}\n", e.sha256, e.path.display()));
            }
            Ok(out)
        } else {
            #[derive(Serialize)]
            struct ManifestOutput {
                version: String,
                total_files: usize,
                files: Vec<FileMetadata>,
            }
            let manifest = ManifestOutput {
                version: "1.0".to_string(),
                total_files: entries.len(),
                files: entries,
            };
            Ok(serde_json::to_string_pretty(&manifest)?)
        }
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

    #[test]
    fn test_hmac_spool_chain_and_tamper_detection() {
        let db = BaselineDb::open_in_memory().unwrap();
        let key = b"super-secret-hmac-key";

        let mut ev1 = SpoolEvent {
            sequence_id: None,
            event_id: "evt-001".to_string(),
            timestamp_nano: 1700000000001,
            event_type: "FILE_CREATED".to_string(),
            path: "/etc/passwd".to_string(),
            severity: 8,
            whodata_pid: Some(100),
            whodata_uid: Some(0),
            whodata_comm: Some("useradd".to_string()),
            whodata_exe: Some("/usr/sbin/useradd".to_string()),
            whodata_cmdline: Some("useradd alice".to_string()),
            whodata_cgroup: None,
            old_sha256: None,
            new_sha256: Some("sha_passwd_v1".to_string()),
            diff_snippet: None,
            hmac_signature: String::new(),
            sent_to_manager: false,
        };

        let mut ev2 = SpoolEvent {
            sequence_id: None,
            event_id: "evt-002".to_string(),
            timestamp_nano: 1700000000002,
            event_type: "CONTENT_MUTATED".to_string(),
            path: "/etc/sudoers".to_string(),
            severity: 10,
            whodata_pid: Some(101),
            whodata_uid: Some(0),
            whodata_comm: Some("visudo".to_string()),
            whodata_exe: Some("/usr/sbin/visudo".to_string()),
            whodata_cmdline: Some("visudo".to_string()),
            whodata_cgroup: None,
            old_sha256: Some("sha_sudo_v1".to_string()),
            new_sha256: Some("sha_sudo_v2".to_string()),
            diff_snippet: None,
            hmac_signature: String::new(),
            sent_to_manager: false,
        };

        let seq1 = db.append_spool_event_chained(&mut ev1, key).unwrap();
        let seq2 = db.append_spool_event_chained(&mut ev2, key).unwrap();
        assert_eq!(seq1, 1);
        assert_eq!(seq2, 2);

        // Verify valid chain
        let audit = db.verify_spool_chain(key).unwrap();
        assert!(audit.is_valid);
        assert_eq!(audit.total_events, 2);
        assert!(audit.tampered_sequence_id.is_none());

        // Simulate adversary tampering with record 2 in the database
        db.conn
            .execute(
                "UPDATE event_spool SET path = '/etc/sudoers_fake' WHERE sequence_id = 2",
                [],
            )
            .unwrap();

        // Audit must now catch the tamper!
        let audit_tampered = db.verify_spool_chain(key).unwrap();
        assert!(!audit_tampered.is_valid);
        assert_eq!(audit_tampered.tampered_sequence_id, Some(2));
    }

    #[test]
    fn test_get_events_for_path_and_export_manifest() {
        let mut db = BaselineDb::open_in_memory().unwrap();
        let f1 = dummy_file("/app/config.json", "hash123", 1024, 0o644);
        db.insert_batch(&[f1], "v1").unwrap();

        let json_manifest = db.export_manifest("json").unwrap();
        assert!(json_manifest.contains("hash123"));
        assert!(json_manifest.contains("config.json"));

        let sha_manifest = db.export_manifest("sha256").unwrap();
        assert!(sha_manifest.contains("hash123"));

        let ev = SpoolEvent {
            sequence_id: None,
            event_id: "evt-999".to_string(),
            timestamp_nano: 1700000000005,
            event_type: "CONTENT_MUTATED".to_string(),
            path: "/app/config.json".to_string(),
            severity: 9,
            whodata_pid: Some(555),
            whodata_uid: Some(1000),
            whodata_comm: Some("vim".to_string()),
            whodata_exe: Some("/usr/bin/vim".to_string()),
            whodata_cmdline: Some("vim /app/config.json".to_string()),
            whodata_cgroup: None,
            old_sha256: Some("hash123".to_string()),
            new_sha256: Some("hash456".to_string()),
            diff_snippet: None,
            hmac_signature: "sig".to_string(),
            sent_to_manager: false,
        };
        db.append_spool_event(&ev).unwrap();

        let events = db.get_events_for_path("/app/config.json", 5).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "CONTENT_MUTATED");
        assert_eq!(events[0].whodata_comm.as_deref(), Some("vim"));
    }

    // ---------------- Tamper-evident chain ----------------

    const TEST_KEY: &[u8] = b"test-hmac-key";

    fn spool_event(id: &str, path: &str) -> SpoolEvent {
        SpoolEvent {
            sequence_id: None,
            event_id: id.to_string(),
            timestamp_nano: 1_700_000_000_000_000_000,
            event_type: "CONTENT_MUTATED".to_string(),
            path: path.to_string(),
            severity: 9,
            whodata_pid: Some(4242),
            whodata_uid: Some(0),
            whodata_comm: Some("attacker".to_string()),
            whodata_exe: Some("/usr/bin/attacker".to_string()),
            whodata_cmdline: Some("attacker --exfil".to_string()),
            whodata_cgroup: None,
            old_sha256: Some("a".repeat(64)),
            new_sha256: Some("b".repeat(64)),
            diff_snippet: None,
            hmac_signature: String::new(),
            sent_to_manager: false,
        }
    }

    fn seeded_db(n: usize) -> BaselineDb {
        let db = BaselineDb::open_in_memory().unwrap();
        for i in 0..n {
            let mut ev = spool_event(&format!("evt-{}", i), &format!("/etc/file{}", i));
            db.append_spool_event_chained(&mut ev, TEST_KEY).unwrap();
        }
        db
    }

    #[test]
    fn test_clean_chain_verifies() {
        let db = seeded_db(5);
        let report = db.verify_spool_chain(TEST_KEY).unwrap();
        assert!(report.is_valid, "{:?}", report.error_message);
        assert_eq!(report.total_events, 5);
    }

    #[test]
    fn test_wrong_key_fails_verification() {
        let db = seeded_db(3);
        let report = db.verify_spool_chain(b"not-the-right-key").unwrap();
        assert!(!report.is_valid);
    }

    #[test]
    fn test_interior_deletion_is_detected() {
        let db = seeded_db(5);
        db.connection()
            .execute("DELETE FROM event_spool WHERE sequence_id = 3", [])
            .unwrap();
        let report = db.verify_spool_chain(TEST_KEY).unwrap();
        assert!(!report.is_valid);
        assert!(report.error_message.unwrap().contains("Sequence gap"));
    }

    #[test]
    fn test_tail_truncation_is_detected() {
        // The critical case the anchor exists for. The surviving rows still chain
        // correctly to each other, so without an anchor this verifies as clean and an
        // attacker can erase the events that incriminate them.
        let db = seeded_db(5);
        db.connection()
            .execute("DELETE FROM event_spool WHERE sequence_id >= 4", [])
            .unwrap();

        let report = db.verify_spool_chain(TEST_KEY).unwrap();
        assert!(
            !report.is_valid,
            "deleting the tail of the log must not verify as a clean chain"
        );
        assert!(
            report.error_message.unwrap().contains("truncation"),
            "truncation should be reported as such"
        );
    }

    #[test]
    fn test_deleting_entire_log_is_detected() {
        let db = seeded_db(4);
        db.connection()
            .execute("DELETE FROM event_spool", [])
            .unwrap();
        let report = db.verify_spool_chain(TEST_KEY).unwrap();
        assert!(!report.is_valid, "wiping the log must be detectable");
    }

    #[test]
    fn test_anchor_removal_is_detected() {
        let db = seeded_db(3);
        db.connection()
            .execute("DELETE FROM chain_meta", [])
            .unwrap();
        let report = db.verify_spool_chain(TEST_KEY).unwrap();
        assert!(!report.is_valid);
    }

    #[test]
    fn test_empty_log_is_valid() {
        let db = BaselineDb::open_in_memory().unwrap();
        let report = db.verify_spool_chain(TEST_KEY).unwrap();
        assert!(report.is_valid);
        assert_eq!(report.total_events, 0);
    }

    /// Every authenticated field must be covered by the MAC. Rewriting any of them
    /// in place has to break verification; a field left out of the MAC is a field an
    /// attacker with database access can quietly rewrite.
    #[test]
    fn test_every_forensic_field_is_authenticated() {
        let mutations: &[(&str, &str)] = &[
            (
                "severity",
                "UPDATE event_spool SET severity = 1 WHERE sequence_id = 2",
            ),
            (
                "path",
                "UPDATE event_spool SET path = '/etc/decoy' WHERE sequence_id = 2",
            ),
            (
                "event_type",
                "UPDATE event_spool SET event_type = 'FILE_CREATED' WHERE sequence_id = 2",
            ),
            (
                "event_id",
                "UPDATE event_spool SET event_id = 'forged' WHERE sequence_id = 2",
            ),
            (
                "timestamp_nano",
                "UPDATE event_spool SET timestamp_nano = 1 WHERE sequence_id = 2",
            ),
            (
                "whodata_pid",
                "UPDATE event_spool SET whodata_pid = 1 WHERE sequence_id = 2",
            ),
            (
                "whodata_uid",
                "UPDATE event_spool SET whodata_uid = 1000 WHERE sequence_id = 2",
            ),
            (
                "whodata_comm",
                "UPDATE event_spool SET whodata_comm = 'bash' WHERE sequence_id = 2",
            ),
            (
                "whodata_exe",
                "UPDATE event_spool SET whodata_exe = '/bin/bash' WHERE sequence_id = 2",
            ),
            (
                "whodata_cmdline",
                "UPDATE event_spool SET whodata_cmdline = 'ls' WHERE sequence_id = 2",
            ),
            (
                "whodata_cgroup",
                "UPDATE event_spool SET whodata_cgroup = '/system.slice' WHERE sequence_id = 2",
            ),
            (
                "old_sha256",
                "UPDATE event_spool SET old_sha256 = NULL WHERE sequence_id = 2",
            ),
            (
                "new_sha256",
                "UPDATE event_spool SET new_sha256 = NULL WHERE sequence_id = 2",
            ),
            (
                "diff_snippet",
                "UPDATE event_spool SET diff_snippet = 'injected' WHERE sequence_id = 2",
            ),
        ];

        for (field, sql) in mutations {
            let db = seeded_db(4);
            assert!(
                db.verify_spool_chain(TEST_KEY).unwrap().is_valid,
                "baseline chain should start valid"
            );

            db.connection().execute(sql, []).unwrap();
            let report = db.verify_spool_chain(TEST_KEY).unwrap();

            assert!(
                !report.is_valid,
                "tampering with `{}` was not detected; the field is not covered by the \
                 event MAC and can be rewritten undetected",
                field
            );
            assert_eq!(
                report.tampered_sequence_id,
                Some(2),
                "wrong sequence id pinpointed for tampered field `{}`",
                field
            );
        }
    }

    #[test]
    fn test_length_prefixing_prevents_field_boundary_shifting() {
        // With bare concatenation, moving bytes across a field boundary keeps the MAC
        // input byte-identical. Length prefixes must make these two distinct.
        let mut a = spool_event("ab", "/etc/c");
        let mut b = spool_event("a", "/etc/bc");
        a.event_type = "X".to_string();
        b.event_type = "X".to_string();

        let mac_a = compute_event_hmac_for(TEST_KEY, CHAIN_GENESIS_HMAC, &a);
        let mac_b = compute_event_hmac_for(TEST_KEY, CHAIN_GENESIS_HMAC, &b);
        assert_ne!(
            mac_a, mac_b,
            "field boundaries are not unambiguously encoded in the MAC input"
        );
    }

    #[test]
    fn test_absent_and_empty_optional_fields_differ() {
        let mut absent = spool_event("e", "/etc/f");
        absent.whodata_comm = None;
        let mut empty = spool_event("e", "/etc/f");
        empty.whodata_comm = Some(String::new());

        assert_ne!(
            compute_event_hmac_for(TEST_KEY, CHAIN_GENESIS_HMAC, &absent),
            compute_event_hmac_for(TEST_KEY, CHAIN_GENESIS_HMAC, &empty),
            "an absent optional field must not hash the same as an empty one"
        );
    }

    #[test]
    fn test_reordering_two_events_breaks_the_chain() {
        let db = seeded_db(3);
        db.connection()
            .execute(
                "UPDATE event_spool SET path = CASE sequence_id
                     WHEN 1 THEN (SELECT path FROM event_spool WHERE sequence_id = 2)
                     WHEN 2 THEN (SELECT path FROM event_spool WHERE sequence_id = 1)
                     ELSE path END
                 WHERE sequence_id IN (1, 2)",
                [],
            )
            .unwrap();
        assert!(!db.verify_spool_chain(TEST_KEY).unwrap().is_valid);
    }

    #[test]
    fn test_append_returns_and_records_sequence_id() {
        let db = BaselineDb::open_in_memory().unwrap();
        let mut ev = spool_event("evt-1", "/etc/passwd");
        let seq = db.append_spool_event_chained(&mut ev, TEST_KEY).unwrap();
        assert_eq!(seq, 1);
        assert_eq!(
            ev.sequence_id,
            Some(1),
            "the event should carry its assigned sequence id"
        );
        assert_eq!(db.count_spool_events().unwrap(), 1);
    }

    // ---------------- Diff scoping ----------------

    #[test]
    fn test_diff_scope_does_not_match_sibling_prefix() {
        // Regression guard: a bare starts_with test let a scope of "/etc" pull in
        // "/etcetera/...", reporting unrelated files as deleted.
        let db = BaselineDb::open_in_memory().unwrap();
        db.insert_entry(&dummy_file("/etc/passwd", &"a".repeat(64), 10, 0o644), "v1")
            .unwrap();
        db.insert_entry(
            &dummy_file("/etcetera/other.conf", &"b".repeat(64), 10, 0o644),
            "v1",
        )
        .unwrap();

        // Nothing observed on disk, scoped to /etc.
        let diff = db
            .diff_filesystem_scoped(&[], Some(Path::new("/etc")))
            .unwrap();

        let removed: Vec<String> = diff
            .removed
            .iter()
            .map(|m| normalize_path_str(&m.path))
            .collect();

        assert!(removed.contains(&"/etc/passwd".to_string()));
        assert!(
            !removed.contains(&"/etcetera/other.conf".to_string()),
            "a sibling path sharing a textual prefix was pulled into the scope: {:?}",
            removed
        );
    }

    #[test]
    fn test_diff_scope_includes_the_root_itself() {
        let db = BaselineDb::open_in_memory().unwrap();
        db.insert_entry(&dummy_file("/etc", &"0".repeat(64), 0, 0o755), "v1")
            .unwrap();
        let diff = db
            .diff_filesystem_scoped(&[], Some(Path::new("/etc")))
            .unwrap();
        assert_eq!(diff.removed.len(), 1);
    }

    #[test]
    fn test_insert_batch_reports_rows_written() {
        let mut db = BaselineDb::open_in_memory().unwrap();
        let entries = vec![
            dummy_file("/a", &"1".repeat(64), 1, 0o644),
            dummy_file("/b", &"2".repeat(64), 2, 0o644),
            dummy_file("/c", &"3".repeat(64), 3, 0o644),
        ];
        assert_eq!(db.insert_batch(&entries, "v1").unwrap(), 3);
        assert_eq!(db.count_entries().unwrap(), 3);
    }
}
