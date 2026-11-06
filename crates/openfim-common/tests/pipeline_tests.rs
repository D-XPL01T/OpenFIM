use sha2::{Digest, Sha256};
use std::io::Write;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

use openfim_common::{
    ActiveResponseAction, BackupStore, BaselineDb, CrawlOptions, FileCrawler, FileMetadata,
    HashAlgorithm, OpenFimError, ProcessContext, SpoolEvent, StreamHasher, TokenBucket,
    DEFAULT_BUFFER_SIZE,
};

#[test]
fn test_day1_workspace_and_algorithm_parsing() {
    assert_eq!(
        "sha256".parse::<HashAlgorithm>().unwrap(),
        HashAlgorithm::Sha256
    );
    assert_eq!(
        "blake3".parse::<HashAlgorithm>().unwrap(),
        HashAlgorithm::Blake3
    );
    assert_eq!(
        "sha512".parse::<HashAlgorithm>().unwrap(),
        HashAlgorithm::Sha512
    );

    match "md5".parse::<HashAlgorithm>() {
        Err(OpenFimError::UnsupportedAlgorithm(msg)) => {
            assert!(msg.contains("deprecated"));
        }
        _ => panic!("Expected md5 to be rejected as deprecated"),
    }

    match "sha1".parse::<HashAlgorithm>() {
        Err(OpenFimError::UnsupportedAlgorithm(msg)) => {
            assert!(msg.contains("deprecated"));
        }
        _ => panic!("Expected sha1 to be rejected as deprecated"),
    }
}

#[test]
fn test_day2_bounded_streaming_hasher() {
    let mut file = NamedTempFile::new().unwrap();
    let chunk = [0x5au8; 1024];
    for _ in 0..500 {
        file.write_all(&chunk).unwrap();
    }
    file.flush().unwrap();

    let mut hasher = StreamHasher::default_sha256().with_buffer_size(DEFAULT_BUFFER_SIZE);
    let result = hasher
        .hash_file(file.path())
        .expect("Streaming hash should succeed");

    assert_eq!(result.algorithm, HashAlgorithm::Sha256);
    assert_eq!(result.bytes_read, 500 * 1024);

    let full_content = std::fs::read(file.path()).unwrap();
    let expected = hex::encode(Sha256::digest(&full_content));
    assert_eq!(result.hex_digest, expected);
}

#[test]
fn test_day2_rate_limiter_throttling() {
    let mut file = NamedTempFile::new().unwrap();
    let chunk = [0x42u8; 1024];
    for _ in 0..200 {
        file.write_all(&chunk).unwrap();
    }
    file.flush().unwrap();

    let limiter = TokenBucket::new(100 * 1024);
    let mut hasher = StreamHasher::new(HashAlgorithm::Sha256, limiter).with_buffer_size(16 * 1024);

    let start = Instant::now();
    let result = hasher.hash_file(file.path()).unwrap();
    let elapsed = start.elapsed();

    assert_eq!(result.bytes_read, 200 * 1024);
    assert!(
        elapsed >= Duration::from_millis(500),
        "Rate limiter should have delayed hashing. Elapsed: {:?}",
        elapsed
    );
}

#[test]
fn test_day2_metadata_extraction() {
    let mut file = NamedTempFile::new().unwrap();
    file.write_all(b"Hello OpenFIM Defensive Architecture\n")
        .unwrap();
    file.flush().unwrap();

    let mut hasher = StreamHasher::default_sha256();
    let meta = FileMetadata::extract(file.path(), &mut hasher).unwrap();

    assert_eq!(
        meta.st_size,
        b"Hello OpenFIM Defensive Architecture\n".len() as u64
    );
    assert!(!meta.is_dir);
    assert!(!meta.is_symlink);
    assert_eq!(
        meta.sha256,
        hex::encode(Sha256::digest(b"Hello OpenFIM Defensive Architecture\n"))
    );

    let json = serde_json::to_string(&meta).unwrap();
    assert!(json.contains("st_size"));
    assert!(json.contains("sha256"));
}

#[test]
fn test_day3_file_crawler_ignore_rules() {
    use tempfile::tempdir;

    let dir = tempdir().unwrap();
    let root = dir.path();

    std::fs::create_dir_all(root.join("subdir")).unwrap();
    std::fs::write(root.join("keep.txt"), b"KEEP").unwrap();
    std::fs::write(root.join("subdir/ignored.tmp"), b"IGNORE").unwrap();

    let options = CrawlOptions::default()
        .with_ignore_patterns(vec!["*.tmp"])
        .unwrap();

    let crawler = FileCrawler::new(options);
    let mut hasher = StreamHasher::default_sha256();
    let items = crawler.crawl(root, &mut hasher).unwrap();

    let names: Vec<String> = items
        .iter()
        .map(|m| m.path.file_name().unwrap().to_string_lossy().to_string())
        .collect();

    assert!(names.contains(&"keep.txt".to_string()));
    assert!(!names.contains(&"ignored.tmp".to_string()));
}

#[test]
fn test_day4_sqlite_baseline_diff_pipeline() {
    use tempfile::tempdir;

    let dir = tempdir().unwrap();
    let root = dir.path();

    // 1. Setup clean baseline files
    let file1_path = root.join("auth.conf");
    let file2_path = root.join("database.yml");
    let file3_path = root.join("delete_me.txt");

    std::fs::write(&file1_path, b"ALLOW_ROOT=0\n").unwrap();
    std::fs::write(&file2_path, b"HOST=127.0.0.1\n").unwrap();
    std::fs::write(&file3_path, b"TEMPORARY\n").unwrap();

    // 2. Crawl clean directory and store baseline in SQLite
    let crawler = FileCrawler::new(CrawlOptions::default());
    let mut hasher = StreamHasher::default_sha256();
    let initial_snapshot = crawler.crawl(root, &mut hasher).unwrap();

    let db_dir = tempdir().unwrap();
    let db_path = db_dir.path().join("openfim_baseline.db");
    let mut db = BaselineDb::open(&db_path).unwrap();
    let inserted = db.insert_batch(&initial_snapshot, "manifest-v1.0").unwrap();
    assert_eq!(inserted, initial_snapshot.len());

    let count = db.count_entries().unwrap();
    assert_eq!(count, initial_snapshot.len());

    // 3. Simulate changes:
    std::fs::write(&file1_path, b"ALLOW_ROOT=1\n").unwrap();
    let new_file_path = root.join("new_component.bin");
    std::fs::write(&new_file_path, b"NEW_COMPONENT_CONTENT\n").unwrap();
    std::fs::remove_file(&file3_path).unwrap();

    // 4. Re-crawl filesystem
    let new_snapshot = crawler.crawl(root, &mut hasher).unwrap();

    // 5. Diff against SQLite baseline
    let diff = db.diff_filesystem(&new_snapshot).unwrap();

    assert!(!diff.is_clean());
    assert_eq!(diff.modified_content.len(), 1);
    assert_eq!(diff.modified_content[0].path, file1_path);
    assert_eq!(diff.added.len(), 1);
    assert_eq!(diff.added[0].path, new_file_path);
    assert_eq!(diff.removed.len(), 1);
    assert_eq!(diff.removed[0].path, file3_path);
}

#[test]
fn test_day5_declarative_policy_and_signature_pipeline() {
    use openfim_common::{ActiveResponseAction, PolicySigner, PolicyVerifier, RuleMode};
    use tempfile::tempdir;

    let dir = tempdir().unwrap();
    let policy_path = dir.path().join("production.yaml");
    let sig_path = dir.path().join("production.yaml.sig");

    let sample_yaml = r#"
version: "1.0"
policy_id: "pol-prod-sec-audit"
name: "Audit Policy v1"
author: "SOC Architecture"
signature_algorithm: "ed25519"

globals:
  default_hash: "sha256"
  max_io_rate_mb_s: 30
  scan_nice_priority: 5
  realtime_fallback_sweep_interval: 1800

rules:
  - id: "RULE_ETC_PASSWD"
    description: "Monitors password file"
    paths:
      - "/etc/passwd"
    recursive: false
    mode: "realtime"
    checks:
      hash: true
      size: true
      permissions: true
      ownership: true
      timestamps: false
      attributes: true
      xattrs: true
    nodiff: true
    severity: 10
    whodata: true
    active_response:
      action: "restore_baseline"

  - id: "RULE_VAR_WWW"
    description: "Monitors web root"
    paths:
      - "/var/www/html"
    recursive: true
    mode: "realtime"
    checks:
      hash: true
      size: true
      permissions: true
      ownership: true
      timestamps: false
      attributes: false
      xattrs: false
    nodiff: false
    ignore:
      - "**/cache/**"
      - "**/logs/**"
    severity: 8
    whodata: true
    active_response:
      action: "quarantine"
"#;

    // 1. Write policy file to disk
    std::fs::write(&policy_path, sample_yaml).unwrap();

    // 2. Generate administrative keypair and sign policy file
    let (admin_signing_key, admin_verifying_key) = PolicySigner::generate_keypair();
    let signature = PolicySigner::sign_file(&policy_path, &admin_signing_key).unwrap();
    let sig_hex = PolicySigner::signature_to_hex(&signature);
    std::fs::write(&sig_path, sig_hex.as_bytes()).unwrap();

    // 3. Verify signed policy file with authorized admin public key
    let verified_policy =
        PolicyVerifier::verify_file(&policy_path, &sig_path, &admin_verifying_key).unwrap();

    assert_eq!(verified_policy.policy_id, "pol-prod-sec-audit");
    assert_eq!(verified_policy.globals.max_io_rate_mb_s, 30);
    assert_eq!(verified_policy.rules.len(), 2);
    assert_eq!(
        verified_policy.rules[0].active_response.action,
        ActiveResponseAction::RestoreBaseline
    );
    assert_eq!(verified_policy.rules[0].mode, RuleMode::Realtime);

    // 4. Test tamper detection: modify policy file on disk and ensure verification fails
    let tampered_yaml = format!("{}\n# Injected malicious comment\n", sample_yaml);
    std::fs::write(&policy_path, tampered_yaml).unwrap();

    let tamper_res = PolicyVerifier::verify_file(&policy_path, &sig_path, &admin_verifying_key);
    assert!(
        tamper_res.is_err(),
        "Tampered policy must be rejected by PolicyVerifier"
    );

    // Restore valid content
    std::fs::write(&policy_path, sample_yaml).unwrap();

    // 5. Test key mismatch: verify against an untrusted public key
    let (_untrusted_signing, untrusted_verifying) = PolicySigner::generate_keypair();
    let untrusted_res = PolicyVerifier::verify_file(&policy_path, &sig_path, &untrusted_verifying);
    assert!(
        untrusted_res.is_err(),
        "Policy signed by Admin must be rejected when verified against untrusted key"
    );

    // 6. Test rule path matching and ignore mechanics
    assert!(verified_policy.is_monitored(std::path::Path::new("/etc/passwd")));
    assert!(verified_policy.is_monitored(std::path::Path::new("/var/www/html/index.php")));
    assert!(!verified_policy.is_monitored(std::path::Path::new("/var/www/html/cache/session.dat")));
    assert!(!verified_policy.is_monitored(std::path::Path::new("/var/www/html/logs/access.log")));
    assert!(!verified_policy.is_monitored(std::path::Path::new("/tmp/unmonitored.txt")));
}

#[test]
fn test_day6_adversary_timestomp_detection() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("critical_config.cfg");
    std::fs::write(&target, b"ORIGINAL_PAYLOAD").unwrap();

    let mut db = BaselineDb::open_in_memory().unwrap();
    let mut hasher = StreamHasher::default_sha256();
    let crawler = FileCrawler::new(CrawlOptions::default());

    let initial_entries = crawler.crawl(dir.path(), &mut hasher).unwrap();
    db.insert_batch(&initial_entries, "v1.0").unwrap();

    let pristine_entry = db.get_entry(&target).unwrap().unwrap();
    let _original_mtime = pristine_entry.st_mtime;

    // Simulate Timestomp Attack: Adversary writes malicious payload but resets timestamp
    std::fs::write(&target, b"MALICIOUS_BACKDOOR_INJECTED").unwrap();
    // In our crawler, content hashing is authoritative regardless of timestamp
    let new_entries = crawler.crawl(dir.path(), &mut hasher).unwrap();
    let diff = db.diff_filesystem(&new_entries).unwrap();

    assert!(!diff.is_clean());
    assert_eq!(diff.modified_content.len(), 1);
    assert_eq!(diff.modified_content[0].path, target);
    assert_ne!(
        diff.modified_content[0].old_sha256,
        diff.modified_content[0].new_sha256
    );
}

#[test]
fn test_day7_adversary_tamper_evident_spool_hmac_audit() {
    let db = BaselineDb::open_in_memory().unwrap();
    let key = b"adversary-defense-key-999";

    for i in 1..=5 {
        let mut ev = SpoolEvent {
            sequence_id: None,
            event_id: format!("evt-{:03}", i),
            timestamp_nano: 1700000000000 + i,
            event_type: "MODIFIED".to_string(),
            path: format!("/bin/binary_{}", i),
            severity: 9,
            whodata_pid: Some(1000 + i as u32),
            whodata_uid: Some(0),
            whodata_comm: Some("attacker".to_string()),
            whodata_exe: Some("/tmp/sh".to_string()),
            whodata_cmdline: None,
            whodata_cgroup: None,
            old_sha256: Some(format!("old_{}", i)),
            new_sha256: Some(format!("new_{}", i)),
            diff_snippet: None,
            hmac_signature: String::new(),
            sent_to_manager: false,
        };
        db.append_spool_event_chained(&mut ev, key).unwrap();
    }

    // Baseline audit must pass
    let valid_audit = db.verify_spool_chain(key).unwrap();
    assert!(valid_audit.is_valid);
    assert_eq!(valid_audit.total_events, 5);

    // Attack Scenario A: Adversary deletes sequence 3 (Truncation / Deletion Evasion)
    let del_db = BaselineDb::open_in_memory().unwrap();
    // Replicate first 2, skip 3, replicate 4 & 5
    for i in [1, 2, 4, 5] {
        let mut ev = SpoolEvent {
            sequence_id: None,
            event_id: format!("evt-{:03}", i),
            timestamp_nano: 1700000000000 + i,
            event_type: "MODIFIED".to_string(),
            path: format!("/bin/binary_{}", i),
            severity: 9,
            whodata_pid: Some(1000 + i as u32),
            whodata_uid: Some(0),
            whodata_comm: Some("attacker".to_string()),
            whodata_exe: Some("/tmp/sh".to_string()),
            whodata_cmdline: None,
            whodata_cgroup: None,
            old_sha256: Some(format!("old_{}", i)),
            new_sha256: Some(format!("new_{}", i)),
            diff_snippet: None,
            hmac_signature: String::new(),
            sent_to_manager: false,
        };
        del_db.append_spool_event_chained(&mut ev, key).unwrap();
    }

    // Force sequence_id gap to simulate row deletion in raw sqlite
    del_db
        .connection()
        .execute(
            "UPDATE event_spool SET sequence_id = 99 WHERE sequence_id = 4",
            [],
        )
        .unwrap();
    let gap_audit = del_db.verify_spool_chain(key).unwrap();
    assert!(!gap_audit.is_valid);
    assert!(gap_audit.error_message.unwrap().contains("Sequence gap"));

    // Attack Scenario B: Adversary modifies path of record in place
    db.connection()
        .execute(
            "UPDATE event_spool SET path = '/bin/tampered' WHERE sequence_id = 4",
            [],
        )
        .unwrap();
    let tampered_audit = db.verify_spool_chain(key).unwrap();
    assert!(!tampered_audit.is_valid);
    assert_eq!(tampered_audit.tampered_sequence_id, Some(4));
}

#[test]
fn test_day8_active_response_quarantine_and_restore() {
    let dir = tempfile::tempdir().unwrap();
    let backup_dir = tempfile::tempdir().unwrap();

    let target_file = dir.path().join("compromised.sh");

    // Capture the pristine copy into the content-addressed store first, which is how an
    // operator populates it via `openfim-cli baseline backup`.
    std::fs::write(&target_file, b"PRISTINE SCRIPT").unwrap();
    let mut store = BackupStore::open_or_create(backup_dir.path().join("store")).unwrap();
    store.store_file(&target_file, "v1").unwrap();
    store.save().unwrap();

    // Adversary replaces it.
    std::fs::write(&target_file, b"MALICIOUS SCRIPT").unwrap();

    // 1. Test Quarantine
    let res = ActiveResponseAction::Quarantine
        .execute(&target_file, None)
        .unwrap();
    assert!(res.was_applied(), "{}", res.message());
    assert!(res.message().contains("quarantined"));
    assert!(!target_file.exists()); // Original compromised file removed

    let q_dir = dir.path().join(".quarantine");
    assert!(q_dir.exists());

    // 2. Test Restore Baseline
    let res_restore = ActiveResponseAction::RestoreBaseline
        .execute(&target_file, Some(&store))
        .unwrap();
    assert!(res_restore.was_applied(), "{}", res_restore.message());
    assert!(res_restore.message().contains("restored"));
    assert!(target_file.exists());
    let restored_content = std::fs::read(&target_file).unwrap();
    assert_eq!(restored_content, b"PRISTINE SCRIPT");

    // 3. A restore with no pristine copy must decline rather than quarantine the
    //    live file, which would destroy the very data it was asked to protect.
    let unbacked = dir.path().join("no_backup_here.conf");
    std::fs::write(&unbacked, b"LIVE DATA").unwrap();
    let declined = ActiveResponseAction::RestoreBaseline
        .execute(&unbacked, Some(&store))
        .unwrap();
    assert!(!declined.was_applied());
    assert!(
        unbacked.exists(),
        "a failed restore must not remove the live file"
    );
    assert_eq!(std::fs::read(&unbacked).unwrap(), b"LIVE DATA");
}

/// Red-team scenario: two monitored files share a filename in different directories.
///
/// A flat `backup_dir.join(file_name)` store maps both to one backup, so restoring
/// either writes the other's contents over a live file. That is silent data destruction
/// performed by the defensive control itself.
#[test]
fn test_adversary_cannot_exploit_backup_filename_collision() {
    let work = tempfile::tempdir().unwrap();

    let nginx_dir = work.path().join("etc/nginx/conf.d");
    let app_dir = work.path().join("opt/myapp/config");
    std::fs::create_dir_all(&nginx_dir).unwrap();
    std::fs::create_dir_all(&app_dir).unwrap();

    let nginx_conf = nginx_dir.join("app.conf");
    let app_conf = app_dir.join("app.conf");
    std::fs::write(&nginx_conf, b"listen 443 ssl;").unwrap();
    std::fs::write(&app_conf, b"debug = false").unwrap();

    let mut store = BackupStore::open_or_create(work.path().join("store")).unwrap();
    store.store_file(&nginx_conf, "v1").unwrap();
    store.store_file(&app_conf, "v1").unwrap();
    store.save().unwrap();

    // Adversary tampers with only one of them.
    std::fs::write(&app_conf, b"debug = true ; backdoor").unwrap();

    let outcome = ActiveResponseAction::RestoreBaseline
        .execute(&app_conf, Some(&store))
        .unwrap();
    assert!(outcome.was_applied(), "{}", outcome.message());

    assert_eq!(
        std::fs::read(&app_conf).unwrap(),
        b"debug = false",
        "the tampered file was restored from the wrong backup"
    );
    assert_eq!(
        std::fs::read(&nginx_conf).unwrap(),
        b"listen 443 ssl;",
        "an untouched file was overwritten by an unrelated restore"
    );
}

/// Red-team scenario: the adversary changes a monitored file while the sensor is not
/// watching — during downtime, a restart, or a window the kernel dropped.
///
/// Real-time watching alone cannot see this. Without reconciliation the miss is
/// permanent and silent: the file stays compromised, the baseline still holds the old
/// digest, and nothing records that a window went unobserved.
#[test]
fn test_change_made_while_unwatched_is_recovered_by_sweep() {
    use openfim_common::{reconcile, CompiledPolicy, Policy};

    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("production.conf");
    std::fs::write(&target, b"approved configuration").unwrap();

    // Baseline while clean.
    let mut db = BaselineDb::open_in_memory().unwrap();
    let crawler = FileCrawler::new(CrawlOptions::default());
    let mut hasher = StreamHasher::default_sha256();
    let snapshot = crawler.crawl(dir.path(), &mut hasher).unwrap();
    db.insert_batch(&snapshot, "v1").unwrap();

    let policy_yaml = format!(
        r#"
version: "1.0"
policy_id: "sweep-recovery"
name: "Sweep Recovery"
author: "test"
rules:
  - id: "PROD"
    description: "production config"
    paths:
      - "{}"
    recursive: true
    severity: 10
    checks:
      hash: true
      size: true
      permissions: false
      ownership: false
      timestamps: false
      attributes: false
      xattrs: false
"#,
        dir.path().to_string_lossy().replace('\\', "/")
    );
    let compiled = CompiledPolicy::new(Policy::from_yaml_str(&policy_yaml).unwrap());

    // The adversary acts with nothing watching at all.
    std::fs::write(&target, b"backdoored configuration").unwrap();
    let deleted = dir.path().join("deleted_by_attacker.conf");
    std::fs::write(&deleted, b"x").unwrap();

    // Re-baseline so the deletion is detectable, then remove the file.
    let snapshot2 = crawler.crawl(dir.path(), &mut hasher).unwrap();
    db.insert_batch(&snapshot2, "v2").unwrap();
    std::fs::write(&target, b"backdoored configuration again").unwrap();
    std::fs::remove_file(&deleted).unwrap();
    std::fs::write(dir.path().join("dropped_payload.sh"), b"#!/bin/sh\n").unwrap();

    let roots = compiled.policy().get_monitored_roots();
    let outcome = reconcile(&db, &compiled, &roots, &mut hasher).unwrap();

    assert_eq!(
        outcome.findings.len(),
        1,
        "the content change made while unwatched was not recovered: {}",
        outcome.summary()
    );
    assert!(outcome.findings[0]
        .changes
        .event_types()
        .contains(&"CONTENT_MUTATED"));

    assert_eq!(
        outcome.missing.len(),
        1,
        "the deletion made while unwatched was not recovered: {}",
        outcome.summary()
    );

    assert_eq!(
        outcome.unbaselined.len(),
        1,
        "the file dropped while unwatched was not recovered: {}",
        outcome.summary()
    );
}

/// A legacy flat backup directory must be refused outright, not silently treated as
/// empty or, worse, used as-is.
#[test]
fn test_legacy_flat_backup_directory_is_refused() {
    let work = tempfile::tempdir().unwrap();
    let legacy = work.path().join("backups");
    std::fs::create_dir_all(&legacy).unwrap();
    std::fs::write(legacy.join("app.conf"), b"loose backup file").unwrap();

    let err = BackupStore::open_or_create(&legacy).expect_err("legacy layout must be refused");
    assert!(err.to_string().contains("legacy flat backup directory"));
}

#[test]
fn test_day9_process_who_data_resolution() {
    let ctx = ProcessContext::current();
    assert!(ctx.pid > 0);
    assert!(ctx.cmdline.is_some() || ctx.exe.is_some() || ctx.comm.is_some());

    // The sensor must never present its own identity as the actor behind a change.
    assert!(
        !ctx.is_attributed,
        "a self-resolved process context must not be flagged as event attribution"
    );
    assert!(!ProcessContext::for_observed_event().is_attributed);
}

/// Red-team scenario: the adversary trips an alert, then deletes the tail of the
/// audit log to erase the evidence.
///
/// This runs against a real on-disk WAL database, the same configuration the shipped
/// binaries use, rather than an in-memory one.
#[test]
fn test_adversary_cannot_erase_evidence_by_truncating_the_log() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("openfim.db");
    let key = b"integration-test-key";

    {
        let db = BaselineDb::open(&db_path).unwrap();
        for i in 0..6 {
            let mut ev = SpoolEvent {
                sequence_id: None,
                event_id: format!("evt-{}", i),
                timestamp_nano: 1_700_000_000_000_000_000 + i as i64,
                event_type: "CONTENT_MUTATED".to_string(),
                path: format!("/etc/secret{}", i),
                severity: 10,
                whodata_pid: None,
                whodata_uid: None,
                whodata_comm: None,
                whodata_exe: None,
                whodata_cmdline: None,
                whodata_cgroup: None,
                old_sha256: Some("a".repeat(64)),
                new_sha256: Some("b".repeat(64)),
                diff_snippet: None,
                hmac_signature: String::new(),
                sent_to_manager: false,
            };
            db.append_spool_event_chained(&mut ev, key).unwrap();
        }

        let clean = db.verify_spool_chain(key).unwrap();
        assert!(clean.is_valid, "{:?}", clean.error_message);
        assert_eq!(clean.total_events, 6);
    }

    // Adversary reopens the spool and removes the incriminating tail.
    {
        let db = BaselineDb::open(&db_path).unwrap();
        db.connection()
            .execute("DELETE FROM event_spool WHERE sequence_id >= 5", [])
            .unwrap();
    }

    // A fresh process (as an auditor would run) must still catch it.
    {
        let db = BaselineDb::open(&db_path).unwrap();
        let report = db.verify_spool_chain(key).unwrap();
        assert!(
            !report.is_valid,
            "tail truncation of the audit log was not detected; an attacker could \
             delete the events that incriminate them and still pass the audit"
        );
        let msg = report.error_message.unwrap();
        assert!(
            msg.contains("truncation"),
            "unexpected failure reason: {}",
            msg
        );
    }
}

/// The sensor daemon and the CLI must be able to touch the same database
/// concurrently; the default zero busy-timeout made that fail with
/// "database is locked" during the documented demo workflow.
#[test]
fn test_concurrent_readers_and_writer_do_not_deadlock() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("concurrent.db");
    let key = b"concurrent-key";

    let writer_db = BaselineDb::open(&db_path).unwrap();
    let reader_db = BaselineDb::open(&db_path).unwrap();

    for i in 0..20 {
        let mut ev = SpoolEvent {
            sequence_id: None,
            event_id: format!("evt-{}", i),
            timestamp_nano: i as i64,
            event_type: "FILE_CREATED".to_string(),
            path: format!("/tmp/f{}", i),
            severity: 5,
            whodata_pid: None,
            whodata_uid: None,
            whodata_comm: None,
            whodata_exe: None,
            whodata_cmdline: None,
            whodata_cgroup: None,
            old_sha256: None,
            new_sha256: Some("c".repeat(64)),
            diff_snippet: None,
            hmac_signature: String::new(),
            sent_to_manager: false,
        };
        writer_db.append_spool_event_chained(&mut ev, key).unwrap();

        // Interleave a read from the second connection, as `audit verify` would.
        let report = reader_db.verify_spool_chain(key).unwrap();
        assert!(report.is_valid, "{:?}", report.error_message);
    }

    assert_eq!(reader_db.count_spool_events().unwrap(), 20);
}
