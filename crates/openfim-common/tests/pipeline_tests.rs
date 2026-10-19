use std::io::Write;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;
use sha2::{Digest, Sha256};

use openfim_common::{
    BaselineDb, CrawlOptions, FileCrawler, FileMetadata, HashAlgorithm, OpenFimError,
    StreamHasher, TokenBucket, DEFAULT_BUFFER_SIZE,
};

#[test]
fn test_day1_workspace_and_algorithm_parsing() {
    assert_eq!("sha256".parse::<HashAlgorithm>().unwrap(), HashAlgorithm::Sha256);
    assert_eq!("blake3".parse::<HashAlgorithm>().unwrap(), HashAlgorithm::Blake3);
    assert_eq!("sha512".parse::<HashAlgorithm>().unwrap(), HashAlgorithm::Sha512);

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
    let result = hasher.hash_file(file.path()).expect("Streaming hash should succeed");

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
    file.write_all(b"Hello OpenFIM Defensive Architecture\n").unwrap();
    file.flush().unwrap();

    let mut hasher = StreamHasher::default_sha256();
    let meta = FileMetadata::extract(file.path(), &mut hasher).unwrap();

    assert_eq!(meta.st_size, b"Hello OpenFIM Defensive Architecture\n".len() as u64);
    assert!(!meta.is_dir);
    assert!(!meta.is_symlink);
    assert_eq!(meta.sha256, hex::encode(Sha256::digest(b"Hello OpenFIM Defensive Architecture\n")));

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
