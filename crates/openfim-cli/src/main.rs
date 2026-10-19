use std::path::PathBuf;
use clap::{Parser, Subcommand};
use openfim_common::{FileMetadata, HashAlgorithm, StreamHasher, TokenBucket};

#[derive(Parser, Debug)]
#[command(
    name = "openfim-cli",
    about = "OpenFIM Command-Line Administrative Tool",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Calculate cryptographic hash of a file with streaming and TOCTOU protection
    Hash {
        /// Target file to hash
        #[arg(value_name = "FILE")]
        path: PathBuf,

        /// Hashing algorithm: sha256 | blake3 | sha512
        #[arg(short, long, default_value = "sha256")]
        algorithm: String,

        /// I/O Rate limit in MB/s (0 = unlimited)
        #[arg(long, default_value_t = 0)]
        throttle_mb_s: u64,
    },

    /// Extract full 64-byte metadata and cryptographic hash tuple
    Inspect {
        /// Target file or directory
        #[arg(value_name = "PATH")]
        path: PathBuf,
    },

    /// Recursively crawl a directory tree, extracting metadata and computing hashes
    Crawl {
        /// Target directory root to crawl
        #[arg(value_name = "DIR")]
        path: PathBuf,

        /// Maximum recursion depth
        #[arg(long, default_value_t = 64)]
        max_depth: usize,

        /// Ignore glob patterns (can be repeated, e.g. -i "*.tmp" -i "**/.git/**")
        #[arg(short, long)]
        ignore: Vec<String>,

        /// I/O rate limit in MB/s (0 = unlimited)
        #[arg(long, default_value_t = 0)]
        throttle_mb_s: u64,
    },

    /// Manage local SQLite baseline database and perform filesystem diffs
    Baseline {
        #[command(subcommand)]
        action: BaselineAction,
    },
}

#[derive(Subcommand, Debug)]
pub enum BaselineAction {
    /// Initialize an empty baseline SQLite database
    Init {
        /// Target SQLite database path
        #[arg(long)]
        db: PathBuf,
    },

    /// Create or update baseline snapshot from directory crawl
    Snapshot {
        /// Target directory root to crawl
        #[arg(short, long)]
        dir: PathBuf,

        /// Path to SQLite database
        #[arg(long)]
        db: PathBuf,

        /// Baseline manifest version string
        #[arg(short, long, default_value = "v1.0")]
        version: String,

        /// Ignore glob patterns (can be repeated, e.g. -i "*.tmp")
        #[arg(short, long)]
        ignore: Vec<String>,
    },

    /// Diff current filesystem state against active baseline database
    Diff {
        /// Target directory root to diff
        #[arg(short, long)]
        dir: PathBuf,

        /// Path to SQLite database
        #[arg(long)]
        db: PathBuf,

        /// Ignore glob patterns
        #[arg(short, long)]
        ignore: Vec<String>,
    },

    /// Display summary status of baseline database
    Status {
        /// Path to SQLite database
        #[arg(long)]
        db: PathBuf,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Hash {
            path,
            algorithm,
            throttle_mb_s,
        } => {
            let algo = algorithm.parse::<HashAlgorithm>()?;
            let rate_bytes = throttle_mb_s * 1024 * 1024;
            let mut hasher = StreamHasher::new(algo, TokenBucket::new(rate_bytes));

            let result = hasher.hash_file(&path)?;
            println!("Algorithm:   {:?}", result.algorithm);
            println!("Hex Digest:  {}", result.hex_digest);
            println!("Bytes Read:  {} bytes", result.bytes_read);
        }
        Commands::Inspect { path } => {
            let mut hasher = StreamHasher::default_sha256();
            let meta = FileMetadata::extract(&path, &mut hasher)?;
            println!("{}", serde_json::to_string_pretty(&meta)?);
        }
        Commands::Crawl {
            path,
            max_depth,
            ignore,
            throttle_mb_s,
        } => {
            use openfim_common::{CrawlOptions, FileCrawler};
            let rate_bytes = throttle_mb_s * 1024 * 1024;
            let mut hasher = StreamHasher::new(HashAlgorithm::Sha256, TokenBucket::new(rate_bytes));

            let mut options = CrawlOptions::default();
            options.max_depth = max_depth;
            options = options.with_ignore_patterns(ignore)?;

            let crawler = FileCrawler::new(options);
            println!("[*] Starting crawl on: {}", path.display());
            let items = crawler.crawl(&path, &mut hasher)?;
            println!("[*] Crawl complete. Indexed {} items:", items.len());
            for item in items {
                let type_str = if item.is_dir { "DIR " } else if item.is_symlink { "LINK" } else { "FILE" };
                println!("  [{}] {} ({} bytes, sha256: {})", type_str, item.path.display(), item.st_size, &item.sha256[..12]);
            }
        }

        Commands::Baseline { action } => {
            use openfim_common::{BaselineDb, CrawlOptions, FileCrawler};

            match action {
                BaselineAction::Init { db } => {
                    let _db = BaselineDb::open(&db)?;
                    println!("[+] Initialized SQLite baseline database at: {}", db.display());
                }
                BaselineAction::Snapshot {
                    dir,
                    db,
                    version,
                    ignore,
                } => {
                    let mut baseline_db = BaselineDb::open(&db)?;
                    let mut options = CrawlOptions::default();
                    options = options.with_ignore_patterns(ignore)?;

                    let crawler = FileCrawler::new(options);
                    let mut hasher = StreamHasher::default_sha256();

                    println!("[*] Crawling target directory: {}", dir.display());
                    let snapshot = crawler.crawl(&dir, &mut hasher)?;

                    println!("[*] Ingesting {} records into baseline database...", snapshot.len());
                    let inserted = baseline_db.insert_batch(&snapshot, &version)?;
                    println!(
                        "[+] Successfully recorded {} baseline entries under version '{}'. Total in DB: {}",
                        inserted,
                        version,
                        baseline_db.count_entries()?
                    );
                }
                BaselineAction::Diff { dir, db, ignore } => {
                    let baseline_db = BaselineDb::open(&db)?;
                    let mut options = CrawlOptions::default();
                    options = options.with_ignore_patterns(ignore)?;

                    let crawler = FileCrawler::new(options);
                    let mut hasher = StreamHasher::default_sha256();

                    println!("[*] Crawling filesystem for live verification: {}", dir.display());
                    let current_snapshot = crawler.crawl(&dir, &mut hasher)?;

                    println!("[*] Diffing against baseline database: {}", db.display());
                    let diff = baseline_db.diff_filesystem(&current_snapshot)?;

                    if diff.is_clean() {
                        println!("\n[✓] INTEGRITY VERIFIED: 0 changes detected. System matches active baseline perfectly.");
                    } else {
                        println!("\n[!] INTEGRITY VIOLATION DETECTED! Total Changes: {}", diff.total_changes());

                        if !diff.modified_content.is_empty() {
                            println!("\n--- [MODIFIED CONTENT (HASH DIVERGENCE)] ({} files) ---", diff.modified_content.len());
                            for c in &diff.modified_content {
                                println!("  * {}: expected {} -> found {}", c.path.display(), &c.old_sha256[..12], &c.new_sha256[..12]);
                            }
                        }

                        if !diff.added.is_empty() {
                            println!("\n--- [UNAUTHORIZED NEW FILES (ADDED)] ({} files) ---", diff.added.len());
                            for a in &diff.added {
                                println!("  * {} ({} bytes, sha256: {})", a.path.display(), a.st_size, &a.sha256[..12]);
                            }
                        }

                        if !diff.removed.is_empty() {
                            println!("\n--- [DELETED FILES (REMOVED)] ({} files) ---", diff.removed.len());
                            for r in &diff.removed {
                                println!("  * {} (last known sha256: {})", r.path.display(), &r.sha256[..12]);
                            }
                        }

                        if !diff.modified_metadata.is_empty() {
                            println!("\n--- [MODIFIED PERMISSIONS / ATTRIBUTES] ({} files) ---", diff.modified_metadata.len());
                            for m in &diff.modified_metadata {
                                println!("  * {}: mode {:o} -> {:o}, uid {} -> {}", m.path.display(), m.old_mode, m.new_mode, m.old_uid, m.new_uid);
                            }
                        }
                    }
                }
                BaselineAction::Status { db } => {
                    let baseline_db = BaselineDb::open(&db)?;
                    let count = baseline_db.count_entries()?;
                    println!("Database:       {}", db.display());
                    println!("Registered:     {} baseline files", count);
                }
            }
        }
    }

    Ok(())
}
