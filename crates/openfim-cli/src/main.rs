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

    /// Parse, sign, verify, and test declarative YAML policies
    Policy {
        #[command(subcommand)]
        action: PolicyAction,
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

#[derive(Subcommand, Debug)]
pub enum PolicyAction {
    /// Validate YAML syntax and optionally verify Ed25519 signature
    Check {
        /// Target policy YAML file
        #[arg(short, long)]
        policy: PathBuf,

        /// Optional admin Ed25519 public key in hex
        #[arg(long)]
        pubkey: Option<String>,

        /// Optional detached signature file (.sig)
        #[arg(long)]
        sig: Option<PathBuf>,
    },

    /// Generate a fresh Ed25519 keypair for policy administration
    Keygen {
        /// Optional directory to save 'openfim_admin.pub' and 'openfim_admin.key'
        #[arg(short, long)]
        out_dir: Option<PathBuf>,
    },

    /// Cryptographically sign a policy YAML file with an Ed25519 private key
    Sign {
        /// Target policy YAML file
        #[arg(short, long)]
        policy: PathBuf,

        /// Ed25519 private key seed (64-character hex or path to key file)
        #[arg(short = 'k', long)]
        privkey: String,

        /// Output path for signature file (defaults to <policy>.sig)
        #[arg(short, long)]
        out: Option<PathBuf>,
    },

    /// Test a specific file path against policy rules to inspect matching and severity
    TestPath {
        /// Target policy YAML file
        #[arg(short, long)]
        policy: PathBuf,

        /// File path to test against policy rules
        #[arg(value_name = "PATH")]
        path: PathBuf,
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

        Commands::Policy { action } => {
            use openfim_common::{Policy, PolicySigner, PolicyVerifier};

            match action {
                PolicyAction::Check { policy, pubkey, sig } => {
                    println!("[*] Reading policy manifest: {}", policy.display());

                    let loaded_policy = if let Some(pk_str) = pubkey {
                        let verifying_key = PolicySigner::pubkey_from_hex(&pk_str)?;
                        let pol = if let Some(s) = sig {
                            PolicyVerifier::verify_file(&policy, &s, &verifying_key)?
                        } else {
                            PolicyVerifier::verify_file_auto(&policy, &verifying_key)?
                        };
                        println!("[✓] Ed25519 Cryptographic Signature: VALID & AUTHENTIC");
                        pol
                    } else {
                        println!("[i] No public key provided. Skipping Ed25519 signature check.");
                        Policy::from_yaml_file(&policy)?
                    };

                    println!("\n================ POLICY METADATA ================");
                    println!("Policy ID:           {}", loaded_policy.policy_id);
                    println!("Name:                {}", loaded_policy.name);
                    println!("Author:              {}", loaded_policy.author);
                    println!("Signature Algorithm: {}", loaded_policy.signature_algorithm);
                    println!("Default Hashing:     {}", loaded_policy.globals.default_hash);
                    println!("Max I/O Scan Rate:   {} MB/s", loaded_policy.globals.max_io_rate_mb_s);
                    println!("Sweep Interval:      {} seconds", loaded_policy.globals.realtime_fallback_sweep_interval);
                    println!("Total Rules Defined: {}", loaded_policy.rules.len());

                    let roots = loaded_policy.get_monitored_roots();
                    println!("\nMonitored Root Paths ({}):", roots.len());
                    for r in &roots {
                        println!("  - {}", r.display());
                    }

                    println!("\nRules Breakdown:");
                    for rule in &loaded_policy.rules {
                        println!(
                            "  [{:2}] {} (mode: {:?}, nodiff: {}, action: {:?})",
                            rule.severity, rule.id, rule.mode, rule.nodiff, rule.active_response.action
                        );
                    }
                    println!("=================================================\n");
                }

                PolicyAction::Keygen { out_dir } => {
                    let (signing_key, verifying_key) = PolicySigner::generate_keypair();
                    let pub_hex = PolicySigner::pubkey_to_hex(&verifying_key);
                    let priv_hex = PolicySigner::privkey_to_hex(&signing_key);

                    println!("[+] Generated fresh Ed25519 administrative keypair:");
                    println!("Public Key  (hex): {}", pub_hex);
                    println!("Private Key (hex): {}", priv_hex);

                    if let Some(dir) = out_dir {
                        std::fs::create_dir_all(&dir)?;
                        let pub_file = dir.join("openfim_admin.pub");
                        let key_file = dir.join("openfim_admin.key");
                        std::fs::write(&pub_file, pub_hex.as_bytes())?;
                        std::fs::write(&key_file, priv_hex.as_bytes())?;
                        println!("[+] Keys saved to:");
                        println!("  - {}", pub_file.display());
                        println!("  - {}", key_file.display());
                    }
                }

                PolicyAction::Sign {
                    policy,
                    privkey,
                    out,
                } => {
                    let key_str = if std::path::Path::new(&privkey).exists() {
                        std::fs::read_to_string(&privkey)?
                    } else {
                        privkey
                    };

                    let signing_key = PolicySigner::privkey_from_hex(&key_str)?;
                    let signature = PolicySigner::sign_file(&policy, &signing_key)?;
                    let sig_hex = PolicySigner::signature_to_hex(&signature);

                    let out_path = out.unwrap_or_else(|| {
                        let mut p = policy.clone();
                        let ext = p.extension().map_or("sig".to_string(), |e| format!("{}.sig", e.to_string_lossy()));
                        p.set_extension(ext);
                        p
                    });

                    std::fs::write(&out_path, sig_hex.as_bytes())?;
                    println!("[+] Successfully signed policy file: {}", policy.display());
                    println!("[+] Ed25519 Detached Signature written to: {}", out_path.display());
                }

                PolicyAction::TestPath { policy, path } => {
                    let pol = Policy::from_yaml_file(&policy)?;
                    println!("[*] Testing path '{}' against policy '{}'...", path.display(), pol.policy_id);

                    if let Some(rule) = pol.find_matching_rule(&path) {
                        println!("\n[✓] PATH MONITORED: Integrity rule matched!");
                        println!("  Rule ID:         {}", rule.id);
                        println!("  Description:     {}", rule.description);
                        println!("  Severity:        {}/10", rule.severity);
                        println!("  Mode:            {:?}", rule.mode);
                        println!("  NoDiff (Secret): {}", rule.nodiff);
                        println!("  WhoData:         {}", rule.whodata);
                        println!("  Active Response: {:?}", rule.active_response.action);
                        println!(
                            "  Checks:          hash={}, size={}, perms={}, owner={}, timestamps={}, xattrs={}",
                            rule.checks.hash,
                            rule.checks.size,
                            rule.checks.permissions,
                            rule.checks.ownership,
                            rule.checks.timestamps,
                            rule.checks.xattrs
                        );
                    } else {
                        println!("\n[x] PATH NOT MONITORED: Path is ignored or not targeted by any rule.");
                    }
                }
            }
        }
    }

    Ok(())
}
