use clap::{Parser, Subcommand};
use openfim_common::{BaselineDb, FileMetadata, HashAlgorithm, Policy, StreamHasher, TokenBucket};
use std::path::{Path, PathBuf};

mod console;

/// Writes sensitive key material with owner-only permissions.
///
/// On Unix the file is created with mode 0600 so that the default umask cannot leave
/// a signing key group- or world-readable. On Windows the file inherits the
/// directory ACL, which is noted in the CLI output so the operator can protect it.
pub(crate) fn write_secret_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(bytes)?;
        f.sync_all()
    }

    #[cfg(not(unix))]
    {
        std::fs::write(path, bytes)
    }
}

/// Renders a `st_mode` value using the right vocabulary for the platform.
///
/// On Unix this is a POSIX permission mode and octal is the natural form. On Windows
/// the same field holds Win32 attribute flags, where an octal rendering like `0o40`
/// reads as a nonsensical permission set (it is in fact FILE_ATTRIBUTE_ARCHIVE).
pub(crate) fn format_mode(mode: u32) -> String {
    if openfim_common::posix_mode_supported() {
        format!("0o{:o}", mode)
    } else {
        let mut flags = Vec::new();
        for (bit, name) in [
            (0x1u32, "READONLY"),
            (0x2, "HIDDEN"),
            (0x4, "SYSTEM"),
            (0x10, "DIRECTORY"),
            (0x20, "ARCHIVE"),
            (0x80, "NORMAL"),
            (0x100, "TEMPORARY"),
            (0x400, "REPARSE_POINT"),
            (0x800, "COMPRESSED"),
            (0x4000, "ENCRYPTED"),
        ] {
            if mode & bit != 0 {
                flags.push(name);
            }
        }
        if flags.is_empty() {
            format!("0x{:x} (Win32 attributes)", mode)
        } else {
            format!("0x{:x} (Win32 attributes: {})", mode, flags.join(" | "))
        }
    }
}

/// Converts a MB/s setting into bytes per second without overflowing.
///
/// A plain `mb_s * 1024 * 1024` wraps for large inputs, which in release builds turns
/// a deliberately huge limit into a very small one and throttles the scan to a crawl.
pub(crate) fn rate_bytes_per_sec(mb_s: u64) -> u64 {
    mb_s.saturating_mul(1024).saturating_mul(1024)
}

/// Resolves an HMAC key from an explicit value, a file, or the environment.
///
/// Prefers the environment and files over a command-line value, because arguments are
/// visible to any local user through the process table.
pub(crate) fn resolve_audit_key(
    explicit: Option<&str>,
    key_file: Option<&Path>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if let Some(path) = key_file {
        let raw = std::fs::read_to_string(path)?;
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(format!("HMAC key file {} is empty", path.display()).into());
        }
        return Ok(trimmed.as_bytes().to_vec());
    }
    if let Some(k) = explicit.map(str::trim).filter(|k| !k.is_empty()) {
        return Ok(k.as_bytes().to_vec());
    }
    if let Ok(env_key) = std::env::var("OPENFIM_HMAC_KEY") {
        let trimmed = env_key.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.as_bytes().to_vec());
        }
    }
    Err(
        "No HMAC key supplied. Set OPENFIM_HMAC_KEY, or pass --key-file <PATH>. \
         The audit chain cannot be verified without the key it was signed with."
            .into(),
    )
}

#[derive(Parser, Debug)]
#[command(
    name = "openfim-cli",
    about = "OpenFIM Command-Line Administrative Tool",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Launch interactive Metasploit-style defensive integrity console
    #[command(alias = "interactive")]
    Console,

    /// On-demand file integrity verification: check tampering, baseline match, policy rules, and audit trail
    #[command(alias = "check-file")]
    VerifyFile {
        /// Target file to verify
        #[arg(value_name = "FILE")]
        path: PathBuf,

        /// Optional baseline database (defaults to openfim.db if present)
        #[arg(short, long)]
        db: Option<PathBuf>,

        /// Optional policy YAML file (defaults to policy.yaml if present)
        #[arg(short, long)]
        policy: Option<PathBuf>,

        /// Optional expected SHA-256 hash to assert against
        #[arg(long)]
        expected_hash: Option<String>,
    },

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

    /// Audit and verify tamper-evidence of local offline event spool
    Audit {
        #[command(subcommand)]
        action: AuditAction,
    },
}

#[derive(Subcommand, Debug)]
pub enum AuditAction {
    /// Verify cryptographic HMAC chain and sequence continuity of the event spool
    Verify {
        /// Path to SQLite database containing event spool
        #[arg(short, long, default_value = "openfim.db")]
        db: PathBuf,

        /// Secret key for HMAC-SHA256 verification.
        ///
        /// Prefer OPENFIM_HMAC_KEY or --key-file: a key passed as an argument is
        /// visible to every local user through the process table. There is no
        /// default, because a built-in key would make the chain forgeable by anyone
        /// holding the binary.
        #[arg(short, long, env = "OPENFIM_HMAC_KEY", hide_env_values = true)]
        key: Option<String>,

        /// Read the HMAC verification key from a file
        #[arg(long, conflicts_with = "key")]
        key_file: Option<PathBuf>,
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

    /// Export baseline entries as a portable JSON or .sha256 manifest
    Export {
        /// Path to SQLite database
        #[arg(long)]
        db: PathBuf,

        /// Output path for manifest file
        #[arg(short, long)]
        out: PathBuf,

        /// Manifest format: json | sha256
        #[arg(short, long, default_value = "json")]
        format: String,
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

    let cmd = match cli.command {
        Some(c) => c,
        None => {
            return console::run_interactive_console();
        }
    };

    match cmd {
        Commands::Console => {
            console::run_interactive_console()?;
        }

        Commands::VerifyFile {
            path,
            db,
            policy,
            expected_hash,
        } => {
            println!("======================================================================");
            println!("               OPENFIM FILE INTEGRITY INSPECTION REPORT               ");
            println!("======================================================================");
            println!("Target Path:         {}", path.display());

            let exists = path.exists();
            let mut hasher = StreamHasher::default_sha256();

            // 1. Physical inspection & cryptographic hashing
            let current_meta = if exists && path.is_file() {
                match FileMetadata::extract(&path, &mut hasher) {
                    Ok(m) => Some(m),
                    Err(e) => {
                        eprintln!("[!] Failed to read file metadata or compute hash: {}", e);
                        None
                    }
                }
            } else if exists && path.is_dir() {
                println!("File Type:           Directory");
                None
            } else {
                println!("File Status:         MISSING / DELETED (Does not exist on disk)");
                None
            };

            if let Some(ref m) = current_meta {
                println!("File Status:         PRESENT ON DISK");
                println!("File Size:           {} bytes", m.st_size);
                println!("Permissions / Mode:  {}", format_mode(m.st_mode));
                println!(
                    "Last Modified Time:  Unix timestamp {} (ctime: {})",
                    m.st_mtime, m.st_ctime
                );
                println!("Computed SHA-256:    {}", m.sha256);
                if let Some(ref b3) = m.blake3 {
                    println!("Computed BLAKE3:     {}", b3);
                }
            }

            // 2. Expected hash manual comparison
            if let Some(ref exp) = expected_hash {
                println!("\n[1] CHECKSUM ASSERTION");
                let clean_exp = exp.trim().to_lowercase();
                if let Some(ref m) = current_meta {
                    if m.sha256.to_lowercase() == clean_exp {
                        println!("    Result:          [✓] PASSED - Cryptographic match with expected hash!");
                    } else {
                        println!("    Result:          [✗] FAILED - Hash mismatch!");
                        println!("    Expected:        {}", clean_exp);
                        println!("    Live SHA-256:    {}", m.sha256);
                    }
                } else {
                    println!("    Result:          [✗] FAILED - Cannot compare hash (file not readable or missing).");
                }
            }

            // 3. Baseline Database Comparison
            let db_path = db.or_else(|| {
                let default_p = PathBuf::from("openfim.db");
                if default_p.exists() {
                    Some(default_p)
                } else {
                    None
                }
            });

            let mut loaded_db = None;
            if let Some(ref p) = db_path {
                println!("\n[2] BASELINE DATABASE COMPARISON ({})", p.display());
                match BaselineDb::open(p) {
                    Ok(bdb) => {
                        match bdb.get_entry(&path) {
                            Ok(Some(baseline)) => {
                                println!("    Baseline Status: REGISTERED IN BASELINE");
                                println!("    Baseline Size:   {} bytes", baseline.st_size);
                                println!("    Baseline SHA256: {}", baseline.sha256);
                                println!("    Baseline Mode:   {}", format_mode(baseline.st_mode));

                                if let Some(ref cur) = current_meta {
                                    let hash_match = cur.sha256 == baseline.sha256;
                                    let meta_match = cur.st_mode == baseline.st_mode
                                        && cur.st_uid == baseline.st_uid;

                                    if hash_match && meta_match {
                                        println!("    INTEGRITY CHECK: [✓] CLEAN & UNCOMPROMISED (Matches baseline snapshot)");
                                    } else {
                                        println!("    INTEGRITY CHECK: [!] TAMPERING / MODIFICATION DETECTED!");
                                        if !hash_match {
                                            println!("      -> Content Divergence: Hash modified since baseline snapshot!");
                                            println!("         Expected: {}", baseline.sha256);
                                            println!("         Current:  {}", cur.sha256);
                                        }
                                        if !meta_match {
                                            println!("      -> Metadata Divergence: Permissions/ownership changed!");
                                            println!(
                                                "         Expected Mode: {}, UID: {}",
                                                format_mode(baseline.st_mode),
                                                baseline.st_uid
                                            );
                                            println!(
                                                "         Current Mode:  {}, UID: {}",
                                                format_mode(cur.st_mode),
                                                cur.st_uid
                                            );
                                        }
                                    }
                                } else {
                                    println!("    INTEGRITY CHECK: [!] FILE REMOVED (File was in baseline but is now deleted)");
                                }
                            }
                            Ok(None) => {
                                println!("    Baseline Status: [?] UNINDEXED (Not found in active baseline database)");
                                if current_meta.is_some() {
                                    println!("    Notice:          This is a new or unmonitored file not present in snapshot.");
                                }
                            }
                            Err(e) => {
                                println!("    Error querying baseline database: {}", e);
                            }
                        }
                        loaded_db = Some(bdb);
                    }
                    Err(e) => {
                        println!("    Error opening baseline database: {}", e);
                    }
                }
            } else {
                println!("\n[2] BASELINE DATABASE COMPARISON");
                println!("    Status:          Skipped (No database provided and 'openfim.db' not found)");
                println!("    Tip:             Run `openfim-cli baseline snapshot --dir <DIR> --db openfim.db` first.");
            }

            // 4. Policy Governance & Access Security
            let pol_path = policy.or_else(|| {
                let default_p = PathBuf::from("policy.yaml");
                if default_p.exists() {
                    Some(default_p)
                } else {
                    None
                }
            });

            if let Some(ref p) = pol_path {
                println!("\n[3] POLICY & SECURITY GOVERNANCE ({})", p.display());
                match Policy::from_yaml_file(p) {
                    Ok(pol) => {
                        if let Some(rule) = pol.find_matching_rule(&path) {
                            println!("    Governance:      [✓] MONITORED BY DEFENSIVE POLICY");
                            println!("    Rule ID:         {}", rule.id);
                            println!("    Description:     {}", rule.description);
                            println!("    Threat Severity: {}/10", rule.severity);
                            println!("    Watch Mode:      {:?}", rule.mode);
                            println!("    WhoData Active:  {}", rule.whodata);
                            println!("    Active Response: {:?}", rule.active_response.action);
                            println!(
                                "    Enforced Checks: hash={}, perms={}, owner={}",
                                rule.checks.hash, rule.checks.permissions, rule.checks.ownership
                            );
                        } else {
                            println!("    Governance:      [-] NOT MONITORED (Path does not match any active policy rules)");
                        }
                    }
                    Err(e) => {
                        println!("    Error loading policy file: {}", e);
                    }
                }
            } else {
                println!("\n[3] POLICY & SECURITY GOVERNANCE");
                println!(
                    "    Status:          Skipped (No policy provided and 'policy.yaml' not found)"
                );
            }

            // 5. Forensic WhoData & Audit Trail (Recent modification history from tamper-evident spool)
            if let Some(ref bdb) = loaded_db {
                println!("\n[4] FORENSIC WHODATA & AUDIT HISTORY (Local Spool)");
                match bdb.get_events_for_path(&path, 5) {
                    Ok(events) => {
                        if events.is_empty() {
                            println!("    Event Log:       No tampering or modification events logged for this file.");
                        } else {
                            println!(
                                "    Recorded Events: {} recent modification event(s) found:",
                                events.len()
                            );
                            for (i, ev) in events.iter().enumerate() {
                                println!("    ---------------- Event #{} ----------------", i + 1);
                                println!("      Type:          {}", ev.event_type);
                                println!("      Severity:      {}/10", ev.severity);
                                println!("      Timestamp:     Unix nanos {}", ev.timestamp_nano);
                                if let Some(pid) = ev.whodata_pid {
                                    println!("      Actor Process: PID {} (Executable: {:?}, Comm: {:?})",
                                        pid, ev.whodata_exe.as_deref().unwrap_or("unknown"), ev.whodata_comm.as_deref().unwrap_or("unknown"));
                                }
                                if let Some(ref cmd) = ev.whodata_cmdline {
                                    println!("      Command Line:  {}", cmd);
                                }
                                if let Some(uid) = ev.whodata_uid {
                                    println!("      Actor UID:     {}", uid);
                                }
                                if let Some(ref oh) = ev.old_sha256 {
                                    println!("      Old SHA-256:   {}", &oh[..oh.len().min(16)]);
                                }
                                if let Some(ref nh) = ev.new_sha256 {
                                    println!("      New SHA-256:   {}", &nh[..nh.len().min(16)]);
                                }
                                println!(
                                    "      HMAC Status:   CHAINED (Signature: {}...)",
                                    &ev.hmac_signature[..ev.hmac_signature.len().min(16)]
                                );
                            }
                        }
                    }
                    Err(e) => {
                        println!("    Error querying event spool: {}", e);
                    }
                }
            }

            println!("======================================================================\n");
        }

        Commands::Hash {
            path,
            algorithm,
            throttle_mb_s,
        } => {
            let algo = algorithm.parse::<HashAlgorithm>()?;
            let rate_bytes = rate_bytes_per_sec(throttle_mb_s);
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
            let mut hasher = StreamHasher::new(
                HashAlgorithm::Sha256,
                TokenBucket::new(rate_bytes_per_sec(throttle_mb_s)),
            );

            let options = CrawlOptions::default()
                .with_max_depth(max_depth)
                .with_ignore_patterns(ignore)?;

            let crawler = FileCrawler::new(options);
            println!("[*] Starting crawl on: {}", path.display());
            let items = crawler.crawl(&path, &mut hasher)?;
            println!("[*] Crawl complete. Indexed {} items:", items.len());
            for item in items {
                let type_str = if item.is_dir {
                    "DIR "
                } else if item.is_symlink {
                    "LINK"
                } else {
                    "FILE"
                };
                let short_hash = &item.sha256[..item.sha256.len().min(12)];
                println!(
                    "  [{}] {} ({} bytes, sha256: {})",
                    type_str,
                    item.path.display(),
                    item.st_size,
                    short_hash
                );
            }
        }

        Commands::Baseline { action } => {
            use openfim_common::{BaselineDb, CrawlOptions, FileCrawler};

            match action {
                BaselineAction::Init { db } => {
                    let _db = BaselineDb::open(&db)?;
                    println!(
                        "[+] Initialized SQLite baseline database at: {}",
                        db.display()
                    );
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

                    println!(
                        "[*] Ingesting {} records into baseline database...",
                        snapshot.len()
                    );
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

                    println!(
                        "[*] Crawling filesystem for live verification: {}",
                        dir.display()
                    );
                    let current_snapshot = crawler.crawl(&dir, &mut hasher)?;

                    println!("[*] Diffing against baseline database: {}", db.display());
                    let diff = baseline_db.diff_filesystem_scoped(&current_snapshot, Some(&dir))?;

                    if diff.is_clean() {
                        println!("\n[✓] INTEGRITY VERIFIED: 0 changes detected. System matches active baseline perfectly.");
                    } else {
                        println!(
                            "\n[!] INTEGRITY VIOLATION DETECTED! Total Changes: {}",
                            diff.total_changes()
                        );

                        if !diff.modified_content.is_empty() {
                            println!(
                                "\n--- [MODIFIED CONTENT (HASH DIVERGENCE)] ({} files) ---",
                                diff.modified_content.len()
                            );
                            for c in &diff.modified_content {
                                let old_h = &c.old_sha256[..c.old_sha256.len().min(12)];
                                let new_h = &c.new_sha256[..c.new_sha256.len().min(12)];
                                println!(
                                    "  * {}: expected {} -> found {}",
                                    c.path.display(),
                                    old_h,
                                    new_h
                                );
                            }
                        }

                        if !diff.added.is_empty() {
                            println!(
                                "\n--- [UNAUTHORIZED NEW FILES (ADDED)] ({} files) ---",
                                diff.added.len()
                            );
                            for a in &diff.added {
                                let h = &a.sha256[..a.sha256.len().min(12)];
                                println!(
                                    "  * {} ({} bytes, sha256: {})",
                                    a.path.display(),
                                    a.st_size,
                                    h
                                );
                            }
                        }

                        if !diff.removed.is_empty() {
                            println!(
                                "\n--- [DELETED FILES (REMOVED)] ({} files) ---",
                                diff.removed.len()
                            );
                            for r in &diff.removed {
                                let h = &r.sha256[..r.sha256.len().min(12)];
                                println!("  * {} (last known sha256: {})", r.path.display(), h);
                            }
                        }

                        if !diff.modified_metadata.is_empty() {
                            println!(
                                "\n--- [MODIFIED PERMISSIONS / ATTRIBUTES] ({} files) ---",
                                diff.modified_metadata.len()
                            );
                            for m in &diff.modified_metadata {
                                println!(
                                    "  * {}: mode {:o} -> {:o}, uid {} -> {}",
                                    m.path.display(),
                                    m.old_mode,
                                    m.new_mode,
                                    m.old_uid,
                                    m.new_uid
                                );
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
                BaselineAction::Export { db, out, format } => {
                    let baseline_db = BaselineDb::open(&db)?;
                    let content = baseline_db.export_manifest(&format)?;
                    std::fs::write(&out, content)?;
                    println!(
                        "[+] Exported baseline manifest ({} format) to: {}",
                        format,
                        out.display()
                    );
                }
            }
        }

        Commands::Policy { action } => {
            use openfim_common::{Policy, PolicySigner, PolicyVerifier};

            match action {
                PolicyAction::Check {
                    policy,
                    pubkey,
                    sig,
                } => {
                    println!("[*] Reading policy manifest: {}", policy.display());

                    let loaded_policy = if let Some(pk_arg) = pubkey {
                        let pk_str = if std::path::Path::new(&pk_arg).exists() {
                            std::fs::read_to_string(&pk_arg)?
                        } else {
                            pk_arg
                        };
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
                    println!(
                        "Default Hashing:     {}",
                        loaded_policy.globals.default_hash
                    );
                    println!(
                        "Max I/O Scan Rate:   {} MB/s",
                        loaded_policy.globals.max_io_rate_mb_s
                    );
                    println!(
                        "Sweep Interval:      {} seconds",
                        loaded_policy.globals.realtime_fallback_sweep_interval
                    );
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
                            rule.severity,
                            rule.id,
                            rule.mode,
                            rule.nodiff,
                            rule.active_response.action
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

                    // The private key is deliberately NOT printed.
                    //
                    // Writing a signing key to stdout leaks it into shell history,
                    // terminal scrollback, CI job logs and anything capturing output.
                    // This key authorizes every policy the fleet will trust, so it is
                    // written only to a file with owner-only permissions.
                    let dir = out_dir.unwrap_or_else(|| PathBuf::from("."));
                    std::fs::create_dir_all(&dir)?;
                    let pub_file = dir.join("openfim_admin.pub");
                    let key_file = dir.join("openfim_admin.key");

                    std::fs::write(&pub_file, pub_hex.as_bytes())?;
                    write_secret_file(&key_file, priv_hex.as_bytes())?;

                    println!("[+] Keys saved to:");
                    println!("  - {} (public)", pub_file.display());
                    println!("  - {} (PRIVATE - keep offline)", key_file.display());
                    println!(
                        "[i] The private key was written to disk only, never to this terminal.\n    \
                         Move it to protected offline storage; anything able to read it can sign \
                         policies your whole fleet will trust."
                    );
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
                        let ext = p.extension().map_or("sig".to_string(), |e| {
                            format!("{}.sig", e.to_string_lossy())
                        });
                        p.set_extension(ext);
                        p
                    });

                    std::fs::write(&out_path, sig_hex.as_bytes())?;
                    println!("[+] Successfully signed policy file: {}", policy.display());
                    println!(
                        "[+] Ed25519 Detached Signature written to: {}",
                        out_path.display()
                    );
                }

                PolicyAction::TestPath { policy, path } => {
                    let pol = Policy::from_yaml_file(&policy)?;
                    println!(
                        "[*] Testing path '{}' against policy '{}'...",
                        path.display(),
                        pol.policy_id
                    );

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

        Commands::Audit { action } => match action {
            AuditAction::Verify { db, key, key_file } => {
                println!(
                    "[*] Auditing tamper-evident HMAC offline log: {}",
                    db.display()
                );
                let audit_key = resolve_audit_key(key.as_deref(), key_file.as_deref())?;
                let baseline_db = BaselineDb::open(&db)?;
                let report = baseline_db.verify_spool_chain(&audit_key)?;
                if report.is_valid {
                    println!("\n============================================================");
                    println!("  [✓] AUDIT PASSED: Tamper-Evident HMAC Chain is VALID      ");
                    println!("  Total Events Verified:  {}", report.total_events);
                    println!("  Sequence Continuity:    CONTIGUOUS (No gaps/deletions)    ");
                    println!("  Cryptographic Status:   UNCOMPROMISED                     ");
                    println!("============================================================");
                } else {
                    println!("\n============================================================");
                    println!("  [✗] AUDIT FAILED: TAMPERING DETECTED!                     ");
                    println!("  Total Events Verified:  {}", report.total_events);
                    println!(
                        "  Tampered Sequence ID:   {:?}",
                        report.tampered_sequence_id
                    );
                    println!(
                        "  Error Details:          {}",
                        report.error_message.unwrap_or_default()
                    );
                    println!("============================================================");
                    std::process::exit(1);
                }
            }
        },
    }

    Ok(())
}
