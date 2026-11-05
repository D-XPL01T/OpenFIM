use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use clap::Parser;
use openfim_common::notify::{self, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use openfim_common::{
    BaselineDb, FileMetadata, HashAlgorithm, Policy, PolicyVerifier, ProcessContext, SpoolEvent,
    StreamHasher, TokenBucket,
};

#[derive(Parser, Debug)]
#[command(
    name = "openfim-agent",
    about = "OpenFIM Defensive Integrity Monitoring Endpoint Sensor & Real-time Daemon",
    version
)]
struct Args {
    /// Path to the declarative YAML policy file
    #[arg(short, long, default_value = "policy.yaml")]
    config: PathBuf,

    /// Path to local SQLite baseline database
    #[arg(short, long, default_value = "openfim.db")]
    db: PathBuf,

    /// Ed25519 administrative public key to verify policy (optional)
    #[arg(short, long)]
    key: Option<PathBuf>,

    /// Secret key for HMAC-SHA256 append-only tamper-evident event log
    #[arg(long, default_value = "openfim-sensor-secret-key")]
    hmac_key: String,

    /// One-shot scan mode: inspect a single path and output JSON metadata
    #[arg(long)]
    inspect: Option<PathBuf>,

    /// Maximum I/O read rate in MB/s (0 = unlimited)
    #[arg(long, default_value_t = 20)]
    throttle_mb_s: u64,

    /// Enable automated active response remediation (quarantine / rollback)
    #[arg(long)]
    remediation: bool,

    /// Optional directory containing pristine baseline backups for file restoration
    #[arg(long)]
    backup_dir: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    println!("============================================================");
    println!("  OpenFIM Defensive Sensor Daemon v0.1.0                    ");
    println!("  Compliance: PCI DSS 11.5 // NIST 800-53 SI-7              ");
    println!("============================================================");

    // One-shot inspection mode
    if let Some(target_path) = args.inspect {
        println!("[*] Performing one-shot inspection on: {}", target_path.display());
        let rate_bytes = args.throttle_mb_s * 1024 * 1024;
        let mut hasher = StreamHasher::new(HashAlgorithm::Sha256, TokenBucket::new(rate_bytes));
        match FileMetadata::extract(&target_path, &mut hasher) {
            Ok(meta) => println!("{}", serde_json::to_string_pretty(&meta)?),
            Err(e) => {
                eprintln!("[!] Inspection error: {}", e);
                std::process::exit(1);
            }
        }
        return Ok(());
    }

    // 1. Load and optionally verify signed policy
    if !args.config.exists() {
        eprintln!("[!] Policy file not found: {}", args.config.display());
        std::process::exit(1);
    }

    let policy = if let Some(key_path) = args.key {
        println!("[*] Verifying signed policy with public key: {}", key_path.display());
        let pub_hex = fs::read_to_string(key_path)?;
        let verifying_key = openfim_common::PolicySigner::pubkey_from_hex(&pub_hex)?;

        let mut sig_candidate = args.config.clone().into_os_string();
        sig_candidate.push(".sig");
        let direct_sig = PathBuf::from(sig_candidate);

        if direct_sig.exists() {
            PolicyVerifier::verify_file(&args.config, &direct_sig, &verifying_key)?
        } else {
            PolicyVerifier::verify_file_auto(&args.config, &verifying_key)?
        }
    } else {
        println!("[*] Loading policy from: {}", args.config.display());
        let content = fs::read_to_string(&args.config)?;
        Policy::from_yaml_str(&content)?
    };

    println!("[*] Policy ID: {} ({} rules loaded)", policy.policy_id, policy.rules.len());

    // 2. Open SQLite baseline database
    let db = BaselineDb::open(&args.db)?;
    println!("[*] Local SQLite baseline active: {}", args.db.display());
    println!("[*] Remediation mode: {}", if args.remediation { "ENABLED (Automated Active Response)" } else { "DISABLED (Audit / Alert Only)" });

    // 3. Setup real-time file watcher
    let (tx, rx) = mpsc::channel();
    let mut watcher = RecommendedWatcher::new(
        move |res| {
            if let Ok(event) = res {
                let _ = tx.send(event);
            }
        },
        notify::Config::default(),
    )?;

    // Register watch paths from policy rules (deduplicating directories)
    let mut watched_targets = std::collections::HashSet::new();
    let mut registered_count = 0;
    for rule in &policy.rules {
        for path_str in &rule.paths {
            let p = Path::new(path_str);
            let watch_target = if p.is_dir() {
                p.to_path_buf()
            } else {
                p.parent().unwrap_or_else(|| Path::new(".")).to_path_buf()
            };

            if watch_target.exists() && watched_targets.insert(watch_target.clone()) {
                let mode = if rule.recursive && p.is_dir() {
                    RecursiveMode::Recursive
                } else {
                    RecursiveMode::NonRecursive
                };
                if watcher.watch(&watch_target, mode).is_ok() {
                    registered_count += 1;
                }
            }
        }
    }
    println!("[*] Real-time sensor active: watching {} filesystem target(s)", registered_count);
    if registered_count == 0 {
        eprintln!("[!] Warning: 0 watch targets could be registered. Verify monitored paths exist on disk.");
    }

    let shutdown = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let shutdown_signal = shutdown.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            println!("\n[*] Received shutdown signal (Ctrl+C). Terminating OpenFIM agent gracefully.");
            shutdown_signal.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    });

    println!("[*] Sensor loop running. Press Ctrl+C to stop.");

    let hmac_bytes = args.hmac_key.as_bytes();
    let mut debounce: HashMap<PathBuf, Instant> = HashMap::new();
    let rate_bytes = args.throttle_mb_s * 1024 * 1024;

    // 4. Asynchronous / Event loop with debouncing and attribution
    loop {
        if shutdown.load(std::sync::atomic::Ordering::SeqCst) {
            break;
        }
        // Drain events from watcher channel with timeout
        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(event) => {
                let should_check = matches!(
                    event.kind,
                    EventKind::Modify(_) | EventKind::Create(_) | EventKind::Remove(_)
                );
                if !should_check {
                    continue;
                }

                for path in event.paths {
                    // Check if monitored and not ignored
                    let rule = match policy.find_matching_rule(&path) {
                        Some(r) => r,
                        None => continue,
                    };

                    // Sliding window debouncing (ignore redundant events within 250ms)
                    let now = Instant::now();
                    if let Some(prev) = debounce.get(&path) {
                        if now.duration_since(*prev) < Duration::from_millis(250) {
                            continue;
                        }
                    }
                    debounce.insert(path.clone(), now);

                    // Forensic who-data capture
                    let whodata = ProcessContext::current();
                    let ts_nano = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_nanos() as i64;

                    if path.exists() && path.is_file() {
                        let mut hasher = StreamHasher::new(HashAlgorithm::Sha256, TokenBucket::new(rate_bytes));
                        let current_meta = match FileMetadata::extract(&path, &mut hasher) {
                            Ok(m) => m,
                            Err(_) => continue,
                        };

                        if let Ok(Some(baseline_entry)) = db.get_entry(&path) {
                            // Check for content mutation
                            if rule.checks.hash && baseline_entry.sha256 != current_meta.sha256 {
                                print_alert("CRITICAL", "CONTENT_MUTATED", &path, rule.severity, &whodata, Some(&baseline_entry.sha256), Some(&current_meta.sha256));
                                
                                let mut spool = create_spool_event(
                                    "CONTENT_MUTATED",
                                    &path,
                                    rule.severity,
                                    &whodata,
                                    ts_nano,
                                    Some(baseline_entry.sha256),
                                    Some(current_meta.sha256),
                                );
                                let _ = db.append_spool_event_chained(&mut spool, hmac_bytes);

                                if args.remediation {
                                    let rem = rule.active_response.action.execute(&path, args.backup_dir.as_deref());
                                    println!("    [REMEDIATION] => {:?}", rem);
                                }
                            } else if rule.checks.permissions && baseline_entry.st_mode != current_meta.st_mode {
                                print_alert("HIGH", "METADATA_MUTATED", &path, rule.severity, &whodata, None, None);
                                let mut spool = create_spool_event("METADATA_MUTATED", &path, rule.severity, &whodata, ts_nano, None, None);
                                let _ = db.append_spool_event_chained(&mut spool, hmac_bytes);
                            }
                        } else {
                            // New unbaselined file created in monitored location
                            print_alert("MEDIUM", "FILE_CREATED", &path, rule.severity, &whodata, None, Some(&current_meta.sha256));
                            let mut spool = create_spool_event("FILE_CREATED", &path, rule.severity, &whodata, ts_nano, None, Some(current_meta.sha256));
                            let _ = db.append_spool_event_chained(&mut spool, hmac_bytes);
                        }
                    } else if !path.exists() {
                        // Monitored file deleted
                        if let Ok(Some(baseline_entry)) = db.get_entry(&path) {
                            print_alert("HIGH", "FILE_DELETED", &path, rule.severity, &whodata, Some(&baseline_entry.sha256), None);
                            let mut spool = create_spool_event("FILE_DELETED", &path, rule.severity, &whodata, ts_nano, Some(baseline_entry.sha256), None);
                            let _ = db.append_spool_event_chained(&mut spool, hmac_bytes);

                            if args.remediation {
                                let rem = rule.active_response.action.execute(&path, args.backup_dir.as_deref());
                                println!("    [REMEDIATION] => {:?}", rem);
                            }
                        }
                    }
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // Background maintenance: clean old debounce entries
                debounce.retain(|_, v| v.elapsed() < Duration::from_secs(5));
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    Ok(())
}

fn print_alert(
    level: &str,
    event_type: &str,
    path: &Path,
    severity: u32,
    who: &ProcessContext,
    old_hash: Option<&str>,
    new_hash: Option<&str>,
) {
    println!("\n[!] ==================== OPENFIM INTEGRITY ALERT ====================");
    println!("    Level:      {} (Severity: {}/10)", level, severity);
    println!("    Event:      {}", event_type);
    println!("    Path:       {}", path.display());
    if let Some(oh) = old_hash { println!("    Old SHA256: {}", oh); }
    if let Some(nh) = new_hash { println!("    New SHA256: {}", nh); }
    println!("    Who-Data:   PID={} Comm={:?} Exe={:?} Cmdline={:?}", who.pid, who.comm, who.exe, who.cmdline);
    println!("    Timestamp:  {}", chrono_now());
    println!("======================================================================");
}

fn create_spool_event(
    event_type: &str,
    path: &Path,
    severity: u32,
    who: &ProcessContext,
    ts_nano: i64,
    old_sha256: Option<String>,
    new_sha256: Option<String>,
) -> SpoolEvent {
    SpoolEvent {
        sequence_id: None,
        event_id: format!("evt-{}", ts_nano),
        timestamp_nano: ts_nano,
        event_type: event_type.to_string(),
        path: openfim_common::normalize_path_str(path),
        severity,
        whodata_pid: Some(who.pid),
        whodata_uid: who.uid,
        whodata_comm: who.comm.clone(),
        whodata_exe: who.exe.clone(),
        whodata_cmdline: who.cmdline.clone(),
        whodata_cgroup: None,
        old_sha256,
        new_sha256,
        diff_snippet: None,
        hmac_signature: String::new(),
        sent_to_manager: false,
    }
}

fn chrono_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
