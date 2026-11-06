use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use clap::Parser;
use openfim_common::notify::{self, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use openfim_common::{
    evaluate, support_for, BackupStore, BaselineDb, ChangeKind, ChangeSet, Check, CompiledPolicy,
    FileMetadata, HashAlgorithm, Policy, PolicyRule, PolicyVerifier, ProcessContext,
    RemediationGuard, SpoolEvent, StreamHasher, TokenBucket, DEFAULT_MAX_REMEDIATIONS_PER_HOUR,
};

/// Debounce window for coalescing multi-stage editor writes.
const DEBOUNCE_WINDOW: Duration = Duration::from_millis(250);

/// Upper bound on debounce bookkeeping entries, so a storm of distinct paths cannot
/// grow the map without limit between idle sweeps.
const DEBOUNCE_MAX_ENTRIES: usize = 8192;

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

    /// Secret key for the HMAC-SHA256 append-only tamper-evident event log.
    ///
    /// Read from OPENFIM_HMAC_KEY in preference to the command line, since anything
    /// passed as an argument is visible to every other user via the process table.
    /// There is deliberately no default: a built-in key would let anyone who has the
    /// binary forge the entire audit chain.
    #[arg(long, env = "OPENFIM_HMAC_KEY", hide_env_values = true)]
    hmac_key: Option<String>,

    /// Read the HMAC key from a file instead of the environment or argv
    #[arg(long, conflicts_with = "hmac_key")]
    hmac_key_file: Option<PathBuf>,

    /// One-shot scan mode: inspect a single path and output JSON metadata
    #[arg(long)]
    inspect: Option<PathBuf>,

    /// Maximum I/O read rate in MB/s (0 = unlimited).
    ///
    /// Overrides `globals.max_io_rate_mb_s` in the policy. Left unset, the policy's
    /// value is used — previously this flag was the only thing that had any effect and
    /// the policy setting was silently ignored.
    #[arg(long)]
    throttle_mb_s: Option<u64>,

    /// Enable automated active response remediation (quarantine / rollback)
    #[arg(long)]
    remediation: bool,

    /// Maximum automated remediations per rolling hour (circuit breaker; 0 disables)
    #[arg(long, default_value_t = DEFAULT_MAX_REMEDIATIONS_PER_HOUR)]
    max_remediations_per_hour: u32,

    /// Optional directory containing pristine baseline backups for file restoration
    #[arg(long)]
    backup_dir: Option<PathBuf>,
}

/// Converts a MB/s setting into bytes per second without overflowing.
fn rate_bytes_per_sec(mb_s: u64) -> u64 {
    mb_s.saturating_mul(1024).saturating_mul(1024)
}

fn resolve_hmac_key(args: &Args) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if let Some(ref path) = args.hmac_key_file {
        let raw = fs::read_to_string(path)?;
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(format!("HMAC key file {} is empty", path.display()).into());
        }
        return Ok(trimmed.as_bytes().to_vec());
    }

    match args.hmac_key.as_deref().map(str::trim) {
        Some(k) if !k.is_empty() => Ok(k.as_bytes().to_vec()),
        _ => Err(
            "No HMAC key supplied. The tamper-evident event log cannot be signed \
                  without one, and shipping a default key would let anyone holding this \
                  binary forge the audit chain. Set OPENFIM_HMAC_KEY, or pass \
                  --hmac-key-file <PATH>."
                .into(),
        ),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    println!("============================================================");
    println!("  OpenFIM Defensive Sensor Daemon v0.1.0                    ");
    println!("  Compliance: PCI DSS 11.5 // NIST 800-53 SI-7              ");
    println!("============================================================");

    // One-shot inspection mode
    if let Some(ref target_path) = args.inspect {
        println!(
            "[*] Performing one-shot inspection on: {}",
            target_path.display()
        );
        let mut hasher = StreamHasher::new(
            HashAlgorithm::Sha256,
            TokenBucket::new(rate_bytes_per_sec(args.throttle_mb_s.unwrap_or(20))),
        );
        match FileMetadata::extract(target_path, &mut hasher) {
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

    let policy = if let Some(ref key_path) = args.key {
        println!(
            "[*] Verifying signed policy with public key: {}",
            key_path.display()
        );
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

    println!(
        "[*] Policy ID: {} ({} rules loaded)",
        policy.policy_id,
        policy.rules.len()
    );

    // Resolve the signing key before doing any work, so a misconfiguration fails
    // immediately rather than after the first undetectable event.
    let hmac_key = resolve_hmac_key(&args)?;

    // 2. Open SQLite baseline database
    let db = BaselineDb::open(&args.db)?;
    println!("[*] Local SQLite baseline active: {}", args.db.display());

    if args.remediation {
        println!(
            "[*] Remediation mode: ENABLED (automated active response, max {}/hour)",
            args.max_remediations_per_hour
        );
    } else {
        println!("[*] Remediation mode: DISABLED (audit / alert only)");
    }

    // Open the pristine-copy store once, up front, so a misconfigured path is reported
    // at startup rather than discovered during an incident.
    let backup_store = match args.backup_dir.as_deref() {
        Some(dir) => match BackupStore::open_or_create(dir) {
            Ok(store) => {
                println!(
                    "[*] Backup store: {} ({} pristine cop{} indexed)",
                    dir.display(),
                    store.len(),
                    if store.len() == 1 { "y" } else { "ies" }
                );
                if store.is_empty() {
                    println!(
                        "[!] The backup store is empty, so restore_baseline cannot act. \
                         Populate it with: openfim-cli baseline backup --db {} --out {}",
                        args.db.display(),
                        dir.display()
                    );
                }
                Some(store)
            }
            Err(e) => {
                // Do not fall back to "no store": that would silently turn a
                // restore_baseline policy into alert-only without the operator knowing.
                eprintln!("[!] Backup store unusable: {}", e);
                if args.remediation {
                    eprintln!(
                        "[!] Refusing to start with --remediation and an unusable backup store. \
                         Fix the store, or drop --remediation to run in alert-only mode."
                    );
                    std::process::exit(1);
                }
                None
            }
        },
        None => {
            if args.remediation {
                println!(
                    "[!] No --backup-dir given: restore_baseline rules will decline, \
                     since there is no pristine copy to restore from."
                );
            }
            None
        }
    };

    // Resolve the scanner settings the policy asks for. Until now `default_hash`,
    // `max_io_rate_mb_s` and `scan_nice_priority` were parsed and then ignored.
    let settings = policy.effective_scan_settings(args.throttle_mb_s);
    println!(
        "[*] Hash algorithm:    {:?} (from {})",
        settings.hash_algorithm.value, settings.hash_algorithm.source
    );
    println!(
        "[*] I/O rate limit:    {}",
        if settings.max_io_rate_mb_s.value == 0 {
            format!("unlimited (from {})", settings.max_io_rate_mb_s.source)
        } else {
            format!(
                "{} MB/s (from {})",
                settings.max_io_rate_mb_s.value, settings.max_io_rate_mb_s.source
            )
        }
    );

    match openfim_common::policy::apply_scan_priority(settings.scan_nice_priority.value) {
        Ok(()) => println!(
            "[*] Scan priority:     {} (from {})",
            settings.scan_nice_priority.value, settings.scan_nice_priority.source
        ),
        // Report rather than swallow: lowering priority needs privilege on Unix, and an
        // operator who configured it deserves to know it did not take effect.
        Err(e) => println!(
            "[!] Scan priority {} could not be applied: {}. Scanning continues at the \
             default priority.",
            settings.scan_nice_priority.value, e
        ),
    }

    // Report unenforceable controls once, at startup, rather than on every event.
    //
    // The operator needs to learn that a control they configured does nothing *before*
    // an incident, not while reading an alert that quietly omitted it.
    report_unenforceable_checks(&policy);

    if !ProcessContext::attribution_available() {
        println!(
            "[!] Process attribution: UNAVAILABLE on this build. Alerts will record the \
             integrity violation but not the writing process. Kernel-level attribution \
             (fanotify FAN_REPORT_PIDFD, eBPF, or a Windows minifilter) is required to \
             identify the actor."
        );
    }

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
    println!(
        "[*] Real-time sensor active: watching {} filesystem target(s)",
        registered_count
    );
    if registered_count == 0 {
        eprintln!(
            "[!] Warning: 0 watch targets could be registered. Verify monitored paths exist on disk."
        );
    }

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_signal = shutdown.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            println!(
                "\n[*] Received shutdown signal (Ctrl+C). Terminating OpenFIM agent gracefully."
            );
            shutdown_signal.store(true, Ordering::SeqCst);
        }
    });

    println!("[*] Sensor loop running. Press Ctrl+C to stop.");

    // 4. Run the sensor loop on the blocking pool.
    //
    // The loop is inherently synchronous: it waits on a std channel and performs
    // throttled file reads that sleep the calling thread. Running that directly inside
    // an async context parks a runtime worker, which would also stall the Ctrl+C task
    // on a single-worker runtime. spawn_blocking puts it where blocking work belongs.
    let compiled = CompiledPolicy::new(policy);
    let guard = RemediationGuard::new(if args.remediation {
        args.max_remediations_per_hour
    } else {
        0
    });

    let loop_cfg = SensorConfig {
        rate_bytes: settings.rate_bytes_per_sec(),
        hash_algorithm: settings.hash_algorithm.value,
        remediation: args.remediation,
        backup: backup_store,
        hmac_key,
    };

    let handle = tokio::task::spawn_blocking(move || {
        sensor_loop(rx, db, compiled, guard, loop_cfg, shutdown)
    });

    // Propagate a panic in the blocking task as an error rather than hanging.
    handle.await?;

    // Keep the watcher alive until the loop has finished.
    drop(watcher);
    Ok(())
}

struct SensorConfig {
    rate_bytes: u64,
    /// Algorithm the policy asked for, rather than a hardcoded SHA-256.
    hash_algorithm: HashAlgorithm,
    remediation: bool,
    /// Opened once at startup rather than per event: the store parses its index from
    /// disk, which has no business happening inside the hot path.
    backup: Option<BackupStore>,
    hmac_key: Vec<u8>,
}

fn sensor_loop(
    rx: mpsc::Receiver<notify::Event>,
    db: BaselineDb,
    policy: CompiledPolicy,
    mut guard: RemediationGuard,
    cfg: SensorConfig,
    shutdown: Arc<AtomicBool>,
) {
    let mut debounce: HashMap<PathBuf, Instant> = HashMap::new();

    loop {
        if shutdown.load(Ordering::SeqCst) {
            break;
        }

        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(event) => {
                let should_check = matches!(
                    event.kind,
                    EventKind::Modify(_) | EventKind::Create(_) | EventKind::Remove(_)
                );
                if !should_check {
                    continue;
                }

                // Bound the bookkeeping map. Under a burst of many distinct paths the
                // idle-timeout sweep never runs, so without this the map grows for as
                // long as the burst lasts.
                if debounce.len() > DEBOUNCE_MAX_ENTRIES {
                    debounce.retain(|_, v| v.elapsed() < DEBOUNCE_WINDOW);
                }

                for path in event.paths {
                    let rule = match policy.find_matching_rule(&path) {
                        Some(r) => r,
                        None => continue,
                    };

                    // Sliding window debouncing (ignore redundant events within 250ms)
                    let now = Instant::now();
                    if let Some(prev) = debounce.get(&path) {
                        if now.duration_since(*prev) < DEBOUNCE_WINDOW {
                            continue;
                        }
                    }
                    debounce.insert(path.clone(), now);

                    handle_path_event(&path, rule, &db, &mut guard, &cfg);
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // Background maintenance: clean old debounce entries
                debounce.retain(|_, v| v.elapsed() < Duration::from_secs(5));
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
}

fn handle_path_event(
    path: &Path,
    rule: &PolicyRule,
    db: &BaselineDb,
    guard: &mut RemediationGuard,
    cfg: &SensorConfig,
) {
    let whodata = ProcessContext::for_observed_event();
    let ts_nano = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as i64;

    let exists = path.exists();

    if exists && path.is_file() {
        let mut hasher = StreamHasher::new(cfg.hash_algorithm, TokenBucket::new(cfg.rate_bytes));
        let current_meta = match FileMetadata::extract(path, &mut hasher) {
            Ok(m) => m,
            Err(e) => {
                // Surface the failure instead of dropping it. A file that cannot be
                // read is exactly the state an attacker wants the monitor to ignore.
                eprintln!(
                    "[!] Could not inspect {} after a change event: {}",
                    path.display(),
                    e
                );
                return;
            }
        };

        match db.get_entry(path) {
            Ok(Some(baseline_entry)) => {
                // One engine decides what changed, for every check the rule enables.
                // The daemon used to compare only `hash` and then `permissions`
                // inline, which left five of the seven checks inert.
                let changes = evaluate(&baseline_entry, &current_meta, &rule.checks);

                if !changes.is_clean() {
                    print_change_alert(path, rule.severity, &whodata, &changes);

                    // Every observed difference is recorded separately, so the audit
                    // trail shows which controls fired rather than collapsing a
                    // content change and a permission change into one vague event.
                    for change in &changes.changes {
                        let mut spool =
                            create_spool_event_for(change, path, rule.severity, &whodata, ts_nano);
                        record_event(db, &mut spool, &cfg.hmac_key);
                    }

                    // Rollback is for content and object substitution. A timestamp or
                    // ownership edit alone does not justify overwriting the live file.
                    if changes.is_substantive() {
                        apply_remediation(path, rule, guard, cfg, db);
                    }
                }
            }
            Ok(None) => {
                // New unbaselined file created in monitored location
                print_alert(
                    "MEDIUM",
                    "FILE_CREATED",
                    path,
                    rule.severity,
                    &whodata,
                    None,
                    Some(&current_meta.sha256),
                );
                let mut spool = create_spool_event(
                    "FILE_CREATED",
                    path,
                    rule.severity,
                    &whodata,
                    ts_nano,
                    None,
                    Some(current_meta.sha256),
                );
                record_event(db, &mut spool, &cfg.hmac_key);
            }
            Err(e) => {
                eprintln!("[!] Baseline lookup failed for {}: {}", path.display(), e);
            }
        }
    } else if !exists {
        // Monitored file deleted
        match db.get_entry(path) {
            Ok(Some(baseline_entry)) => {
                print_alert(
                    "HIGH",
                    "FILE_DELETED",
                    path,
                    rule.severity,
                    &whodata,
                    Some(&baseline_entry.sha256),
                    None,
                );
                let mut spool = create_spool_event(
                    "FILE_DELETED",
                    path,
                    rule.severity,
                    &whodata,
                    ts_nano,
                    Some(baseline_entry.sha256),
                    None,
                );
                record_event(db, &mut spool, &cfg.hmac_key);
                apply_remediation(path, rule, guard, cfg, db);
            }
            Ok(None) => {}
            Err(e) => {
                eprintln!("[!] Baseline lookup failed for {}: {}", path.display(), e);
            }
        }
    }
}

/// Appends an event to the tamper-evident chain, reporting a failure rather than
/// silently discarding the record.
fn record_event(db: &BaselineDb, spool: &mut SpoolEvent, hmac_key: &[u8]) {
    if let Err(e) = db.append_spool_event_chained(spool, hmac_key) {
        eprintln!(
            "[!] CRITICAL: failed to record event {} to the tamper-evident log: {}. \
             The alert above is NOT in the audit chain.",
            spool.event_id, e
        );
    }
}

fn apply_remediation(
    path: &Path,
    rule: &PolicyRule,
    guard: &mut RemediationGuard,
    cfg: &SensorConfig,
    db: &BaselineDb,
) {
    if !cfg.remediation {
        return;
    }
    match guard.execute(rule.active_response.action, path, cfg.backup.as_ref()) {
        Ok(outcome) => {
            println!("    [REMEDIATION] {}", outcome);
            if outcome.was_applied() {
                reanchor_after_restore(path, cfg, db);
            }
        }
        Err(e) => eprintln!("    [REMEDIATION] failed: {}", e),
    }
}

/// After a verified restore, record the restored object's identity as the baseline's.
///
/// An atomic restore stages content beside the target and renames it into place, which
/// is what stops the live path being observed half-written — but it also means the file
/// now has a different inode (NTFS file index on Windows) than the baseline recorded.
/// Without this, the identity check reports `FILE_REPLACED` on the very next event, so
/// the defensive action would raise an alert about its own work.
///
/// Re-anchoring is gated on the content digest still matching the baseline, so a
/// tampered file can never be blessed this way.
fn reanchor_after_restore(path: &Path, cfg: &SensorConfig, db: &BaselineDb) {
    let mut hasher = StreamHasher::new(cfg.hash_algorithm, TokenBucket::new(cfg.rate_bytes));
    let restored = match FileMetadata::extract(path, &mut hasher) {
        Ok(m) => m,
        Err(e) => {
            eprintln!(
                "    [!] Restored {} but could not re-read it to re-anchor the baseline: {}",
                path.display(),
                e
            );
            return;
        }
    };

    match db.reanchor_entry_identity(path, &restored) {
        Ok(true) => {}
        Ok(false) => eprintln!(
            "    [!] Restored {} but its content does not match the baseline digest, so \
             the baseline identity was left unchanged. Investigate: the backup store may \
             hold content that was never the approved baseline.",
            path.display()
        ),
        Err(e) => eprintln!(
            "    [!] Could not re-anchor the baseline identity for {}: {}",
            path.display(),
            e
        ),
    }
}

/// Maps a change's rank onto an operator-facing severity label.
fn level_for(change: &ChangeKind) -> &'static str {
    match change.rank() {
        r if r >= 90 => "CRITICAL",
        r if r >= 60 => "HIGH",
        r if r >= 40 => "MEDIUM",
        _ => "LOW",
    }
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
    if let Some(oh) = old_hash {
        println!("    Old SHA256: {}", oh);
    }
    if let Some(nh) = new_hash {
        println!("    New SHA256: {}", nh);
    }
    print_whodata(who);
    println!("    Timestamp:  {}", unix_now_secs());
    println!("======================================================================");
}

/// Alert covering every difference the detection engine found for one path.
fn print_change_alert(path: &Path, severity: u32, who: &ProcessContext, changes: &ChangeSet) {
    let headline = match changes.most_severe() {
        Some(c) => c,
        None => return,
    };

    println!("\n[!] ==================== OPENFIM INTEGRITY ALERT ====================");
    println!(
        "    Level:      {} (Severity: {}/10)",
        level_for(headline),
        severity
    );
    println!("    Event:      {}", headline.event_type());
    println!("    Path:       {}", path.display());

    println!("    Changes:    {} detected", changes.len());
    let mut ordered: Vec<&ChangeKind> = changes.changes.iter().collect();
    ordered.sort_by_key(|c| std::cmp::Reverse(c.rank()));
    for change in ordered {
        println!("      - [{}] {}", change.event_type(), change.describe());
    }

    print_whodata(who);
    println!("    Timestamp:  {}", unix_now_secs());
    println!("======================================================================");
}

/// State plainly whether the acting process is known.
///
/// Printing the sensor's own PID under an "actor" label would put a false attribution
/// into the operator's hands and into the audit trail.
fn print_whodata(who: &ProcessContext) {
    if who.is_attributed {
        println!(
            "    Who-Data:   PID={} Comm={:?} Exe={:?} Cmdline={:?}",
            who.pid, who.comm, who.exe, who.cmdline
        );
    } else {
        println!("    Who-Data:   UNATTRIBUTED - the writing process could not be identified");
        println!("                (kernel-level attribution is required and unavailable here)");
    }
}

/// Warns about every check the policy enables that this platform cannot perform.
///
/// Silence here is what produces false assurance: a rule with `ownership: true` on
/// Windows loads, validates, and displays as active while comparing two fields that
/// are both hardcoded to zero.
fn report_unenforceable_checks(policy: &Policy) {
    use std::collections::BTreeSet;

    let mut offenders: BTreeSet<(&'static str, &'static str)> = BTreeSet::new();

    for rule in &policy.rules {
        for check in Check::ALL {
            let requested = match check {
                Check::Hash => rule.checks.hash,
                Check::Size => rule.checks.size,
                Check::Permissions => rule.checks.permissions,
                Check::Ownership => rule.checks.ownership,
                Check::Timestamps => rule.checks.timestamps,
                Check::Attributes => rule.checks.attributes,
                Check::Xattrs => rule.checks.xattrs,
            };
            if !requested {
                continue;
            }
            let support = support_for(check);
            if !support.is_active() {
                offenders.insert((
                    check.field_name(),
                    support.note().unwrap_or("unsupported in this build"),
                ));
            }
        }
    }

    if offenders.is_empty() {
        return;
    }

    println!(
        "[!] {} of the checks this policy enables cannot be enforced on {}:",
        offenders.len(),
        openfim_common::platform_name()
    );
    for (field, reason) in &offenders {
        println!("      - {}: {}", field, reason);
    }
    println!(
        "    These are reported as skipped rather than silently passing. \
         Run `openfim-cli policy lint` for the full picture."
    );
}

/// Monotonic discriminator for event ids.
///
/// `event_id` is UNIQUE in the spool schema, and a single filesystem change can now
/// produce several events in the same nanosecond — a content edit and a permission
/// edit, say. Deriving the id from the timestamp alone made those collide, and the
/// second insert would fail, silently dropping a real event from the audit chain.
static EVENT_COUNTER: AtomicU64 = AtomicU64::new(0);

fn next_event_id(ts_nano: i64) -> String {
    let n = EVENT_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("evt-{}-{}", ts_nano, n)
}

/// Builds a spool event for one detected change, carrying its digests where it has them.
fn create_spool_event_for(
    change: &ChangeKind,
    path: &Path,
    severity: u32,
    who: &ProcessContext,
    ts_nano: i64,
) -> SpoolEvent {
    let (old, new) = change.hashes();
    let mut event = create_spool_event(
        change.event_type(),
        path,
        severity,
        who,
        ts_nano,
        old.map(str::to_string),
        new.map(str::to_string),
    );
    // Record the human-readable description of this specific change. It is
    // authenticated by the event MAC, so it cannot be rewritten after the fact.
    event.diff_snippet = Some(change.describe());
    event
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
    // Only populate the who-data columns when the values genuinely describe the
    // acting process. Recording the sensor's own identity here would make every event
    // in the forensic log claim that OpenFIM itself performed the modification.
    let attributed = who.is_attributed;

    SpoolEvent {
        sequence_id: None,
        event_id: next_event_id(ts_nano),
        timestamp_nano: ts_nano,
        event_type: event_type.to_string(),
        path: openfim_common::normalize_path_str(path),
        severity,
        whodata_pid: attributed.then_some(who.pid),
        whodata_uid: if attributed { who.uid } else { None },
        whodata_comm: if attributed { who.comm.clone() } else { None },
        whodata_exe: if attributed { who.exe.clone() } else { None },
        whodata_cmdline: if attributed {
            who.cmdline.clone()
        } else {
            None
        },
        whodata_cgroup: None,
        old_sha256,
        new_sha256,
        diff_snippet: None,
        hmac_signature: String::new(),
        sent_to_manager: false,
    }
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_conversion_does_not_overflow() {
        assert_eq!(rate_bytes_per_sec(20), 20 * 1024 * 1024);
        assert_eq!(rate_bytes_per_sec(0), 0);
        // A huge setting must saturate rather than wrap to a tiny limit.
        assert_eq!(rate_bytes_per_sec(u64::MAX), u64::MAX);
    }

    fn args_with(hmac_key: Option<&str>, file: Option<PathBuf>) -> Args {
        Args {
            config: PathBuf::from("policy.yaml"),
            db: PathBuf::from("openfim.db"),
            key: None,
            hmac_key: hmac_key.map(|s| s.to_string()),
            hmac_key_file: file,
            inspect: None,
            throttle_mb_s: None,
            remediation: false,
            max_remediations_per_hour: 3,
            backup_dir: None,
        }
    }

    #[test]
    fn missing_hmac_key_is_rejected() {
        // A built-in default key would let anyone holding the binary forge the chain,
        // so the absence of a key must be a hard error, not a silent fallback.
        assert!(resolve_hmac_key(&args_with(None, None)).is_err());
        assert!(resolve_hmac_key(&args_with(Some("   "), None)).is_err());
    }

    #[test]
    fn hmac_key_is_read_from_argument() {
        let key = resolve_hmac_key(&args_with(Some("s3cret"), None)).unwrap();
        assert_eq!(key, b"s3cret");
    }

    #[test]
    fn hmac_key_is_read_from_file_and_trimmed() {
        let dir = std::env::temp_dir().join("openfim-agent-keytest");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("hmac.key");
        std::fs::write(&path, "  file-key\n").unwrap();

        let key = resolve_hmac_key(&args_with(None, Some(path.clone()))).unwrap();
        assert_eq!(key, b"file-key");

        std::fs::write(&path, "   \n").unwrap();
        assert!(resolve_hmac_key(&args_with(None, Some(path.clone()))).is_err());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn unattributed_events_leave_whodata_columns_empty() {
        let who = ProcessContext {
            pid: 1234,
            ppid: None,
            exe: Some("/opt/openfim/openfim-agent".to_string()),
            cmdline: Some("openfim-agent --config policy.yaml".to_string()),
            uid: Some(0),
            comm: Some("openfim-agent".to_string()),
            is_attributed: false,
        };

        let ev = create_spool_event(
            "CONTENT_MUTATED",
            Path::new("/etc/passwd"),
            9,
            &who,
            1,
            None,
            None,
        );

        assert_eq!(
            ev.whodata_pid, None,
            "the sensor's own PID must not be recorded as the acting process"
        );
        assert_eq!(ev.whodata_comm, None);
        assert_eq!(ev.whodata_exe, None);
        assert_eq!(ev.whodata_cmdline, None);
        assert_eq!(ev.whodata_uid, None);
    }

    #[test]
    fn attributed_events_record_whodata() {
        let who = ProcessContext {
            pid: 4242,
            ppid: Some(1),
            exe: Some("/usr/bin/vim".to_string()),
            cmdline: Some("vim /etc/passwd".to_string()),
            uid: Some(0),
            comm: Some("vim".to_string()),
            is_attributed: true,
        };

        let ev = create_spool_event(
            "CONTENT_MUTATED",
            Path::new("/etc/passwd"),
            9,
            &who,
            1,
            None,
            None,
        );

        assert_eq!(ev.whodata_pid, Some(4242));
        assert_eq!(ev.whodata_comm.as_deref(), Some("vim"));
    }
}
