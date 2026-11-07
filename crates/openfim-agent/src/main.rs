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
    evaluate, reconcile, support_for, BackupStore, BaselineDb, ChangeKind, ChangeSet, Check,
    CompiledPolicy, DiffOutcome, FileMetadata, HashAlgorithm, Policy, PolicyRule, PolicyVerifier,
    ProcessContext, RemediationGuard, RuleMode, SpoolEvent, StreamHasher, SweepReason, TokenBucket,
    DEFAULT_MAX_REMEDIATIONS_PER_HOUR, EVENT_HEARTBEAT, EVENT_SPOOL_PRUNED, EVENT_WATCH_OVERFLOW,
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

    /// Request the Linux append-only inode flag on the spool database.
    ///
    /// Raises the bar on evidence destruction: the kernel then refuses to truncate or
    /// rewrite the file, and clearing the flag needs CAP_LINUX_IMMUTABLE. Opt-in, and
    /// the result is always reported rather than assumed.
    #[arg(long)]
    append_only_spool: bool,

    /// Seconds between liveness heartbeats and spool-quota enforcement.
    ///
    /// Heartbeats make a coverage gap visible: without them, an agent stopped by an
    /// attacker is indistinguishable from an agent with nothing to report.
    #[arg(long, default_value_t = 300)]
    heartbeat_secs: u64,

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
    //
    // A key file readable by other users is refused outright, the same way OpenSSH
    // refuses an exposed private key: anything able to read it can forge the audit
    // chain, so proceeding would teach the operator that the exposure is acceptable.
    if let Some(ref key_path) = args.hmac_key_file {
        openfim_common::require_owner_only_secret(key_path)?;
    }
    let root_key = resolve_hmac_key(&args)?;

    // 2. Open SQLite baseline database
    let db = BaselineDb::open(&args.db)?;

    // Derive this database's chain key from the operator's root secret, so a fleet
    // sharing one secret does not share one chain key. A database that already holds
    // events but no recorded scheme predates derivation and stays on the raw key, since
    // switching it would make its entire existing chain fail verification and the tool
    // would report tampering where there was none.
    let (hmac_key, key_scheme) = db.resolve_chain_key(&root_key)?;
    println!("[*] Chain key:         {}", key_scheme.describe());
    if key_scheme == openfim_common::KeyScheme::Raw {
        println!(
            "[!] This database predates key derivation. Its chain is still valid, but the \
             supplied secret signs it directly, so a leak compromises every host sharing \
             that secret. Re-baseline into a fresh database to adopt derivation."
        );
    }
    println!("[*] Local SQLite baseline active: {}", args.db.display());

    // The baseline is not an ordinary application file: it holds the digests that
    // define "unmodified", so anyone who can write it can redefine correct. Tighten it
    // where possible and say so loudly where not.
    match openfim_common::protect::restrict_to_owner(&args.db) {
        Ok(true) => println!("[*] Tightened baseline database permissions to owner-only."),
        Ok(false) => {}
        Err(e) => eprintln!(
            "[!] Could not restrict baseline database permissions: {}",
            e
        ),
    }
    if let Some(warning) = openfim_common::warn_if_exposed(&args.db, "baseline database") {
        eprintln!("[!] {}", warning);
    }

    if args.append_only_spool {
        let outcome = openfim_common::protect::request_append_only(&args.db);
        if outcome.is_protected() {
            println!("[*] Spool append-only: {}", outcome.explain());
        } else {
            // Never claim a protection that was not applied.
            eprintln!("[!] Spool append-only NOT in force: {}", outcome.explain());
        }
    }

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

    // Register watch paths from policy rules (deduplicating directories).
    //
    // `rule.mode` is honoured here rather than ignored: only `realtime` rules get a
    // kernel watch. `scheduled` and `on_boot` rules are covered by the reconciliation
    // sweep instead, which is the whole point of declaring a mode. Watching everything
    // regardless would quietly make the field meaningless.
    let mut watched_targets = std::collections::HashSet::new();
    let mut registered_count = 0;
    let mut sweep_only_rules = 0;
    for rule in &policy.rules {
        if rule.mode != RuleMode::Realtime {
            sweep_only_rules += 1;
            continue;
        }
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
    if sweep_only_rules > 0 {
        println!(
            "[*] {} rule(s) are scheduled or on-boot, so they are covered by the \
             reconciliation sweep rather than by a live watch.",
            sweep_only_rules
        );
    }
    if registered_count == 0 && sweep_only_rules == 0 {
        eprintln!(
            "[!] Warning: 0 watch targets could be registered. Verify monitored paths exist on disk."
        );
    }

    // Self-monitoring. The agent's own binary, policy, trusted public key and baseline
    // are the first things an attacker goes after: replace the binary and monitoring
    // stops; edit the policy and the monitored set shrinks; swap the public key and
    // forged policies become trusted. These watches are registered unconditionally and
    // cannot be removed by policy, because a policy able to disable self-monitoring
    // would be the first thing an attacker edited.
    let mut self_watched = 0;
    for (label, candidate) in [
        ("own binary", std::env::current_exe().ok()),
        ("policy file", Some(args.config.clone())),
        ("trusted public key", args.key.clone()),
        ("baseline database", Some(args.db.clone())),
    ] {
        let Some(target) = candidate else { continue };
        let dir = match target.parent() {
            Some(d) if d.exists() => d.to_path_buf(),
            _ => continue,
        };
        if watched_targets.insert(dir.clone())
            && watcher.watch(&dir, RecursiveMode::NonRecursive).is_ok()
        {
            self_watched += 1;
        }
        let _ = label;
    }
    if self_watched > 0 {
        println!(
            "[*] Self-defense: watching {} additional location(s) holding the agent's own \
             binary, policy, key and baseline.",
            self_watched
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

    let sweep_interval = Duration::from_secs(settings.sweep_interval_secs.value);
    if sweep_interval.is_zero() {
        println!(
            "[!] Reconciliation sweep DISABLED (globals.realtime_fallback_sweep_interval \
             is 0). Events dropped by the watcher will not be recovered."
        );
    } else {
        println!(
            "[*] Reconciliation sweep: every {}s (from {})",
            sweep_interval.as_secs(),
            settings.sweep_interval_secs.source
        );
    }

    // Read through the compiled policy: the owned `Policy` was moved into it above.
    let max_spool_mb = compiled.policy().globals.max_spool_mb;
    let max_spool_bytes = max_spool_mb.saturating_mul(1024).saturating_mul(1024);
    println!(
        "[*] Spool quota:       {}",
        if max_spool_bytes == 0 {
            "unlimited".to_string()
        } else {
            format!("{} MB", max_spool_mb)
        }
    );

    let loop_cfg = SensorConfig {
        rate_bytes: settings.rate_bytes_per_sec(),
        hash_algorithm: settings.hash_algorithm.value,
        sweep_interval,
        heartbeat_interval: Duration::from_secs(args.heartbeat_secs),
        max_spool_bytes,
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
    /// How often to reconcile against the baseline. `ZERO` disables the sweep.
    sweep_interval: Duration,
    /// How often to emit a liveness beacon and enforce the spool quota.
    heartbeat_interval: Duration,
    /// Spool disk quota in bytes; 0 disables the cap.
    max_spool_bytes: u64,
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
    let mut reported = ReportedState::default();

    // Startup reconciliation, covering everything that changed while the agent was not
    // running. Without it, a modification made during downtime is never noticed: the
    // watcher only reports changes that happen after its watch is registered.
    run_sweep(
        SweepReason::Boot,
        &db,
        &policy,
        &mut guard,
        &cfg,
        &mut reported,
    );

    let mut next_sweep = Instant::now() + cfg.sweep_interval;
    let mut next_heartbeat = Instant::now() + cfg.heartbeat_interval;

    loop {
        if shutdown.load(Ordering::SeqCst) {
            break;
        }

        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(event) => {
                // The watcher admitting it dropped events is itself a security-relevant
                // fact. On Linux this is inotify's IN_Q_OVERFLOW; on Windows it is a
                // ReadDirectoryChangesW buffer overrun. Everything in that window is
                // gone, so record the gap and reconcile immediately rather than
                // carrying on as though coverage were continuous.
                if event.need_rescan() {
                    eprintln!(
                        "\n[!] WATCHER OVERFLOW: the kernel dropped filesystem events. \
                         An unobserved window exists; forcing immediate reconciliation."
                    );
                    record_bare_event(
                        &db,
                        EVENT_WATCH_OVERFLOW,
                        Path::new("<watcher>"),
                        10,
                        Some(
                            "the filesystem event queue overflowed; changes in this \
                             window were not observed in real time"
                                .to_string(),
                        ),
                        &cfg.hmac_key,
                    );
                    run_sweep(
                        SweepReason::WatchOverflow,
                        &db,
                        &policy,
                        &mut guard,
                        &cfg,
                        &mut reported,
                    );
                    next_sweep = Instant::now() + cfg.sweep_interval;
                    continue;
                }

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

                let now = Instant::now();

                if cfg.sweep_interval > Duration::ZERO && now >= next_sweep {
                    run_sweep(
                        SweepReason::Periodic,
                        &db,
                        &policy,
                        &mut guard,
                        &cfg,
                        &mut reported,
                    );
                    next_sweep = Instant::now() + cfg.sweep_interval;
                }

                if now >= next_heartbeat {
                    emit_heartbeat(&db, &cfg);
                    enforce_spool_quota(&db, &cfg);
                    next_heartbeat = Instant::now() + cfg.heartbeat_interval;
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    // A clean shutdown is recorded, so that a gap in the chain distinguishes "the
    // operator stopped the agent" from "something killed it".
    record_bare_event(
        &db,
        "SENSOR_STOPPED",
        Path::new("<sensor>"),
        1,
        Some("graceful shutdown".to_string()),
        &cfg.hmac_key,
    );
}

/// Tracks which divergences have already been reported, so an unresolved one is not
/// re-announced on every sweep.
///
/// Without this, a divergence the operator has chosen not to remediate is reported
/// afresh every interval: in the live test above, the same change was announced every
/// two seconds. That buries genuinely new findings in repetition and, because every
/// repeat is a chained spool event, drives the spool straight into its quota.
///
/// Keyed by path and current digest, so the suppression is specific to *this* observed
/// state. If the file changes again the digest differs and the new state is reported
/// immediately — nothing is ever hidden, only de-duplicated.
#[derive(Default)]
struct ReportedState {
    seen: HashMap<PathBuf, String>,
}

impl ReportedState {
    /// Returns true when this exact state has not been reported yet, recording it.
    fn is_new(&mut self, path: &Path, fingerprint: &str) -> bool {
        match self.seen.get(path) {
            Some(prev) if prev == fingerprint => false,
            _ => {
                self.seen
                    .insert(path.to_path_buf(), fingerprint.to_string());
                true
            }
        }
    }

    /// Forgets a path, so its next divergence is reported again. Used after a
    /// successful remediation, since the file is back to its approved state.
    fn forget(&mut self, path: &Path) {
        self.seen.remove(path);
    }
}

/// Runs a reconciliation sweep and records whatever it finds.
fn run_sweep(
    reason: SweepReason,
    db: &BaselineDb,
    policy: &CompiledPolicy,
    guard: &mut RemediationGuard,
    cfg: &SensorConfig,
    reported: &mut ReportedState,
) {
    let roots = policy.policy().get_monitored_roots();
    if roots.is_empty() {
        return;
    }

    println!("[*] Reconciliation sweep starting ({})", reason);
    let started = Instant::now();

    let mut hasher = StreamHasher::new(cfg.hash_algorithm, TokenBucket::new(cfg.rate_bytes));
    let outcome = match reconcile(db, policy, &roots, &mut hasher) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("[!] Reconciliation sweep failed: {}", e);
            return;
        }
    };

    let whodata = ProcessContext::for_observed_event();
    let ts_nano = unix_now_nanos();
    let mut suppressed = 0usize;

    for finding in &outcome.findings {
        if !reported.is_new(&finding.path, &finding.current.sha256) {
            suppressed += 1;
            continue;
        }

        println!(
            "\n[!] SWEEP DIVERGENCE on {} ({} change(s) the watcher did not report)",
            finding.path.display(),
            finding.changes.len()
        );
        print_change_alert(&finding.path, finding.severity, &whodata, &finding.changes);

        for change in &finding.changes.changes {
            let mut spool =
                create_spool_event_for(change, &finding.path, finding.severity, &whodata, ts_nano);
            // Mark the provenance: a divergence found by sweep means a real-time event
            // was missed, which matters to an investigator.
            spool.diff_snippet = Some(format!("[{}] {}", reason.label(), change.describe()));
            record_event(db, &mut spool, &cfg.hmac_key);
        }

        if finding.changes.is_substantive() {
            if let Some(rule) = policy.find_matching_rule(&finding.path) {
                // Only clear the suppression when the file was genuinely restored. If
                // remediation is disabled or declined, the divergence is still
                // outstanding and must stay suppressed rather than being re-announced
                // on every sweep.
                if apply_remediation(&finding.path, rule, guard, cfg, db) {
                    reported.forget(&finding.path);
                }
            }
        }
    }

    for missing in &outcome.missing {
        if !reported.is_new(&missing.baseline.path, "<deleted>") {
            suppressed += 1;
            continue;
        }
        println!(
            "\n[!] SWEEP DIVERGENCE: {} is in the baseline but missing from disk",
            missing.baseline.path.display()
        );
        let mut spool = create_spool_event(
            "FILE_DELETED",
            &missing.baseline.path,
            missing.severity,
            &whodata,
            ts_nano,
            Some(missing.baseline.sha256.clone()),
            None,
        );
        spool.diff_snippet = Some(format!("[{}] file no longer present", reason.label()));
        record_event(db, &mut spool, &cfg.hmac_key);
    }

    for added in &outcome.unbaselined {
        if !reported.is_new(&added.path, &added.sha256) {
            suppressed += 1;
            continue;
        }
        println!(
            "\n[!] SWEEP DIVERGENCE: unbaselined file present at {}",
            added.path.display()
        );
        let mut spool = create_spool_event(
            "FILE_CREATED",
            &added.path,
            5,
            &whodata,
            ts_nano,
            None,
            Some(added.sha256.clone()),
        );
        spool.diff_snippet = Some(format!("[{}] not present in baseline", reason.label()));
        record_event(db, &mut spool, &cfg.hmac_key);
    }

    for (path, err) in &outcome.errors {
        eprintln!("[!] Sweep could not read {}: {}", path.display(), err);
    }

    // Suppression is reported, never hidden. The operator must be able to tell
    // "nothing is wrong" from "the same thing is still wrong and I have stopped
    // repeating myself".
    let suppression_note = if suppressed > 0 {
        format!(
            ", {} unchanged divergence(s) still outstanding (already reported)",
            suppressed
        )
    } else {
        String::new()
    };

    println!(
        "[*] Reconciliation sweep complete in {:.1}s: {}{}",
        started.elapsed().as_secs_f64(),
        outcome.summary(),
        suppression_note
    );
}

/// Periodic liveness beacon.
///
/// Without this, "the agent was stopped by an attacker" and "nothing happened" look
/// identical in the audit log: both are an absence of events. A regular signed
/// heartbeat turns a coverage gap into a visible gap.
fn emit_heartbeat(db: &BaselineDb, cfg: &SensorConfig) {
    record_bare_event(
        db,
        EVENT_HEARTBEAT,
        Path::new("<sensor>"),
        1,
        Some("sensor alive".to_string()),
        &cfg.hmac_key,
    );
}

/// Keeps the spool inside its configured quota (RSK-03).
fn enforce_spool_quota(db: &BaselineDb, cfg: &SensorConfig) {
    if cfg.max_spool_bytes == 0 {
        return;
    }
    match db.prune_spool_to_quota(cfg.max_spool_bytes) {
        Ok(0) => {}
        Ok(removed) => {
            println!(
                "[*] Spool exceeded its {} MB quota; pruned {} already-forwarded event(s).",
                cfg.max_spool_bytes / (1024 * 1024),
                removed
            );
            // Record what was dropped. Pruning rows makes chain verification report
            // truncation, which is correct: the rows really are gone. This event is the
            // explanation an auditor needs, and it is itself chained.
            record_bare_event(
                db,
                EVENT_SPOOL_PRUNED,
                Path::new("<spool>"),
                7,
                Some(format!(
                    "pruned {} forwarded event(s) to stay within the {} MB quota; \
                     chain verification will report truncation from this point",
                    removed,
                    cfg.max_spool_bytes / (1024 * 1024)
                )),
                &cfg.hmac_key,
            );
        }
        Err(e) => eprintln!("[!] Could not enforce the spool quota: {}", e),
    }
}

/// Records an operational event that is not tied to a monitored file.
fn record_bare_event(
    db: &BaselineDb,
    event_type: &str,
    path: &Path,
    severity: u32,
    detail: Option<String>,
    hmac_key: &[u8],
) {
    let whodata = ProcessContext::for_observed_event();
    let mut spool = create_spool_event(
        event_type,
        path,
        severity,
        &whodata,
        unix_now_nanos(),
        None,
        None,
    );
    spool.diff_snippet = detail;
    record_event(db, &mut spool, hmac_key);
}

/// Indents a multi-line block so a diff reads as part of the alert rather than as
/// loose output that could be confused with the agent's own logging.
fn indent_block(text: &str) -> String {
    text.lines()
        .map(|l| format!("      {}", l))
        .collect::<Vec<_>>()
        .join("\n")
}

fn unix_now_nanos() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as i64
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

                    // Content diff, resolved once per path. `nodiff` is honoured inside
                    // `resolve_diff`, before any file content is read into memory.
                    let content_diff = if changes
                        .changes
                        .iter()
                        .any(|c| matches!(c, ChangeKind::Content { .. }))
                    {
                        Some(resolve_diff(rule, path, cfg))
                    } else {
                        None
                    };
                    if let Some(ref outcome) = content_diff {
                        match outcome.diff() {
                            Some(text) => println!("    Diff:\n{}", indent_block(text)),
                            None => println!("    Diff:       {}", outcome.explain()),
                        }
                    }

                    // Every observed difference is recorded separately, so the audit
                    // trail shows which controls fired rather than collapsing a
                    // content change and a permission change into one vague event.
                    for change in &changes.changes {
                        let mut spool =
                            create_spool_event_for(change, path, rule.severity, &whodata, ts_nano);

                        // Attach the diff only to the content event, and only when one
                        // was actually captured. Otherwise record the explanation, so an
                        // absent diff is never mistaken for an absent change.
                        if matches!(change, ChangeKind::Content { .. }) {
                            if let Some(ref outcome) = content_diff {
                                spool.diff_snippet = Some(match outcome.diff() {
                                    Some(text) => text.to_string(),
                                    None => outcome.explain().to_string(),
                                });
                            }
                        }

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

/// Returns whether remediation actually restored the file to its approved state.
///
/// The return value matters: callers use it to decide whether a divergence has been
/// resolved. Treating a declined or disabled remediation as a resolution would clear
/// the suppression state and make the same unresolved divergence be re-announced on
/// every sweep.
fn apply_remediation(
    path: &Path,
    rule: &PolicyRule,
    guard: &mut RemediationGuard,
    cfg: &SensorConfig,
    db: &BaselineDb,
) -> bool {
    if !cfg.remediation {
        return false;
    }
    match guard.execute(rule.active_response.action, path, cfg.backup.as_ref()) {
        Ok(outcome) => {
            println!("    [REMEDIATION] {}", outcome);
            if outcome.was_applied() {
                reanchor_after_restore(path, cfg, db);
                true
            } else {
                false
            }
        }
        Err(e) => {
            eprintln!("    [REMEDIATION] failed: {}", e);
            false
        }
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

/// Resolves a content diff for a change, honouring `nodiff` before reading anything.
///
/// The previous bytes come from the backup store's pristine copy, which is the only
/// place they exist: the baseline holds digests, not contents. With no store configured
/// the result explains that rather than silently omitting the detail.
///
/// Suppression is consulted first, so for a `nodiff` path no file content is read into
/// memory at all.
fn resolve_diff(rule: &PolicyRule, path: &Path, cfg: &SensorConfig) -> DiffOutcome {
    let path_str = path.to_string_lossy().to_string();

    // Check policy before touching the file. For a nodiff path there is no window in
    // which its contents exist destined for the database.
    if rule.nodiff_effective(&path_str) {
        return DiffOutcome::SuppressedByPolicy;
    }

    let store = match cfg.backup.as_ref() {
        Some(s) => s,
        None => return DiffOutcome::NoPreviousContent,
    };
    let entry = match store.lookup(path) {
        Some(e) => e,
        None => return DiffOutcome::NoPreviousContent,
    };

    let old = match std::fs::read(store.object_path(&entry.sha256)) {
        Ok(bytes) => bytes,
        Err(_) => return DiffOutcome::NoPreviousContent,
    };
    let new = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(_) => return DiffOutcome::NoPreviousContent,
    };

    openfim_common::capture_for_rule(rule, &path_str, &old, &new)
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
            heartbeat_secs: 300,
            append_only_spool: false,
            backup_dir: None,
        }
    }

    #[test]
    fn reported_state_suppresses_repeats_but_not_new_states() {
        // An unresolved divergence must be announced once, not on every sweep: in a
        // live test with a 2s interval the same finding was re-reported every cycle,
        // and each repeat is a chained spool event, so the spool fills with noise.
        let mut reported = ReportedState::default();
        let path = Path::new("/etc/app.conf");

        assert!(
            reported.is_new(path, "digest-a"),
            "first observation is new"
        );
        assert!(
            !reported.is_new(path, "digest-a"),
            "the same unchanged state must be suppressed"
        );
        assert!(
            !reported.is_new(path, "digest-a"),
            "suppression must persist across sweeps"
        );

        // A genuinely different state is reported immediately. Nothing is hidden.
        assert!(
            reported.is_new(path, "digest-b"),
            "a new state must be reported even though the path was seen before"
        );
        assert!(!reported.is_new(path, "digest-b"));
    }

    #[test]
    fn reported_state_tracks_paths_independently() {
        let mut reported = ReportedState::default();
        assert!(reported.is_new(Path::new("/a"), "d1"));
        assert!(
            reported.is_new(Path::new("/b"), "d1"),
            "a different path with the same digest is a separate finding"
        );
        assert!(!reported.is_new(Path::new("/a"), "d1"));
    }

    #[test]
    fn forgetting_a_path_allows_it_to_be_reported_again() {
        // Called only after a *successful* restore: the file is back to its approved
        // state, so the next divergence there is genuinely new. Clearing it after a
        // declined or disabled remediation was a bug that defeated suppression
        // entirely.
        let mut reported = ReportedState::default();
        let path = Path::new("/etc/app.conf");

        assert!(reported.is_new(path, "tampered"));
        assert!(!reported.is_new(path, "tampered"));

        reported.forget(path);
        assert!(
            reported.is_new(path, "tampered"),
            "after remediation restores the file, a fresh tamper must be reported"
        );
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
