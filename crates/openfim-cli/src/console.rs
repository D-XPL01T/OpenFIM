use std::fs;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};

use openfim_common::{
    BaselineDb, CrawlOptions, FileCrawler, FileMetadata, HashAlgorithm, Policy, PolicySigner,
    PolicyVerifier, StreamHasher, TokenBucket,
};

// ANSI Color Escape Sequences
#[allow(dead_code)]
pub const RESET: &str = "\x1b[0m";
#[allow(dead_code)]
pub const BOLD: &str = "\x1b[1m";
#[allow(dead_code)]
pub const RED: &str = "\x1b[1;31m";
#[allow(dead_code)]
pub const GREEN: &str = "\x1b[1;32m";
#[allow(dead_code)]
pub const YELLOW: &str = "\x1b[1;33m";
#[allow(dead_code)]
pub const BLUE: &str = "\x1b[1;34m";
#[allow(dead_code)]
pub const MAGENTA: &str = "\x1b[1;35m";
#[allow(dead_code)]
pub const CYAN: &str = "\x1b[1;36m";
#[allow(dead_code)]
pub const WHITE: &str = "\x1b[1;37m";
#[allow(dead_code)]
pub const DIM: &str = "\x1b[2m";

#[cfg(windows)]
pub fn enable_ansi_support() {
    unsafe {
        use std::ffi::c_void;
        #[link(name = "kernel32")]
        extern "system" {
            fn GetStdHandle(nStdHandle: u32) -> *mut c_void;
            fn GetConsoleMode(hConsoleHandle: *mut c_void, lpMode: *mut u32) -> i32;
            fn SetConsoleMode(hConsoleHandle: *mut c_void, dwMode: u32) -> i32;
        }
        const STD_OUTPUT_HANDLE: u32 = 0xFFFFFFF5;
        const ENABLE_VIRTUAL_TERMINAL_PROCESSING: u32 = 0x0004;

        let handle = GetStdHandle(STD_OUTPUT_HANDLE);
        if !handle.is_null() {
            let mut mode: u32 = 0;
            if GetConsoleMode(handle, &mut mode) != 0 {
                SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
            }
        }
    }
}

#[cfg(not(windows))]
pub fn enable_ansi_support() {}

// Metasploit-Replica Stylized ASCII Banners
const BANNERS: &[&str] = &[
    r#"
      _______________________________________________________
     < OpenFIM: Endpoint File Integrity & Intrusion Defense  >
      -------------------------------------------------------
             \   ^__^
              \  (oo)\_______
                 (__)\       )\/\
                     ||----w |
                     ||     ||
    "#,
    r#"
    ______________________________________________________________________________
   |                                                                              |
   |    ______                       ______ _____ __  __                          |
   |   / ____ \                     / ____//_  _//  |/  /                         |
   |  / /    \ \ ____  ___  ____   / /_     / / / /|_/ /                          |
   | / /      \ \_  _// _ \/ _  \ / __/    / / / /  / /                           |
   | \ \____  / /  / //  __// / / // /     _/ /_/ /  / /                            |
   |  \______/ /  /_/ \___//_/ /_//_/     /___//_/  /_/     v0.1.0-release        |
   |______________________________________________________________________________|
    "#,
    r#"
       +-------------------------------------------------------+
       |  __    ___  ____  _  _  ____  ____  __  __            |
       | /  \  (  ,\(  __)( \( )(  __)(_  _)(  \/  )           |
       |/ () \  ) _/ ) _)  )  (  ) _)  _)(_  )    (            |
       |_/\_/  (_)  (____)(_)\_)(_)   (____)(_/\/\_)           |
       |                                                       |
       |  Advanced Endpoint Integrity & Active Remediation     |
       +-------------------------------------------------------+
    "#,
];

const QUOTES: &[&str] = &[
    "Trust, but cryptographically verify with SHA-256 and Ed25519.",
    "Watching your filesystem so adversaries cannot live in the dark.",
    "There is no patch for human curiosity, but there is OpenFIM for file integrity.",
    "Defending critical endpoints since sequence #1.",
    "Zero external egress. Air-gapped compliance for PCI DSS 11.5 & NIST 800-53 SI-7.",
];

/// RAII Guard for Terminal Raw Mode
struct RawModeGuard {
    active: bool,
}

impl RawModeGuard {
    fn new() -> Self {
        if io::stdin().is_terminal() && enable_raw_mode().is_ok() {
            return Self { active: true };
        }
        Self { active: false }
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        if self.active {
            let _ = disable_raw_mode();
        }
    }
}

/// Possible outcomes of interactive line reading
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputResult {
    Value(String),
    GoBack,
    Exit,
}

/// Reads interactive input character-by-character with live Backspace navigation
pub fn read_input(
    prompt_label: &str,
    default: Option<&str>,
    can_go_back: bool,
) -> io::Result<InputResult> {
    match default {
        Some(d) => print!("{}{} [{}]:{} ", WHITE, prompt_label, d, RESET),
        None => {
            let t = prompt_label.trim();
            if t.ends_with('>') || t.ends_with(':') {
                print!("{}{} ", WHITE, prompt_label);
            } else {
                print!("{}{}:{} ", WHITE, prompt_label, RESET);
            }
        }
    }
    io::stdout().flush()?;

    // Fallback for non-interactive / piped input
    if !io::stdin().is_terminal() {
        let mut line = String::new();
        if io::stdin().read_line(&mut line)? == 0 {
            return Ok(InputResult::Exit);
        }
        let trimmed = line.trim().trim_start_matches('\u{feff}');
        let is_backspace_input = trimmed == "\x08"
            || trimmed == "\x7f"
            || trimmed.contains('\x08')
            || trimmed.eq_ignore_ascii_case("back")
            || trimmed.eq_ignore_ascii_case("b");

        if is_backspace_input {
            if can_go_back {
                return Ok(InputResult::GoBack);
            } else {
                // On main menu (no prior input given): backspace does not work
                return Ok(InputResult::Value(String::new()));
            }
        }

        if trimmed.is_empty() {
            return Ok(InputResult::Value(default.unwrap_or("").to_string()));
        } else {
            return Ok(InputResult::Value(trimmed.to_string()));
        }
    }

    let _guard = RawModeGuard::new();
    let mut buffer = String::new();

    loop {
        if let Event::Key(KeyEvent {
            code,
            modifiers,
            kind,
            ..
        }) = event::read()?
        {
            if kind != KeyEventKind::Press {
                continue;
            }

            match code {
                KeyCode::Enter => {
                    print!("\r\n");
                    io::stdout().flush()?;
                    let trimmed = buffer.trim();
                    if trimmed.is_empty() {
                        return Ok(InputResult::Value(default.unwrap_or("").to_string()));
                    } else {
                        return Ok(InputResult::Value(trimmed.to_string()));
                    }
                }
                KeyCode::Backspace => {
                    if !buffer.is_empty() {
                        buffer.pop();
                        print!("\x08 \x08");
                        io::stdout().flush()?;
                    } else if can_go_back {
                        // Buffer is empty and we are in a sub-menu or operation:
                        // Navigate back to previous menu!
                        print!("\r\n");
                        io::stdout().flush()?;
                        return Ok(InputResult::GoBack);
                    } else {
                        // At main menu (no prior input given):
                        // Backspace does NOT work. Stay at prompt.
                    }
                }
                KeyCode::Esc => {
                    if can_go_back {
                        print!("\r\n");
                        io::stdout().flush()?;
                        return Ok(InputResult::GoBack);
                    }
                }
                KeyCode::Char(c) => {
                    if modifiers.contains(KeyModifiers::CONTROL) && (c == 'c' || c == 'C') {
                        print!("\r\n");
                        io::stdout().flush()?;
                        return Ok(InputResult::Exit);
                    }
                    buffer.push(c);
                    print!("{}", c);
                    io::stdout().flush()?;
                }
                _ => {}
            }
        }
    }
}

/// Helper to prompt for user input with Backspace navigation
pub fn prompt_input(
    label: &str,
    default: Option<&str>,
    can_go_back: bool,
) -> io::Result<Option<String>> {
    match read_input(label, default, can_go_back)? {
        InputResult::Value(v) => Ok(Some(v)),
        InputResult::GoBack => Ok(None),
        InputResult::Exit => {
            println!("\n{}[*] Terminating OpenFIM Console.{}\n", YELLOW, RESET);
            std::process::exit(0);
        }
    }
}

/// Helper to prompt for a yes/no confirmation with Backspace navigation
pub fn prompt_confirm(
    label: &str,
    default_yes: bool,
    can_go_back: bool,
) -> io::Result<Option<bool>> {
    let suffix = if default_yes { "[Y/n]" } else { "[y/N]" };
    let full_label = format!("{} {}", label, suffix);
    match read_input(
        &full_label,
        Some(if default_yes { "y" } else { "n" }),
        can_go_back,
    )? {
        InputResult::Value(v) => {
            let lower = v.trim().to_lowercase();
            if lower.is_empty() {
                Ok(Some(default_yes))
            } else if lower == "y" || lower == "yes" {
                Ok(Some(true))
            } else {
                Ok(Some(false))
            }
        }
        InputResult::GoBack => Ok(None),
        InputResult::Exit => {
            println!("\n{}[*] Terminating OpenFIM Console.{}\n", YELLOW, RESET);
            std::process::exit(0);
        }
    }
}

/// Helper to pause and return to previous menu on Enter or Backspace
pub fn prompt_press_enter() {
    print!(
        "\n{}Press [Enter] or [Backspace] to return to previous menu...{}",
        DIM, RESET
    );
    let _ = io::stdout().flush();

    if !io::stdin().is_terminal() {
        let mut line = String::new();
        let _ = io::stdin().read_line(&mut line);
        return;
    }

    let _guard = RawModeGuard::new();
    loop {
        if let Ok(Event::Key(key)) = event::read() {
            if key.kind == KeyEventKind::Press
                && matches!(key.code, KeyCode::Enter | KeyCode::Backspace | KeyCode::Esc)
            {
                print!("\r\n");
                let _ = io::stdout().flush();
                break;
            }
        }
    }
}

/// Displays the Metasploit-style dynamic header and statistics
fn print_banner_and_stats() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let banner_idx = (now as usize) % BANNERS.len();
    let quote_idx = (now as usize) % QUOTES.len();

    println!("{}{}{}", CYAN, BANNERS[banner_idx], RESET);
    println!("  \"{}\"\n", QUOTES[quote_idx]);

    // Inspect local status
    let db_path = Path::new("openfim.db");
    let db_info = if db_path.exists() {
        match BaselineDb::open(db_path) {
            Ok(db) => match db.count_entries() {
                Ok(c) => format!("{} ({} baseline records registered)", db_path.display(), c),
                Err(_) => format!("{} (Active)", db_path.display()),
            },
            Err(_) => "Error reading openfim.db".to_string(),
        }
    } else {
        "No baseline database loaded (Run option 2 to setup)".to_string()
    };

    let policy_path = Path::new("policy.yaml");
    let policy_info = if policy_path.exists() {
        match Policy::from_yaml_file(policy_path) {
            Ok(p) => format!("{} ({} active rules)", policy_path.display(), p.rules.len()),
            Err(_) => format!("{} (Syntax error)", policy_path.display()),
        }
    } else {
        "None (Run option 2 to generate)".to_string()
    };

    println!(
        "{}=[{}{} OpenFIM Defensive Console v0.1.0-release{}             ]",
        BOLD, CYAN, RESET, BOLD
    );
    println!("+ -- --=[ Engine: Cryptographic Streaming Hash & TOCTOU Proof    ]");
    println!("+ -- --=[ Database: {:<45}]", db_info);
    println!("+ -- --=[ Policy:   {:<45}]", policy_info);
    println!(
        "+ -- --=[ Compliance: PCI DSS 11.5 | NIST 800-53 SI-7 Audit Chain  ]{}",
        RESET
    );
    println!();
}

/// Prints the main menu options
fn print_menu() {
    println!("{}Core Operations:{}", BOLD, RESET);
    println!(
        "  {}[1]{} Quick File Check       {}-- On-demand tamper detection, baseline diff & WhoData{}",
        GREEN, RESET, DIM, RESET
    );
    println!(
        "  {}[2]{} Setup Protection       {}-- Sub-menu: keys, policy, signing & baseline snapshot{}",
        GREEN, RESET, DIM, RESET
    );
    println!(
        "  {}[3]{} Monitor & Remediate    {}-- Real-time watcher daemon with automated active rollback{}",
        GREEN, RESET, DIM, RESET
    );
    println!(
        "  {}[4]{} Forensics & Audit Log  {}-- Cryptographic HMAC tamper audit & intrusion events{}",
        GREEN, RESET, DIM, RESET
    );
    println!(
        "  {}[5]{} Exit Console           {}-- Terminate program{}",
        GREEN, RESET, DIM, RESET
    );
    println!();
}

/// Main Interactive Metasploit-Style Console Loop
pub fn run_interactive_console() -> Result<(), Box<dyn std::error::Error>> {
    enable_ansi_support();
    print_banner_and_stats();
    print_menu();

    let mut failed_attempts = 0;

    loop {
        // can_go_back = false on Main Menu (no prior input given)
        let prompt_str = format!("{}{}openfim{} > ", BOLD, CYAN, RESET);
        let input_res = read_input(&prompt_str, None, false)?;

        let input = match input_res {
            InputResult::Value(v) => v,
            InputResult::GoBack => {
                // Backspace on main menu with no prior input does NOT work
                continue;
            }
            InputResult::Exit => {
                println!(
                    "\n{}[*] Exiting OpenFIM Console. Stay secure!{}\n",
                    YELLOW, RESET
                );
                break;
            }
        };

        if input.is_empty() {
            continue;
        }

        match input.as_str() {
            "1" => {
                failed_attempts = 0;
                op_quick_file_check()?;
                println!();
                print_menu();
            }
            "2" => {
                failed_attempts = 0;
                op_setup_protection_menu()?;
                println!();
                print_banner_and_stats();
                print_menu();
            }
            "3" => {
                failed_attempts = 0;
                op_monitor_and_remediate()?;
                println!();
                print_menu();
            }
            "4" => {
                failed_attempts = 0;
                op_forensics_and_audit()?;
                println!();
                print_menu();
            }
            "5" | "exit" | "quit" => {
                println!(
                    "\n{}[*] Terminating OpenFIM Console. Security monitoring session ended.{}\n",
                    YELLOW, RESET
                );
                std::process::exit(0);
            }
            invalid => {
                failed_attempts += 1;
                println!(
                    "{}[-] Invalid selection: '{}'. Please enter a valid number (1-5). (Attempt {}/3){}",
                    RED, invalid, failed_attempts, RESET
                );

                if failed_attempts >= 3 {
                    println!(
                        "\n{}[!] Maximum attempts reached (3/3). Security lockout initiated. Terminating console.{}\n",
                        RED, RESET
                    );
                    std::process::exit(1);
                }
            }
        }
    }

    Ok(())
}

/// Operation 1: Quick File Check (with Backspace return support)
fn op_quick_file_check() -> Result<(), Box<dyn std::error::Error>> {
    println!(
        "\n{}======================================================================{}",
        CYAN, RESET
    );
    println!(
        "{}               [1] QUICK FILE INTEGRITY INSPECTION                    {}",
        BOLD, RESET
    );
    println!(
        "{}======================================================================{}",
        CYAN, RESET
    );
    println!(
        "{}Tip: Press [Backspace] at any prompt to return to Main Menu.{}",
        DIM, RESET
    );

    let target_str = match prompt_input("Target file to inspect", None, true)? {
        Some(s) => s,
        None => {
            println!(
                "{}[*] Backspace pressed. Returning to Main Menu...{}",
                CYAN, RESET
            );
            return Ok(());
        }
    };

    if target_str.is_empty() {
        println!(
            "{}[-] Target file cannot be blank. Aborting inspection.{}",
            RED, RESET
        );
        prompt_press_enter();
        return Ok(());
    }

    let target_path = PathBuf::from(&target_str);
    let db_default = if Path::new("openfim.db").exists() {
        "openfim.db"
    } else {
        ""
    };
    let db_str = match prompt_input("Baseline SQLite database", Some(db_default), true)? {
        Some(s) => s,
        None => {
            println!(
                "{}[*] Backspace pressed. Returning to Main Menu...{}",
                CYAN, RESET
            );
            return Ok(());
        }
    };

    let pol_default = if Path::new("policy.yaml").exists() {
        "policy.yaml"
    } else {
        ""
    };
    let pol_str = match prompt_input("Security policy file", Some(pol_default), true)? {
        Some(s) => s,
        None => {
            println!(
                "{}[*] Backspace pressed. Returning to Main Menu...{}",
                CYAN, RESET
            );
            return Ok(());
        }
    };

    let db_path = if !db_str.is_empty() && Path::new(&db_str).exists() {
        Some(PathBuf::from(db_str))
    } else {
        None
    };

    let pol_path = if !pol_str.is_empty() && Path::new(&pol_str).exists() {
        Some(PathBuf::from(pol_str))
    } else {
        None
    };

    println!(
        "\n{}--- INSPECTION REPORT FOR: {} ---{}",
        BOLD,
        target_path.display(),
        RESET
    );

    let exists = target_path.exists();
    let mut hasher = StreamHasher::default_sha256();

    let current_meta = if exists && target_path.is_file() {
        match FileMetadata::extract(&target_path, &mut hasher) {
            Ok(m) => Some(m),
            Err(e) => {
                println!("{}[!] Error reading file: {}{}", RED, e, RESET);
                None
            }
        }
    } else if exists && target_path.is_dir() {
        println!("File Type:           Directory");
        None
    } else {
        println!(
            "{}File Status:         MISSING / DELETED (Not on disk){}",
            RED, RESET
        );
        None
    };

    if let Some(ref m) = current_meta {
        println!("File Status:         {}PRESENT ON DISK{}", GREEN, RESET);
        println!("File Size:           {} bytes", m.st_size);
        println!("Permissions / Mode:  {}", crate::format_mode(m.st_mode));
        println!(
            "Last Modified Time:  Unix timestamp {} (ctime: {})",
            m.st_mtime, m.st_ctime
        );
        println!("Computed SHA-256:    {}{}{}", GREEN, m.sha256, RESET);
        if let Some(ref b3) = m.blake3 {
            println!("Computed BLAKE3:     {}", b3);
        }
    }

    // Baseline Comparison
    let mut loaded_db = None;
    if let Some(ref p) = db_path {
        println!("\n[2] BASELINE DATABASE COMPARISON ({})", p.display());
        match BaselineDb::open(p) {
            Ok(bdb) => {
                match bdb.get_entry(&target_path) {
                    Ok(Some(baseline)) => {
                        println!("    Baseline Status: REGISTERED IN BASELINE");
                        println!("    Baseline Size:   {} bytes", baseline.st_size);
                        println!("    Baseline SHA256: {}", baseline.sha256);

                        if let Some(ref cur) = current_meta {
                            let hash_match = cur.sha256 == baseline.sha256;
                            let meta_match =
                                cur.st_mode == baseline.st_mode && cur.st_uid == baseline.st_uid;

                            if hash_match && meta_match {
                                println!("    INTEGRITY CHECK: {}[✓] CLEAN & UNCOMPROMISED (Matches baseline snapshot){}", GREEN, RESET);
                            } else {
                                println!("    INTEGRITY CHECK: {}[!] TAMPERING / MODIFICATION DETECTED!{}", RED, RESET);
                                if !hash_match {
                                    println!("      {}-> Content Divergence: Hash modified since baseline snapshot!{}", RED, RESET);
                                    println!("         Expected: {}", baseline.sha256);
                                    println!("         Current:  {}", cur.sha256);
                                }
                                if !meta_match {
                                    println!("      {}-> Metadata Divergence: Permissions/ownership changed!{}", RED, RESET);
                                    println!(
                                        "         Expected Mode: {}, UID: {}",
                                        crate::format_mode(baseline.st_mode),
                                        baseline.st_uid
                                    );
                                    println!(
                                        "         Current Mode:  {}, UID: {}",
                                        crate::format_mode(cur.st_mode),
                                        cur.st_uid
                                    );
                                }
                            }
                        } else {
                            println!("    INTEGRITY CHECK: {}[!] FILE REMOVED (File was in baseline but is now deleted){}", RED, RESET);
                        }
                    }
                    Ok(None) => {
                        println!("    Baseline Status: {}[?] UNINDEXED (Not found in active baseline database){}", YELLOW, RESET);
                    }
                    Err(e) => println!("    Error querying baseline: {}", e),
                }
                loaded_db = Some(bdb);
            }
            Err(e) => println!("    Error opening baseline database: {}", e),
        }
    } else {
        println!("\n[2] BASELINE DATABASE COMPARISON: Skipped (no database provided)");
    }

    // Policy Governance
    if let Some(ref p) = pol_path {
        println!("\n[3] POLICY & SECURITY GOVERNANCE ({})", p.display());
        match Policy::from_yaml_file(p) {
            Ok(pol) => {
                if let Some(rule) = pol.find_matching_rule(&target_path) {
                    println!(
                        "    Governance:      {}[✓] MONITORED BY DEFENSIVE POLICY{}",
                        GREEN, RESET
                    );
                    println!("    Rule ID:         {}", rule.id);
                    println!("    Description:     {}", rule.description);
                    println!("    Threat Severity: {}/10", rule.severity);
                    println!("    Watch Mode:      {:?}", rule.mode);
                    println!("    WhoData Active:  {}", rule.whodata);
                    println!("    Active Response: {:?}", rule.active_response.action);
                } else {
                    println!("    Governance:      [-] NOT MONITORED (No matching rule)");
                }
            }
            Err(e) => println!("    Error loading policy: {}", e),
        }
    } else {
        println!("\n[3] POLICY & SECURITY GOVERNANCE: Skipped (no policy provided)");
    }

    // WhoData Forensic Trail
    if let Some(ref bdb) = loaded_db {
        println!("\n[4] FORENSIC WHODATA & AUDIT HISTORY (Local Spool)");
        match bdb.get_events_for_path(&target_path, 5) {
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
                        println!("      Type:          {}{}{}", RED, ev.event_type, RESET);
                        println!("      Severity:      {}/10", ev.severity);
                        println!("      Timestamp:     Unix nanos {}", ev.timestamp_nano);
                        if let Some(pid) = ev.whodata_pid {
                            println!(
                                "      Actor Process: PID {} (Executable: {:?}, Comm: {:?})",
                                pid,
                                ev.whodata_exe.as_deref().unwrap_or("unknown"),
                                ev.whodata_comm.as_deref().unwrap_or("unknown")
                            );
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
                            "      HMAC Status:   {}CHAINED (Signature: {}...){}",
                            GREEN,
                            &ev.hmac_signature[..ev.hmac_signature.len().min(16)],
                            RESET
                        );
                    }
                }
            }
            Err(e) => println!("    Error querying event spool: {}", e),
        }
    }

    println!(
        "{}======================================================================{}",
        CYAN, RESET
    );
    prompt_press_enter();
    Ok(())
}

/// Operation 2: Setup Protection Sub-Menu
fn op_setup_protection_menu() -> Result<(), Box<dyn std::error::Error>> {
    let mut failed_attempts = 0;

    loop {
        println!(
            "\n{}======================================================================{}",
            CYAN, RESET
        );
        println!(
            "{}               [2] SETUP ENDPOINT PROTECTION MENU                     {}",
            BOLD, RESET
        );
        println!(
            "{}======================================================================{}",
            CYAN, RESET
        );
        println!(
            "  {}[1]{} Generate Fresh Ed25519 Administrative Keys",
            GREEN, RESET
        );
        println!(
            "  {}[2]{} Create & Digitally Sign Security Policy",
            GREEN, RESET
        );
        println!("  {}[3]{} Ingest Baseline Snapshot Database", GREEN, RESET);
        println!(
            "  {}[4]{} Export Portable Manifests (.json & .sha256)",
            GREEN, RESET
        );
        println!(
            "  {}[5]{} Run Complete Guided Setup Wizard (All steps)",
            GREEN, RESET
        );
        println!(
            "  {}[6]{} Return to Main Menu {}[or press Backspace]{}",
            GREEN, RESET, DIM, RESET
        );
        println!();

        let choice_res = read_input(
            &format!("{}[setup]{} openfim >", CYAN, RESET),
            None,
            true, // can_go_back = true in sub-menu!
        )?;

        let choice = match choice_res {
            InputResult::Value(v) => v,
            InputResult::GoBack => {
                println!(
                    "{}[*] Backspace pressed. Returning to Main Menu...{}",
                    CYAN, RESET
                );
                break;
            }
            InputResult::Exit => {
                println!("\n{}[*] Terminating OpenFIM Console.{}\n", YELLOW, RESET);
                std::process::exit(0);
            }
        };

        if choice.is_empty() {
            continue;
        }

        match choice.as_str() {
            "1" => {
                failed_attempts = 0;
                sub_generate_keys()?;
            }
            "2" => {
                failed_attempts = 0;
                sub_create_policy()?;
            }
            "3" => {
                failed_attempts = 0;
                sub_baseline_snapshot()?;
            }
            "4" => {
                failed_attempts = 0;
                sub_export_manifests()?;
            }
            "5" => {
                failed_attempts = 0;
                op_setup_protection_wizard()?;
            }
            "6" | "back" | "b" => {
                println!("{}[*] Returning to Main Menu...{}", CYAN, RESET);
                break;
            }
            invalid => {
                failed_attempts += 1;
                println!(
                    "{}[-] Invalid selection: '{}'. Please enter a valid number (1-6) or press Backspace to return. (Attempt {}/3){}",
                    RED, invalid, failed_attempts, RESET
                );
                if failed_attempts >= 3 {
                    println!(
                        "\n{}[!] Maximum attempts reached (3/3). Security lockout initiated. Terminating console.{}\n",
                        RED, RESET
                    );
                    std::process::exit(1);
                }
            }
        }
    }

    Ok(())
}

/// Sub-operation: Generate Ed25519 Keys
fn sub_generate_keys() -> Result<(), Box<dyn std::error::Error>> {
    println!(
        "\n{}--- GENERATE ED25519 ADMINISTRATIVE KEYS ---{}",
        BOLD, RESET
    );
    let key_dir_str = match prompt_input("Key storage directory", Some("."), true)? {
        Some(s) => s,
        None => return Ok(()),
    };
    let key_dir = PathBuf::from(key_dir_str);
    fs::create_dir_all(&key_dir)?;

    let (signing_key, verifying_key) = PolicySigner::generate_keypair();
    let pub_hex = PolicySigner::pubkey_to_hex(&verifying_key);
    let priv_hex = PolicySigner::privkey_to_hex(&signing_key);

    let pub_path = key_dir.join("openfim_admin.pub");
    let priv_path = key_dir.join("openfim_admin.key");
    fs::write(&pub_path, &pub_hex)?;
    fs::write(&priv_path, &priv_hex)?;

    println!(
        "{}[+] Generated fresh Ed25519 administrative keys:{}",
        GREEN, RESET
    );
    println!("    Public Key:  {}", pub_path.display());
    println!("    Private Key: {}", priv_path.display());
    prompt_press_enter();
    Ok(())
}

/// Sub-operation: Create & Digitally Sign Policy
fn sub_create_policy() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n{}--- CREATE & DIGITALLY SIGN POLICY ---{}", BOLD, RESET);
    let target_dir_str = match prompt_input("Monitored directory path", Some("."), true)? {
        Some(s) => s,
        None => return Ok(()),
    };
    let pol_out_str = match prompt_input("Policy output filename", Some("policy.yaml"), true)? {
        Some(s) => s,
        None => return Ok(()),
    };
    let severity_str = match prompt_input("Threat severity level (1-10)", Some("9"), true)? {
        Some(s) => s,
        None => return Ok(()),
    };
    let severity = severity_str.parse::<u32>().unwrap_or(9);

    let remediation_choice = match prompt_input(
        "Active Response remediation action [1: none, 2: restore_baseline, 3: quarantine]",
        Some("2"),
        true,
    )? {
        Some(s) => s,
        None => return Ok(()),
    };
    let action_str = match remediation_choice.as_str() {
        "1" => "none",
        "3" => "quarantine",
        _ => "restore_baseline",
    };

    let priv_key_str = match prompt_input(
        "Admin private key (hex or path to .key)",
        Some("openfim_admin.key"),
        true,
    )? {
        Some(s) => s,
        None => return Ok(()),
    };
    let priv_key_hex = if Path::new(&priv_key_str).exists() {
        fs::read_to_string(&priv_key_str)?
    } else {
        priv_key_str
    };

    let norm_dir = openfim_common::normalize_path_str(Path::new(&target_dir_str));
    let policy_yaml = format!(
        r#"version: "1.0"
policy_id: "sec-guard-01"
name: "Protected Workspace Policy"
author: "Security Administrator"
signature_algorithm: "ed25519"
globals:
  default_hash: "sha256"
  max_io_rate_mb_s: 50
  realtime_fallback_sweep_interval: 10
rules:
  - id: "rule-protect-root"
    description: "Defend files in {} against unauthorized modification"
    paths:
      - "{}"
    recursive: true
    mode: "realtime"
    nodiff: false
    whodata: true
    severity: {}
    checks:
      hash: true
      size: true
      permissions: true
      ownership: true
      timestamps: true
      xattrs: false
    active_response:
      action: "{}"
"#,
        norm_dir, norm_dir, severity, action_str
    );

    let pol_path = PathBuf::from(&pol_out_str);
    fs::write(&pol_path, policy_yaml)?;

    let signing_key = PolicySigner::privkey_from_hex(priv_key_hex.trim())?;
    let sig = PolicySigner::sign_file(&pol_path, &signing_key)?;
    let sig_hex = PolicySigner::signature_to_hex(&sig);

    let sig_path = PathBuf::from(format!("{}.sig", pol_path.display()));
    fs::write(&sig_path, sig_hex)?;

    println!(
        "{}[+] Policy written and signed successfully: {}{}",
        GREEN,
        pol_path.display(),
        RESET
    );
    println!("{}[+] Signature: {}{}", GREEN, sig_path.display(), RESET);
    prompt_press_enter();
    Ok(())
}

/// Sub-operation: Capture Baseline Snapshot
fn sub_baseline_snapshot() -> Result<(), Box<dyn std::error::Error>> {
    println!(
        "\n{}--- INGEST BASELINE SNAPSHOT DATABASE ---{}",
        BOLD, RESET
    );
    let target_dir_str = match prompt_input("Directory root to crawl", Some("."), true)? {
        Some(s) => s,
        None => return Ok(()),
    };
    let db_out_str = match prompt_input("Baseline SQLite database path", Some("openfim.db"), true)?
    {
        Some(s) => s,
        None => return Ok(()),
    };

    let target_dir = PathBuf::from(target_dir_str);
    let db_path = PathBuf::from(db_out_str);
    let mut baseline_db = BaselineDb::open(&db_path)?;

    println!(
        "{}[*] Crawling target directory '{}' and computing SHA-256 hashes...{}",
        CYAN,
        target_dir.display(),
        RESET
    );
    let crawler = FileCrawler::new(CrawlOptions::default());
    let mut hasher = StreamHasher::default_sha256();
    let snapshot = crawler.crawl(&target_dir, &mut hasher)?;

    let count = baseline_db.insert_batch(&snapshot, "v1.0")?;
    println!(
        "{}[+] Indexed {} files into baseline database: {}{}",
        GREEN,
        count,
        db_path.display(),
        RESET
    );
    prompt_press_enter();
    Ok(())
}

/// Sub-operation: Export Portable Manifests
fn sub_export_manifests() -> Result<(), Box<dyn std::error::Error>> {
    println!(
        "\n{}--- EXPORT PORTABLE MANIFESTS FOR WEB GUI ---{}",
        BOLD, RESET
    );
    let db_str = match prompt_input("Baseline SQLite database", Some("openfim.db"), true)? {
        Some(s) => s,
        None => return Ok(()),
    };
    let baseline_db = BaselineDb::open(Path::new(&db_str))?;

    let json_manifest = baseline_db.export_manifest("json")?;
    let sha_manifest = baseline_db.export_manifest("sha256")?;
    fs::write("manifest.json", json_manifest)?;
    fs::write("manifest.sha256", sha_manifest)?;

    println!(
        "{}[+] Exported 'manifest.json' and 'manifest.sha256' for web/verifier.html{}",
        GREEN, RESET
    );
    prompt_press_enter();
    Ok(())
}

/// Complete Guided Setup Wizard
fn op_setup_protection_wizard() -> Result<(), Box<dyn std::error::Error>> {
    println!(
        "\n{}======================================================================{}",
        CYAN, RESET
    );
    println!(
        "{}               COMPLETE GUIDED SETUP WIZARD                           {}",
        BOLD, RESET
    );
    println!(
        "{}======================================================================{}",
        CYAN, RESET
    );
    println!(
        "{}Tip: Press [Backspace] at any prompt to return to previous menu.{}",
        DIM, RESET
    );

    // 1. Target Directory
    let target_dir_str = match prompt_input("Target directory root to protect", Some("."), true)? {
        Some(s) => s,
        None => return Ok(()),
    };
    let target_dir = PathBuf::from(&target_dir_str);
    if !target_dir.exists() {
        println!(
            "{}[-] Directory '{}' does not exist. Creating it now...{}",
            YELLOW,
            target_dir.display(),
            RESET
        );
        fs::create_dir_all(&target_dir)?;
    }

    // 2. Administrative Keys
    let gen_keys = match prompt_confirm(
        "Generate fresh Ed25519 administrative security keypair?",
        true,
        true,
    )? {
        Some(b) => b,
        None => return Ok(()),
    };

    let (pub_file, priv_key_hex) = if gen_keys {
        let key_dir_str = match prompt_input("Key storage directory", Some("."), true)? {
            Some(s) => s,
            None => return Ok(()),
        };
        let key_dir = PathBuf::from(key_dir_str);
        fs::create_dir_all(&key_dir)?;

        let (signing_key, verifying_key) = PolicySigner::generate_keypair();
        let pub_hex = PolicySigner::pubkey_to_hex(&verifying_key);
        let priv_hex = PolicySigner::privkey_to_hex(&signing_key);

        let pub_path = key_dir.join("openfim_admin.pub");
        let priv_path = key_dir.join("openfim_admin.key");
        fs::write(&pub_path, &pub_hex)?;
        fs::write(&priv_path, &priv_hex)?;

        println!(
            "{}[+] Generated and saved fresh Ed25519 keys:{}",
            GREEN, RESET
        );
        println!("    Public Key:  {}", pub_path.display());
        println!("    Private Key: {}", priv_path.display());
        (pub_path, priv_hex)
    } else {
        let pub_str = match prompt_input(
            "Path to existing public key (openfim_admin.pub)",
            Some("openfim_admin.pub"),
            true,
        )? {
            Some(s) => s,
            None => return Ok(()),
        };
        let priv_str = match prompt_input(
            "Existing private key (hex or path to .key)",
            Some("openfim_admin.key"),
            true,
        )? {
            Some(s) => s,
            None => return Ok(()),
        };
        let key_content = if Path::new(&priv_str).exists() {
            fs::read_to_string(&priv_str)?
        } else {
            priv_str
        };
        (PathBuf::from(pub_str), key_content.trim().to_string())
    };

    // 3. Declarative Policy
    let create_policy =
        match prompt_confirm("Create and sign security policy manifest?", true, true)? {
            Some(b) => b,
            None => return Ok(()),
        };

    let policy_path = if create_policy {
        let pol_out_str = match prompt_input("Policy output filename", Some("policy.yaml"), true)? {
            Some(s) => s,
            None => return Ok(()),
        };
        let severity_str = match prompt_input("Threat severity level (1-10)", Some("9"), true)? {
            Some(s) => s,
            None => return Ok(()),
        };
        let severity = severity_str.parse::<u32>().unwrap_or(9);

        let remediation_choice = match prompt_input(
            "Active Response remediation action [1: none, 2: restore_baseline, 3: quarantine]",
            Some("2"),
            true,
        )? {
            Some(s) => s,
            None => return Ok(()),
        };
        let action_str = match remediation_choice.as_str() {
            "1" => "none",
            "3" => "quarantine",
            _ => "restore_baseline",
        };

        let norm_dir = openfim_common::normalize_path_str(&target_dir);
        let policy_yaml = format!(
            r#"version: "1.0"
policy_id: "sec-guard-01"
name: "Protected Workspace Policy"
author: "Security Administrator"
signature_algorithm: "ed25519"
globals:
  default_hash: "sha256"
  max_io_rate_mb_s: 50
  realtime_fallback_sweep_interval: 10
rules:
  - id: "rule-protect-root"
    description: "Defend files in {} against unauthorized modification"
    paths:
      - "{}"
    recursive: true
    mode: "realtime"
    nodiff: false
    whodata: true
    severity: {}
    checks:
      hash: true
      size: true
      permissions: true
      ownership: true
      timestamps: true
      xattrs: false
    active_response:
      action: "{}"
"#,
            norm_dir, norm_dir, severity, action_str
        );

        let pol_path = PathBuf::from(pol_out_str);
        fs::write(&pol_path, policy_yaml)?;

        let signing_key = PolicySigner::privkey_from_hex(&priv_key_hex)?;
        let sig = PolicySigner::sign_file(&pol_path, &signing_key)?;
        let sig_hex = PolicySigner::signature_to_hex(&sig);

        let sig_path = PathBuf::from(format!("{}.sig", pol_path.display()));
        fs::write(&sig_path, sig_hex)?;

        if pub_file.exists() {
            let pub_hex = fs::read_to_string(&pub_file)?;
            let vk = PolicySigner::pubkey_from_hex(&pub_hex)?;
            PolicyVerifier::verify_file(&pol_path, &sig_path, &vk)?;
            println!(
                "{}[✓] Cryptographic Ed25519 Signature Verified: VALID & AUTHENTIC{}",
                GREEN, RESET
            );
        }

        println!(
            "{}[+] Created and digitally signed policy: {}{}",
            GREEN,
            pol_path.display(),
            RESET
        );
        pol_path
    } else {
        PathBuf::from("policy.yaml")
    };

    // 4. Baseline Snapshot
    let db_out_str = match prompt_input("Baseline SQLite database path", Some("openfim.db"), true)?
    {
        Some(s) => s,
        None => return Ok(()),
    };
    let db_path = PathBuf::from(db_out_str);
    let mut baseline_db = BaselineDb::open(&db_path)?;

    println!(
        "{}[*] Crawling target directory '{}' and computing SHA-256 hashes...{}",
        CYAN,
        target_dir.display(),
        RESET
    );
    let crawler = FileCrawler::new(CrawlOptions::default());
    let mut hasher = StreamHasher::default_sha256();
    let snapshot = crawler.crawl(&target_dir, &mut hasher)?;

    let count = baseline_db.insert_batch(&snapshot, "v1.0")?;
    println!(
        "{}[+] Successfully indexed {} files into baseline database: {}{}",
        GREEN,
        count,
        db_path.display(),
        RESET
    );

    // 5. Portable Manifests for Web GUI
    let export_web = match prompt_confirm(
        "Export portable manifests for Zero-Upload Web GUI?",
        true,
        true,
    )? {
        Some(b) => b,
        None => return Ok(()),
    };
    if export_web {
        let json_manifest = baseline_db.export_manifest("json")?;
        let sha_manifest = baseline_db.export_manifest("sha256")?;
        fs::write("manifest.json", json_manifest)?;
        fs::write("manifest.sha256", sha_manifest)?;
        println!(
            "{}[+] Exported 'manifest.json' and 'manifest.sha256' for web/verifier.html{}",
            GREEN, RESET
        );
    }

    println!(
        "\n{}======================================================================{}",
        GREEN, RESET
    );
    println!(
        "{}                 [✓] SETUP PROTECTION COMPLETED                      {}",
        BOLD, RESET
    );
    println!(
        "{}======================================================================{}",
        GREEN, RESET
    );
    println!("Summary:");
    println!("  Target Root:   {}", target_dir.display());
    println!("  Policy:        {} (Signed)", policy_path.display());
    println!("  Baseline DB:   {} ({} records)", db_path.display(), count);
    println!("  Web Verifier:  Ready (Open web/verifier.html in browser)");
    println!(
        "{}======================================================================{}",
        GREEN, RESET
    );

    prompt_press_enter();
    Ok(())
}

/// Operation 3: Monitor & Remediate (with Backspace return support)
fn op_monitor_and_remediate() -> Result<(), Box<dyn std::error::Error>> {
    println!(
        "\n{}======================================================================{}",
        CYAN, RESET
    );
    println!(
        "{}            [3] REAL-TIME SENSOR & REMEDIATION DAEMON                 {}",
        BOLD, RESET
    );
    println!(
        "{}======================================================================{}",
        CYAN, RESET
    );
    println!(
        "{}Tip: Press [Backspace] at any prompt to return to Main Menu.{}",
        DIM, RESET
    );

    let pol_str = match prompt_input("Security policy file", Some("policy.yaml"), true)? {
        Some(s) => s,
        None => return Ok(()),
    };
    let db_str = match prompt_input("Baseline SQLite database", Some("openfim.db"), true)? {
        Some(s) => s,
        None => return Ok(()),
    };
    let pub_str = match prompt_input(
        "Admin public key for policy verification",
        Some("openfim_admin.pub"),
        true,
    )? {
        Some(s) => s,
        None => return Ok(()),
    };
    let rem = match prompt_confirm(
        "Enable Automated Active Remediation (quarantine/rollback)?",
        true,
        true,
    )? {
        Some(b) => b,
        None => return Ok(()),
    };

    let backup_dir_str = if rem {
        match prompt_input(
            "Backup directory for baseline rollback",
            Some("backups"),
            true,
        )? {
            Some(s) => s,
            None => return Ok(()),
        }
    } else {
        String::new()
    };

    let current_exe = std::env::current_exe().unwrap_or_default();
    let exe_dir = current_exe.parent().unwrap_or_else(|| Path::new("."));

    #[cfg(windows)]
    let agent_name = "openfim-agent.exe";
    #[cfg(not(windows))]
    let agent_name = "openfim-agent";

    let candidate_paths = vec![
        exe_dir.join(agent_name),
        PathBuf::from(format!("target/debug/{}", agent_name)),
        PathBuf::from(format!("target/release/{}", agent_name)),
        PathBuf::from(agent_name),
    ];

    let agent_bin = candidate_paths.into_iter().find(|p| p.exists());

    if let Some(agent_path) = agent_bin {
        println!(
            "{}[*] Launching Real-Time Sensor Daemon: {}{}",
            GREEN,
            agent_path.display(),
            RESET
        );
        println!(
            "{}[*] Press [Ctrl+C] at any time to stop monitoring and return to console.{}\n",
            YELLOW, RESET
        );

        let mut cmd = std::process::Command::new(agent_path);
        cmd.arg("--config").arg(&pol_str);
        cmd.arg("--db").arg(&db_str);

        if Path::new(&pub_str).exists() {
            cmd.arg("--key").arg(&pub_str);
        }
        if rem {
            cmd.arg("--remediation");
            if !backup_dir_str.is_empty() {
                cmd.arg("--backup-dir").arg(&backup_dir_str);
            }
        }

        let _ = cmd.status();
        println!(
            "\n{}[*] Sensor daemon exited. Returning to OpenFIM console.{}",
            CYAN, RESET
        );
    } else {
        println!(
            "{}[!] 'openfim-agent' binary not found. Running in-process real-time sensor...{}",
            YELLOW, RESET
        );
        run_inprocess_sensor(
            &pol_str,
            &db_str,
            rem,
            if rem { Some(&backup_dir_str) } else { None },
        )?;
    }

    prompt_press_enter();
    Ok(())
}

/// Fallback in-process real-time watcher
fn run_inprocess_sensor(
    pol_file: &str,
    db_file: &str,
    remediation: bool,
    backup_dir: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    use openfim_common::notify::{self, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
    use std::sync::mpsc;
    use std::time::Duration;

    if !Path::new(pol_file).exists() {
        println!(
            "{}[!] Policy file '{}' does not exist.{}",
            RED, pol_file, RESET
        );
        return Ok(());
    }

    let policy = Policy::from_yaml_file(pol_file)?;
    let db = BaselineDb::open(db_file)?;

    println!(
        "{}[*] Loaded policy '{}' with {} rules.{}",
        GREEN,
        policy.policy_id,
        policy.rules.len(),
        RESET
    );
    println!(
        "{}[*] SQLite baseline active at '{}'.{}",
        GREEN, db_file, RESET
    );

    let (tx, rx) = mpsc::channel();
    let mut watcher = RecommendedWatcher::new(
        move |res| {
            if let Ok(event) = res {
                let _ = tx.send(event);
            }
        },
        notify::Config::default(),
    )?;

    for rule in &policy.rules {
        for path_str in &rule.paths {
            let p = Path::new(path_str);
            if p.exists() {
                let _ = watcher.watch(p, RecursiveMode::Recursive);
            }
        }
    }

    println!(
        "{}[*] Real-time sensor active. Watching filesystem...{}",
        CYAN, RESET
    );
    println!(
        "{}[*] Press Enter or Ctrl+C to stop monitoring.{}",
        YELLOW, RESET
    );

    // No built-in key: a shared constant would let anyone with the binary forge the
    // audit chain, and would also silently disagree with the key the agent daemon
    // signs with, so chains written here would fail `audit verify` there.
    let hmac_key = match resolve_console_audit_key()? {
        Some(k) => k,
        None => {
            println!(
                "{}[!] No HMAC key available, so events cannot be signed into the \
                 tamper-evident log. Set OPENFIM_HMAC_KEY and retry.{}",
                RED, RESET
            );
            return Ok(());
        }
    };

    // Open the pristine-copy store once, before the loop, and report a bad path up
    // front rather than mid-incident.
    let backup_store = match backup_dir.filter(|d| !d.is_empty()) {
        Some(dir) => match openfim_common::BackupStore::open_or_create(dir) {
            Ok(store) => {
                println!(
                    "{}[*] Backup store: {} ({} pristine copies indexed){}",
                    DIM,
                    dir,
                    store.len(),
                    RESET
                );
                Some(store)
            }
            Err(e) => {
                println!("{}[!] Backup store unusable: {}{}", RED, e, RESET);
                println!(
                    "{}[!] restore_baseline will decline rather than act on an unusable store.{}",
                    YELLOW, RESET
                );
                None
            }
        },
        None => None,
    };

    let mut debounce = std::collections::HashMap::new();
    let rate_bytes = 50 * 1024 * 1024;
    let mut guard = openfim_common::RemediationGuard::new(if remediation {
        openfim_common::DEFAULT_MAX_REMEDIATIONS_PER_HOUR
    } else {
        0
    });

    // Run for a bounded wall-clock session rather than a fixed iteration count.
    //
    // The previous `for _ in 0..100` with a 150 ms timeout meant the "real-time"
    // sensor quietly exited after about 15 seconds of calm, while still telling the
    // operator it was watching until they pressed a key.
    let session_limit = Duration::from_secs(120);
    let started = std::time::Instant::now();
    println!(
        "{}[*] In-process sensor session runs for up to {} seconds.{}",
        CYAN,
        session_limit.as_secs(),
        RESET
    );

    while started.elapsed() < session_limit {
        if let Ok(event) = rx.recv_timeout(Duration::from_millis(150)) {
            if !matches!(
                event.kind,
                EventKind::Modify(_) | EventKind::Create(_) | EventKind::Remove(_)
            ) {
                continue;
            }

            for path in event.paths {
                let rule = match policy.find_matching_rule(&path) {
                    Some(r) => r,
                    None => continue,
                };

                let now = std::time::Instant::now();
                if let Some(prev) = debounce.get(&path) {
                    if now.duration_since(*prev) < Duration::from_millis(300) {
                        continue;
                    }
                }
                debounce.insert(path.clone(), now);

                let whodata = openfim_common::ProcessContext::for_observed_event();
                let ts_nano = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos() as i64;

                if path.exists() && path.is_file() {
                    let mut hasher =
                        StreamHasher::new(HashAlgorithm::Sha256, TokenBucket::new(rate_bytes));
                    if let Ok(cur_meta) = FileMetadata::extract(&path, &mut hasher) {
                        if let Ok(Some(base_meta)) = db.get_entry(&path) {
                            // Shared detection engine. This block used to carry its own
                            // hash-only comparison, a second implementation of the same
                            // security decision that ignored every other check the rule
                            // enabled and could drift from the daemon's verdict.
                            let changes =
                                openfim_common::evaluate(&base_meta, &cur_meta, &rule.checks);

                            if !changes.is_clean() {
                                let headline = changes
                                    .most_severe()
                                    .map(|c| c.event_type())
                                    .unwrap_or("CHANGED");
                                println!(
                                    "\n{}[!] INTEGRITY ALERT: {} on {}{}",
                                    RED,
                                    headline,
                                    path.display(),
                                    RESET
                                );
                                for change in &changes.changes {
                                    println!("    [{}] {}", change.event_type(), change.describe());
                                }
                                if whodata.is_attributed {
                                    println!(
                                        "    Who-Data: PID={} Exe={:?}",
                                        whodata.pid, whodata.exe
                                    );
                                } else {
                                    println!(
                                        "    Who-Data: {}UNATTRIBUTED{} - the writing process could not be identified",
                                        YELLOW, RESET
                                    );
                                }

                                let attributed = whodata.is_attributed;
                                for (n, change) in changes.changes.iter().enumerate() {
                                    let (old_hash, new_hash) = change.hashes();
                                    let mut spool = openfim_common::SpoolEvent {
                                        sequence_id: None,
                                        // event_id is UNIQUE in the schema and one change
                                        // can yield several events in the same
                                        // nanosecond, so the index is part of the id.
                                        event_id: format!("evt-{}-{}", ts_nano, n),
                                        timestamp_nano: ts_nano,
                                        event_type: change.event_type().to_string(),
                                        path: openfim_common::normalize_path_str(&path),
                                        severity: rule.severity,
                                        // Leave these empty unless they really describe
                                        // the actor; otherwise every event would name
                                        // OpenFIM itself as the process that changed it.
                                        whodata_pid: attributed.then_some(whodata.pid),
                                        whodata_uid: if attributed { whodata.uid } else { None },
                                        whodata_comm: if attributed {
                                            whodata.comm.clone()
                                        } else {
                                            None
                                        },
                                        whodata_exe: if attributed {
                                            whodata.exe.clone()
                                        } else {
                                            None
                                        },
                                        whodata_cmdline: if attributed {
                                            whodata.cmdline.clone()
                                        } else {
                                            None
                                        },
                                        whodata_cgroup: None,
                                        old_sha256: old_hash.map(str::to_string),
                                        new_sha256: new_hash.map(str::to_string),
                                        diff_snippet: Some(change.describe()),
                                        hmac_signature: String::new(),
                                        sent_to_manager: false,
                                    };
                                    if let Err(e) =
                                        db.append_spool_event_chained(&mut spool, &hmac_key)
                                    {
                                        println!(
                                            "    {}[!] Failed to record this event to the audit chain: {}{}",
                                            RED, e, RESET
                                        );
                                    }
                                }

                                // Rollback only for content or object substitution; a
                                // metadata edit does not justify overwriting the file.
                                if remediation && changes.is_substantive() {
                                    match guard.execute(
                                        rule.active_response.action,
                                        &path,
                                        backup_store.as_ref(),
                                    ) {
                                        Ok(outcome) => println!(
                                            "    {}[REMEDIATION] {}{}",
                                            GREEN, outcome, RESET
                                        ),
                                        Err(e) => println!(
                                            "    {}[REMEDIATION] failed: {}{}",
                                            RED, e, RESET
                                        ),
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

/// Resolves the audit-chain HMAC key for interactive use.
///
/// Prefers `OPENFIM_HMAC_KEY` so the secret is not retyped into terminal scrollback,
/// and falls back to prompting. Returns `Ok(None)` when the operator supplies nothing
/// or navigates back; there is deliberately no default value.
fn resolve_console_audit_key() -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
    if let Ok(env_key) = std::env::var("OPENFIM_HMAC_KEY") {
        let trimmed = env_key.trim();
        if !trimmed.is_empty() {
            println!("{}[i] Using HMAC key from OPENFIM_HMAC_KEY.{}", DIM, RESET);
            return Ok(Some(trimmed.as_bytes().to_vec()));
        }
    }

    match prompt_input(
        "HMAC secret key (no default; or set OPENFIM_HMAC_KEY)",
        None,
        true,
    )? {
        Some(s) if !s.trim().is_empty() => Ok(Some(s.trim().as_bytes().to_vec())),
        _ => Ok(None),
    }
}

/// Operation 4: Forensics & Audit Log (with Backspace return support)
fn op_forensics_and_audit() -> Result<(), Box<dyn std::error::Error>> {
    println!(
        "\n{}======================================================================{}",
        CYAN, RESET
    );
    println!(
        "{}            [4] FORENSIC AUDIT & TAMPER-EVIDENT SPOOL                 {}",
        BOLD, RESET
    );
    println!(
        "{}======================================================================{}",
        CYAN, RESET
    );
    println!(
        "{}Tip: Press [Backspace] at any prompt to return to Main Menu.{}",
        DIM, RESET
    );

    let db_str = match prompt_input(
        "Baseline SQLite database to audit",
        Some("openfim.db"),
        true,
    )? {
        Some(s) => s,
        None => return Ok(()),
    };
    // Offered with no default. A shipped default key is a key every adversary also
    // has, which would make the "tamper-evident" chain forgeable at will.
    let key_str = match resolve_console_audit_key()? {
        Some(k) => k,
        None => {
            println!(
                "{}[-] No HMAC key provided; the audit chain cannot be verified without \
                 the key it was signed with.{}",
                RED, RESET
            );
            prompt_press_enter();
            return Ok(());
        }
    };

    let db_path = Path::new(&db_str);
    if !db_path.exists() {
        println!("{}[-] Database '{}' does not exist.{}", RED, db_str, RESET);
        prompt_press_enter();
        return Ok(());
    }

    let db = BaselineDb::open(db_path)?;

    println!(
        "{}[*] Cryptographically auditing HMAC chain and sequence continuity...{}",
        CYAN, RESET
    );
    let report = db.verify_spool_chain(&key_str)?;

    if report.is_valid {
        println!(
            "\n{}============================================================",
            GREEN
        );
        println!("  [✓] AUDIT PASSED: Tamper-Evident HMAC Chain is VALID      ");
        println!("  Total Events Verified:  {}", report.total_events);
        println!("  Sequence Continuity:    CONTIGUOUS (No gaps/deletions)    ");
        println!("  Cryptographic Status:   UNCOMPROMISED                     ");
        println!(
            "============================================================{}",
            RESET
        );
    } else {
        println!(
            "\n{}============================================================",
            RED
        );
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
        println!(
            "============================================================{}",
            RESET
        );
    }

    // Retrieve recent logged security events from the spool
    println!("\n{}Recent Event Spool Entries (Last 10):{}", BOLD, RESET);
    let events = db.get_unsent_spool_events(10)?;
    if events.is_empty() {
        println!("  No events logged in spool.");
    } else {
        for (i, ev) in events.iter().enumerate() {
            let seq = ev.sequence_id.unwrap_or(0);
            let p_name = ev.whodata_comm.as_deref().unwrap_or("system");
            let short_sig = &ev.hmac_signature[..ev.hmac_signature.len().min(12)];
            println!(
                "  [{:2}] Seq #{:<3} | {:<16} | Path: {:<25} | Actor: {:<12} | HMAC: {}",
                i + 1,
                seq,
                ev.event_type,
                ev.path,
                p_name,
                short_sig
            );
        }
    }

    prompt_press_enter();
    Ok(())
}
