use std::path::PathBuf;
use clap::Parser;
use openfim_common::{FileMetadata, HashAlgorithm, StreamHasher, TokenBucket};

#[derive(Parser, Debug)]
#[command(
    name = "openfim-agent",
    about = "OpenFIM Defensive Integrity Monitoring Endpoint Sensor",
    version
)]
struct Args {
    /// Path to the agent YAML configuration
    #[arg(short, long, default_value = "/etc/openfim/agent.yaml")]
    config: PathBuf,

    /// One-shot scan mode: inspect a single path and output JSON metadata
    #[arg(long)]
    inspect: Option<PathBuf>,

    /// Maximum I/O read rate in MB/s (0 = unlimited)
    #[arg(long, default_value_t = 20)]
    throttle_mb_s: u64,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    println!("============================================================");
    println!("  OpenFIM Defensive Sensor Daemon v0.1.0                    ");
    println!("  Compliance: PCI DSS 11.5 // NIST 800-53 SI-7              ");
    println!("============================================================");

    if let Some(target_path) = args.inspect {
        println!("[*] Performing one-shot inspection on: {}", target_path.display());
        let rate_bytes = args.throttle_mb_s * 1024 * 1024;
        let mut hasher = StreamHasher::new(HashAlgorithm::Sha256, TokenBucket::new(rate_bytes));
        
        match FileMetadata::extract(&target_path, &mut hasher) {
            Ok(meta) => {
                let json = serde_json::to_string_pretty(&meta)?;
                println!("{}", json);
            }
            Err(e) => {
                eprintln!("[!] Inspection error: {}", e);
                std::process::exit(1);
            }
        }
        return Ok(());
    }

    println!("[*] Agent starting with config: {}", args.config.display());
    println!("[*] Token-bucket rate limiter configured to: {} MB/s", args.throttle_mb_s);
    println!("[*] Initializing local SQLite baseline store...");
    println!("[*] Agent initialized successfully.");
    Ok(())
}
