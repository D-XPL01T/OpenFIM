# Build Order Checklist: First Two Weeks

This actionable, day-by-day implementation plan guides the solo researcher through scaffolding, coding, and testing the core MVP of the OpenFIM defensive architecture.

---

## Week 1: Core Agent Engine, Hasher & Local Storage (Rust)

- [x] **Day 1: Repository Scaffolding & Build Toolchain**
  - [x] Initialize Git repository with documentation structure and architecture specs.
  - [x] Initialize Cargo workspace (`openfim-agent`, `openfim-common`, `openfim-cli`).
  - [x] Configure `Cargo.toml` dependencies: `sha2`, `blake3`, `serde`, `serde_yaml`, `serde_json`, `thiserror`, `tokio`, `clap`.
  - [x] Setup toolchain with MinGW / UCRT and musl cross-compilation support.

- [x] **Day 2: Bounded Streaming Hasher & Page-Cache Protection**
  - [x] Implement `StreamHasher` struct in Rust with 64 KB chunked reads.
  - [x] Add `libc::posix_fadvise(fd, 0, 0, libc::POSIX_FADV_DONTNEED)` on Unix and sequential scan on Windows.
  - [x] Implement token-bucket rate limiter (`TokenBucket`) to enforce configurable MB/s read throttling.
  - [x] Add pre- and post-read inode/device checks (`st_ino`, `st_dev` / file identity) to catch TOCTOU substitution attacks.
  - [x] Write unit tests verifying SHA-256 and BLAKE3 hash accuracy against NIST test vectors, rate limiting, and TOCTOU validation (11/11 tests passing).

- [x] **Day 3: Metadata Capture & File Crawler**
  - [x] Implement `FileMetadata` extractor using `std::os::unix::fs::MetadataExt` and Windows `MetadataExt`.
  - [x] Capture `mode`, `uid`, `gid`, `size`, `mtime`, `ctime`, `inode`, `dev`, `nlink`.
  - [x] Implement glob pattern ignore engine (`CrawlOptions::is_ignored`) supporting multi-pattern exclusions.
  - [x] Implement recursive directory crawler (`FileCrawler`) with recursion depth bounds and symlink safety.
  - [x] Add CLI `crawl` subcommand with real-time progress, formatting, and ignore flags.

- [x] **Day 4: Local SQLite Baseline Schema & rusqlite Integration**
  - [x] Create SQLite schema migrations (`baseline_entries` and `event_spool` tables).
  - [x] Enable WAL journal mode (`PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;`).
  - [x] Implement batched bulk insert for initial baseline snapshot generation.
  - [x] Implement high-speed baseline diff query comparing disk stat tuples against SQLite index.
  - [x] Add CLI `baseline` subcommand (`init`, `snapshot`, `diff`, `status`) with integrity diff reports.

- [x] **Day 5: Declarative YAML Policy Parser & Ed25519 Verification**
  - [x] Define policy schema struct with serde deserializers for path rules, checks, and ignore globs.
  - [x] Implement Ed25519 public key signature verification on loaded policy files.
  - [x] Write integration test: load sample enterprise Linux policy, ensure invalid signatures are rejected.
  - [x] Add CLI `policy` subcommand suite (`check`, `keygen`, `sign`, `test-path`).

---

## Week 2: Real-Time Event Sensor, Attribution & Client-Side Verifier

- [x] **Day 6: Real-Time File Integrity Sensor Daemon**
  - [x] Implement cross-platform filesystem event listener using asynchronous `notify` engine (Windows ReadDirectoryChangesW, Linux inotify/fanotify).
  - [x] Watch all path targets and directories defined in signed YAML policies.
  - [x] Implement sliding-window debouncing (250ms) to suppress multi-stage editor write noise.
  - [x] Integrate with tokio asynchronous runtime and graceful shutdown handling.

- [x] **Day 7: Process Attribution Engine (Who-Data)**
  - [x] Implement lightweight `ProcessContext` resolver (`whodata.rs`) extracting acting PID, PPID, exe, cmdline, and UID.
  - [x] Support Linux `/proc/[pid]/exe` and `/proc/[pid]/cmdline` with cross-platform Win32 fallback.
  - [x] Enrich every security alert and spooled event tuple with actor process identity.

- [x] **Day 8: Standalone Browser Verifier UI (`verifier.html`)**
  - [x] Create standalone single-file HTML5/CSS3/JavaScript application (`web/verifier.html`).
  - [x] Implement drag-and-drop file ingestion with Web Crypto API (`crypto.subtle.digest`).
  - [x] Implement GNU `.sha256` and OpenFIM manifest JSON auto-parsing and visual color diff badges.

- [x] **Day 9: Offline Spooling & Cryptographic Append-Only HMAC Chain**
  - [x] Implement HMAC-SHA256 chaining on local SQLite `event_spool` table (`append_spool_event_chained`).
  - [x] Add CLI `audit verify` command to verify cryptographic hash chain and sequence continuity.
  - [x] Write recovery test: artificially corrupt or delete intermediate rows in SQLite; verify sensor detects broken chain and pinpoints tampered sequence ID.

- [x] **Day 10: Guarded Active Response & End-to-End Evasion Test Suite**
  - [x] Implement automated Active Response remediation engine (`Quarantine`, `RestoreBaseline`).
  - [x] Execute Red-Team evasion test suite in `tests/pipeline_tests.rs`:
    - [x] Test 1: Timestomping evasion test -> verify content change flagged regardless of timestamp.
    - [x] Test 2: Tamper-evident spool audit -> verify sequence gaps and payload tampering detected.
    - [x] Test 3: Active response quarantine & baseline restoration -> verify malicious payload isolated and pristine file restored.
    - [x] Test 4: Who-data forensic attribution -> verify process metadata resolution.
  - [x] Full workspace test suite passing (26/26 tests passing in < 3s).
