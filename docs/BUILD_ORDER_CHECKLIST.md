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

- [ ] **Day 5: Declarative YAML Policy Parser & Ed25519 Verification**
  - [ ] Define policy schema struct with serde deserializers for path rules, checks, and ignore globs.
  - [ ] Implement Ed25519 public key signature verification on loaded policy files.
  - [ ] Write integration test: load sample enterprise Linux policy, ensure invalid signatures are rejected.

---

## Week 2: Real-Time Kernel Sensor, Attribution & Client-Side Verifier

- [ ] **Day 6: Linux Fanotify Real-Time Kernel Sensor**
  - [ ] Implement Fanotify listener using `libc::fanotify_init` and `libc::fanotify_mark`.
  - [ ] Subscribe to `FAN_MODIFY`, `FAN_CLOSE_WRITE`, `FAN_ATTRIB`, and `FAN_MOVED_TO`.
  - [ ] Implement kernel buffer overflow handler catching `FAN_Q_OVERFLOW` and setting reconciliation flags.
  - [ ] Integrate with tokio asynchronous event loop via `AsyncFd`.

- [ ] **Day 7: Process Attribution Engine (Who-Data)**
  - [ ] Implement `/proc/[pid]/exe`, `/proc/[pid]/cmdline`, and `/proc/[pid]/status` resolver.
  - [ ] Extract acting `PID`, `PPID`, `UID`, `EUID`, `comm`, and `loginuid`.
  - [ ] Implement in-memory LRU cache for process metadata to avoid redundant `/proc` lookups.
  - [ ] Assemble full change event tuple combining file diff with acting process context.

- [ ] **Day 8: Standalone Browser Verifier UI (`verifier.html`)**
  - [x] Create standalone single-file HTML5/CSS3/JavaScript application (`web/verifier.html`).
  - [x] Implement drag-and-drop file ingestion with Web Crypto API (`crypto.subtle.digest`).
  - [x] Implement GNU `.sha256` and OpenFIM manifest JSON auto-parsing and visual color diff badges.
  - [ ] Add WebAssembly (Wasm) BLAKE3 SIMD streaming module for gigabyte-scale ISO verification.

- [ ] **Day 9: Offline Spooling & Append-Only HMAC Chain**
  - [ ] Implement HMAC-SHA256 chaining on local SQLite `event_spool` table.
  - [ ] Write recovery test: artificially corrupt or delete an intermediate row in SQLite; verify agent detects broken chain on startup.
  - [ ] Add disk quota manager enforcing 500 MB ceiling and dropping low-severity events under pressure.

- [ ] **Day 10: Systemd Watchdog & End-to-End Evasion Test Run**
  - [ ] Configure `sd_notify` watchdog ping in agent loop (`WatchdogSec=10s`).
  - [ ] Execute Red-Team test suite:
    - [ ] Test 1: Timestomping evasion test via `futimens()` -> verify detection.
    - [ ] Test 2: Symlink swap test via `renameat2(RENAME_EXCHANGE)` -> verify detection.
    - [ ] Test 3: Process kill test -> verify systemd restarts daemon in < 2s.
  - [ ] Benchmark resource usage on a 100,000-file filesystem: confirm memory < 15 MB RSS and CPU < 5%.
