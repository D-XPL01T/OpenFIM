# 1. Reference Analysis

This section analyzes the leading commercial, legacy open-source, modern open-source, and client-side integrity tools to distill proven mechanisms and identify architectural failure points.

## 1.1 Comparative Reference Matrix

| Feature / Dimension | OSSEC (syscheck) | SolarWinds SEM (formerly TriGeo SIM) | Jam.dev File Integrity Checker | Aback Tools Checksum Verifier | AIDE (Advanced Intrusion Detection Env.) | Samhain | Kekkai (catatsuy/kekkai) | Achiefs FIM (Achiefs/fim) |
|---|---|---|---|---|---|---|---|---|
| **Detection Method** | Dual: periodic directory traversal diffing + OS notification hooks. | Real-time agent filter driver / OS event-log intercepts + correlation engine. | Pure client-side single/batch file verification via browser engine. | Pure client-side hash generator and string/hash comparison utility. | Static filesystem crawling compared against an offline baseline snapshot. | Daemon-based scheduled filesystem scan with stealth client/server reporting. | Content-only baseline generation & periodic manifest verification. | Real-time asynchronous kernel notification sensor with JSON event stream. |
| **Real-time vs Scheduled** | Scheduled (default every 6h) + optional real-time (`realtime="yes"` via inotify). | Real-time streaming interception of file I/O operations. | On-demand (user drags/drops file in browser). | On-demand (browser execution). | Scheduled only (traditionally invoked via `cron` or orchestration). | Primarily scheduled; supports pseudo-realtime via inotify daemon mode. | Scheduled / CI-CD pipeline trigger (`kekkai verify`). | Real-time continuous background monitoring. |
| **Hashing Algorithms** | MD5, SHA-1, SHA-256 (configurable; older versions default to MD5/SHA-1). | Proprietary agent hashing (typically SHA-256 / SHA-1) [UNVERIFIED: exact internal cipher options]. | SHA-256, SHA-512, MD5 (via browser Web Crypto / JS). | MD5, SHA-1, SHA-256, SHA-512 (via browser Web Crypto). | MD5, SHA-1, SHA-256, SHA-512, RMD160, TIGER, WHIRLPOOL. | TIGER192, SHA-1, MD5. | SHA-256 (Go `crypto/sha256`). | SHA-256, BLAKE3 (Rust crypto crates). |
| **Metadata Tracked** | Size, permissions, UID/GID, mtime, inode, file hashes. | Size, attributes, ACLs, creation time, modification time, process name. | File name, file size, MIME type (no OS filesystem metadata). | File name, file size (no OS filesystem metadata). | Size, permissions, UID, GID, atime, mtime, ctime, inode, link count, xattrs, SELinux. | Size, permissions, owner, group, timestamps, inode, hard links. | File size, symlink target destination (intentionally ignores timestamps). | Size, permissions, UID, GID, mtime, ctime, inode, file path. |
| **Who-Made-The-Change Attribution** | Yes, on Linux via integration with Linux Auditd (`whodata="yes"`). | Yes: deep process attribution, Active Directory username, PID, parent PID. | None (runs in user's browser sandbox). | None (runs in user's browser sandbox). | None (offline crawl; no process context available). | None (records filesystem state changes only). | None (state verification only). | Yes: captures Linux Auditd netlink events and process identifiers. |
| **Baseline Storage** | Manager-side SQLite DB or flat text files (`/var/ossec/queue/syscheck`). | Central proprietary MS SQL / PostgreSQL backend on virtual appliance. | Ephemeral browser memory (zero persistent storage, no uploads). | Ephemeral browser memory (zero persistent storage). | Gzip-compressed flat text database file (`/var/lib/aide/aide.db.gz`). | Encrypted/signed database on central server or local host. | Amazon S3 bucket or local JSON manifest file (`manifest.json`). | Local JSON event logs (`/var/lib/fim/events.json`) and local state. |
| **Tamper Protection** | Encrypted UDP/TCP agent-manager channel with pre-shared keys; baseline on manager. | Hardened Linux virtual appliance, signed agent binaries, encrypted TLS pipe. | Sandboxed browser origin; zero server attack surface. | Sandboxed browser origin; zero server attack surface. | None natively; relies on administrator burning baseline to read-only media (CD/WORM). | Embedded XOR/steganographic keys in binary; signed database with PGP/GPG. | Cloud separation: write-only IAM policy for CI/CD, read-only IAM for nodes. | Local filesystem permissions; process isolation. |
| **Alerting** | Syslog, email notifications, active response scripts, JSON log forwarders. | Real-time console alerts, automated Active Response actions, email, SNMP. | Visual UI diff indicator (green match / red mismatch). | Visual UI status badge / diff string. | Standard output / exit code (captured by cron/email). | Syslog, email, encrypted TCP socket to central Samhain server. | Non-zero exit code (`status 1` on mismatch) to CI/CD or logging agent. | Structured JSON log outputs consumed by Wazuh, Elasticsearch, or SIEM. |
| **Compliance Reporting** | Mappings for PCI DSS, HIPAA, CIS Benchmarks (via Wazuh/OSSEC rules). | Built-in audit reports for PCI DSS, SOX, HIPAA, NIST 800-53, ISO 27001. | None (ad-hoc manual utility). | None (ad-hoc manual utility). | None out of the box (requires external log parser/SIEM). | Basic audit trails; no out-of-the-box regulatory report generator. | None (designed for cloud DevOps pipelines). | Facilitates PCI DSS FIM controls via JSON log ingestion into SIEMs. |
| **False-Positive Handling** | Ignore directives, regex exclusion, `nodiff` directives for sensitive files. | Configurable change windows, noise-reduction filters, scheduled exemptions. | N/A (interactive single-file verification). | N/A (interactive single-file verification). | Complex regular expression negative matching in configuration rules. | Ignore rules for growing files, inode changes, or log file rotations. | Ignores timestamp/inode changes entirely; strictly evaluates file byte content. | Path-based exclusion patterns in configuration file. |
| **Weaknesses** | High CPU spikes during crawls; inotify queue overflow causes silent drops; MD5 legacy. | Heavyweight enterprise footprint; expensive proprietary appliance; Windows-centric. | Cannot monitor OS directories; strictly manual interactive file drop. | No batch folder crawling; cannot monitor system state. | High I/O impact during full scan; baseline vulnerable to local root overwrite if online. | Complex legacy C codebase; difficult key deployment; slow cryptographic primitives. | No real-time file event capture; no process attribution; manual S3 pull needed. | Early project maturity [UNVERIFIED: production stress-testing at 5k nodes]; limited manager. |

---

## 1.2 Lessons Learned: What to Adopt, Avoid, and Improve

### Features to Adopt
1. **Cloud / Storage Separation of Baseline (from Kekkai)**:
   - *Adoption*: The agent must never possess write privileges to its own baseline manifest in normal operating mode. Baseline creation/updating happens during an authorized transition, cryptographically signed and stored on the central manager or signed locally with an external key.
2. **Dual-Engine Real-Time + Scheduled Sweep (from OSSEC/AIDE)**:
   - *Adoption*: Real-time kernel event monitoring handles immediate detection, while a low-priority, I/O-throttled scheduled sweep catches any anomalies missed during kernel queue overflows or system downtime.
3. **Deep Process Attribution / Who-Data (from SolarWinds SEM)**:
   - *Adoption*: File modifications without process context (PID, UID, PPID, executable binary path, cgroup, container ID) are insufficient for forensic triage. We must bind file change events directly to the acting process.
4. **Client-Side Zero-Upload Streaming Hasher (from Jam.dev & Aback Tools)**:
   - *Adoption*: A standalone browser-based verification utility allowing operators and auditors to drag-and-drop gigabyte-sized ISOs, packages, or offline baseline files, computing SHA-256/BLAKE3 client-side via the Web Crypto API without byte transfer across the network.
5. **Structured JSON Telemetry (from Achiefs FIM)**:
   - *Adoption*: First-class, Elastic Common Schema (ECS)-compliant JSON logs for frictionless SIEM and data-lake routing.

### Features to Avoid
1. **Blind Timestamp/Inode Tracking on Dynamic Directories (OSSEC & AIDE Failure Point)**:
   - *Avoid*: Alerting indiscriminately on `mtime` or `ctime` changes on directories where temporary files or touch events occur, which overwhelms SOC analysts with false positives.
2. **Unauthenticated or Cleartext Baseline Storage (AIDE Failure Point)**:
   - *Avoid*: Storing baseline databases as plain local flat files (`aide.db.gz`) writable by local `root`. Any attacker achieving privilege escalation trivially overwrites the baseline after dropping a backdoor.
3. **Heavyweight Monolithic Java/Appliance Architectures (SolarWinds SEM Failure Point)**:
   - *Avoid*: Monolithic proprietary virtual appliances that require dedicated multi-gigabyte memory allocations and inflexible licensing.
4. **Inotify-Only Real-Time Engines Without Overflow Fallback (OSSEC Failure Point)**:
   - *Avoid*: Relying on inotify without handling `IN_Q_OVERFLOW`. When an attacker or a compiler generates millions of events, inotify drops events silently, allowing attackers to blind the FIM.

### Features to Improve
1. **Kernel Attribution Overhead**:
   - *Improvement*: Instead of hooking heavy auditd netlink sockets (which compete with host auditd daemons and cause system-wide performance degradation), utilize modern eBPF CO-RE (Compile-Once Run-Everywhere) with ring buffers. Fall back to Fanotify/Auditd only on legacy kernels.
2. **Package Manager & Package Repository Intelligence**:
   - *Improvement*: Traditional FIMs flag all files modified during `apt upgrade` or `dnf update` as hundreds of critical integrity violations. OpenFIM cross-references changes against local package manager databases (`dpkg`, `rpm`, `apk`) and verifies signed repository hashes to classify routine system updates as "Authorized/Expected".
3. **I/O Throttling and Cache Eviction Prevention**:
   - *Improvement*: Scanning large files traditionally flushes useful data out of the Linux page cache. OpenFIM utilizes `posix_fadvise(POSIX_FADV_DONTNEED)` during baseline calculation and tokens-per-second rate limiting to guarantee sub-5% CPU and bounded IOPS.
