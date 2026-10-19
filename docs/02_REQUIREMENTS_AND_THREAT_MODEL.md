# 2. Requirements & Threat Model

## 2.1 Functional Requirements (FR)

- **FR-01 (Multi-Engine Detection)**: The system MUST support real-time kernel event-driven monitoring, scheduled periodic scans, on-demand CLI scans, and boot-time integrity validation.
  - *Rationale*: Real-time provides instant detection of intrusions, while scheduled scans catch out-of-band changes (e.g. offline disk mounts). *Alternative rejected*: Pure scheduled scan (misses transient attacker drops).
- **FR-02 (Cryptographic Hashing)**: The agent MUST compute SHA-256 by default for all tracked files, with optional support for BLAKE3 (performance) and SHA-512. MD5 and SHA-1 MUST be marked cryptographically deprecated and disallowed for policy compliance.
  - *Rationale*: SHA-256 is universally mandated by PCI DSS 11.5 and NIST SI-7; BLAKE3 offers 4x-8x throughput for large files. *Alternative rejected*: MD5/SHA-1 (known collision vulnerabilities).
- **FR-03 (Granular Metadata Tracking)**: For every monitored path, the agent MUST track file size, permissions/mode (`st_mode`), owner UID, group GID, inode (`st_ino`), hard link count (`st_nlink`), device ID (`st_dev`), extended attributes (`xattrs`), POSIX ACLs, SELinux/AppArmor security labels, and timestamps (`mtime`, `ctime`, `btime` where supported).
  - *Rationale*: Attackers frequently alter file attributes (e.g., adding SUID bit or altering ACLs) without changing file content. *Alternative rejected*: Content-only hashing (misses permission escalation).
- **FR-04 (Who-Data Attribution)**: The system MUST attribute file system events to the acting process: process ID (PID), thread ID (TID), parent PID (PPID), real and effective user ID (UID/EUID), executable binary path, command-line arguments, and Linux cgroup/container ID.
  - *Rationale*: SOC triage requires immediate attribution to determine whether an edit was caused by an admin, a service, or an interactive shell. *Alternative rejected*: Anonymous file notification (forces manual forensic correlation).
- **FR-05 (Declarative Policy Engine)**: The system MUST evaluate file checks against a declarative YAML policy supporting path globs, recursive directory scanning, regex-based ignore filters, check attribute masks, severity ratings (1-10), and action triggers.
  - *Rationale*: Standardized declarative policies enable version control via GitOps and automated compliance auditing. *Alternative rejected*: Imperative shell scripts (prone to syntax bugs and non-deterministic behavior).
- **FR-06 (Baseline Versioning & Signed Manifests)**: Every baseline snapshot MUST be compiled into an immutable manifest cryptographically signed with an Ed25519 private key. The agent MUST verify the manifest signature prior to execution.
  - *Rationale*: Prevents an attacker with local root privileges from silently modifying the baseline database to legitimize malicious files. *Alternative rejected*: Plain SQLite/flat-file baselines (writable by root).
- **FR-07 (Content-vs-Metadata Policy Decoupling)**: The policy engine MUST allow paths to be monitored for metadata changes only, content changes only, or both.
  - *Rationale*: Dynamic configuration directories (e.g. `/etc/resolv.conf`, `/etc/adjtime`) change timestamps frequently, generating massive false-positive noise if timestamps are strictly enforced. *Alternative rejected*: Rigid global check mask.
- **FR-08 (Package Manager Integration)**: The agent MUST cross-reference modified system files against local package manager databases (`dpkg`, `rpm`, `apk`) to classify changes resulting from verified vendor updates as "Authorized Package Updates".
  - *Rationale*: Routine OS upgrades otherwise trigger thousands of false alerts, blinding security teams. *Alternative rejected*: Manual approval of every single patched library.
- **FR-09 (Air-Gapped & Offline Autonomy)**: The agent MUST operate autonomously without an active network connection, storing events in a local encrypted spool buffer (up to a configurable disk quota) and verifying baselines against local signed manifests.
  - *Rationale*: Critical infrastructure, military enclaves, and maritime systems operate in disconnected environments. *Alternative rejected*: Cloud-tethered streaming-only agent (fails silently when offline).
- **FR-10 (Stateful Event Correlation)**: The central manager MUST support stateful correlation rules evaluating sliding time windows (e.g. file modification + new user creation + outbound network connection within 300 seconds).
  - *Rationale*: SolarWinds SEM demonstrated that single-event alerting is too noisy; multi-vector correlation catches real attack chains. *Alternative rejected*: Stateless regex alert triggers.
- **FR-11 (Guarded Active Response)**: The agent MUST support policy-driven automated rollback of unauthorized configuration changes from a signed local cache, with strict circuit breakers (e.g. max 3 auto-reverts/hour) and mandatory dry-run simulation mode.
  - *Rationale*: Automated containment stops ransomware and unauthorized tampering before data egress, while circuit breakers prevent self-inflicted denial-of-service. *Alternative rejected*: Unguarded automatic deletion (catches legitimate boot files in failure loops).
- **FR-12 (Client-Side Browser Verifier)**: The system MUST include a standalone, zero-upload web utility executing in the browser using the Web Crypto API to stream-hash local files and verify them against published baseline manifests and `.sha256` checksum files.
  - *Rationale*: Provides auditors, air-gapped operators, and forensics teams instant verification without installing binaries or uploading proprietary files to third-party clouds. *Alternative rejected*: Server-side upload verification (violates data sovereignty).
- **FR-13 (Standardized Log Export)**: The manager MUST export normalized events in Elastic Common Schema (ECS), CEF, and OpenTelemetry formats over TLS syslog, Kafka, and webhook channels.
  - *Rationale*: Ensures seamless integration with existing SIEMs (Splunk, Elastic, Sentinel, Chronicle). *Alternative rejected*: Proprietary binary log format.
- **FR-14 (Windows Registry & Object Monitoring - Phase 2)**: The architecture MUST define extension points for Windows Registry monitoring (`HKLM\Software\Microsoft\Windows\CurrentVersion\Run`, Services, etc.) and macOS FSEvents.
  - *Rationale*: Cross-platform enterprise coverage requires registry and system attribute monitoring. *Alternative rejected*: Linux-only codebase rewrite for Windows.
- **FR-15 (Audit Trail Immutability)**: All baseline promotions, policy modifications, and operator alerts MUST be recorded in an append-only, cryptographic hash-chained audit ledger.
  - *Rationale*: Compliance mandates (PCI DSS 11.5, NIST 800-53 AU-9) require tamper-evident operator audit trails. *Alternative rejected*: Standard database update/delete statements.

---

## 2.2 Non-Functional Requirements (NFR)

- **NFR-01 (Memory Footprint)**: Agent resident set size (RSS) MUST NOT exceed 15 MB in steady-state idle monitoring, and MUST NOT exceed 35 MB during active baseline verification sweeps across 100,000 files.
- **NFR-02 (CPU Utilization)**: Agent CPU utilization MUST remain below 1.0% of a single core during real-time kernel monitoring, and MUST NOT exceed 5.0% during full disk crawling via automatic token-bucket rate limiting and POSIX `nice(10)` or `SCHED_IDLE`.
- **NFR-03 (I/O Impact & Page Cache Protection)**: During file hashing, the agent MUST read files in 64 KB chunks and issue `posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED)` on Linux to ensure scanning does not flush critical application data from the OS page cache. File reads MUST be throttled to a configurable ceiling (default: 20 MB/s).
- **NFR-04 (Scale & Throughput)**: A single central manager instance MUST ingest and index up to 10,000 change events per second sustained, supporting up to 5,000 concurrently connected agents.
- **NFR-05 (Detection Latency)**: For real-time monitored paths, the end-to-end latency from file write close (`close_write`) to local agent alert generation MUST be less than 50 milliseconds.
- **NFR-06 (Network Overhead)**: Telemetry between agent and manager MUST be compressed via zstd, encrypted over mutual TLS 1.3, with keepalive traffic consuming less than 2 KB per minute per idle agent.
- **NFR-07 (Fault Tolerance & Spooling)**: In the event of network disruption or manager unavailability, the agent MUST spool up to 500 MB of encrypted event logs locally in a circular SQLite ring buffer without dropping events or crashing.
- **NFR-08 (Zero External Runtime Dependencies)**: The agent MUST compile to a single statically linked binary (musl libc target for Linux) requiring no external shared libraries, Python, or runtime interpreters.
- **NFR-09 (Kernel Compatibility)**: The agent MUST function seamlessly across Linux kernels 4.19 through 6.x+, automatically falling back from eBPF CO-RE to Fanotify/Inotify if kernel capabilities or permissions (`CAP_BPF`) are unavailable.
- **NFR-10 (Crash Recovery)**: If the agent crashes or the machine experiences an ungraceful power loss, the local SQLite database MUST recover automatically via Write-Ahead Logging (WAL) without baseline corruption.

---

## 2.3 Trust Boundaries & Security Assumptions

```
+-----------------------------------------------------------------------------------------+
| TRUST DOMAIN 0: Hardened Management & Signing Authority (Air-gapped / HSM / Admin Workstation)
|  - Holds Master Ed25519 Signing Key for baseline manifests & binary release certificates.
|  - High trust: Never exposes private keys to managed endpoints.
+-----------------------------------------------------------------------------------------+
                                           | Policy / Signed Manifests (mTLS / Offline USB)
                                           v
+-----------------------------------------------------------------------------------------+
| TRUST DOMAIN 1: Central FIM Manager Cluster (DMZ / Private Cloud)
|  - PostgreSQL (Policy/Node DB) + ClickHouse (Event Lake) + Ingestion API + CEL Engine.
|  - Boundary: Network perimeter. Authenticates agents via X.509 mTLS certificates.
+-----------------------------------------------------------------------------------------+
                                           ^
                                           | Bidirectional mTLS 1.3 (gRPC / zstd)
                                           v
+-----------------------------------------------------------------------------------------+
| TRUST DOMAIN 2: Monitored Endpoint - Host Operating System
|  +-----------------------------------------------------------------------------------+  |
|  | KERNEL SPACE: Linux Kernel (5.8+ eBPF LSM / tracepoints or Fanotify subsystem)    |  |
|  | - Ultimate enforcement of memory boundaries, file descriptors, and ring buffers.  |  |
|  +-----------------------------------------------------------------------------------+  |
|       ^                                                                                  |
|       | BPF ring_buffer_poll / fanotify_init                                            |
|       v                                                                                  |
|  +-----------------------------------------------------------------------------------+  |
|  | PRIVILEGED USER-SPACE (root / CAP_SYS_ADMIN / CAP_BPF / CAP_DAC_READ_SEARCH)      |  |
|  | - OpenFIM Agent daemon (Rust, static binary, local SQLite WAL, Ed25519 verifier).   |  |
|  | - Systemd Watchdog supervisor.                                                    |  |
|  +-----------------------------------------------------------------------------------+  |
|  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ PROCESS / USER BOUNDARY ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~  |
|  +-----------------------------------------------------------------------------------+  |
|  | UNPRIVILEGED / COMPROMISED APPLICATION SPACE                                      |  |
|  | - Web server (www-data), database (postgres), compromised daemon, non-root users.  |  |
|  | - Untrusted: Potential adversary attempting local privilege escalation.             |  |
|  +-----------------------------------------------------------------------------------+  |
+-----------------------------------------------------------------------------------------+
```

### Explicit Assumptions
1. **Kernel Integrity Assumption**: If the host kernel itself is compromised by a ring-0 rootkit (e.g. kernel memory patcher, malicious kernel module), all user-space and eBPF security telemetry is untrusted. Defense against ring-0 compromise relies on Secure Boot, kernel lockdown (`lockdown=confidentiality`), and signed kernel modules.
2. **Initial Trusted State (Gold Master)**: Baselines are captured when the host is known to be in an uncompromised state (e.g. during golden image bake, clean OS provisioning, or immediately post-validation).
3. **Manager Compromise Blast Radius**: If the central manager is compromised, the attacker cannot forge valid baseline updates on agents because agents verify offline Ed25519 signatures from an independent signing key (held in an offline HSM or developer workstation). The attacker can at most drop incoming alerts or spoof policies, which agents reject if unsigned.

---

## 2.4 STRIDE Threat Model of the FIM Itself

| STRIDE Category | Threat Vector / Attacker Goal | Concrete Attack Mechanism | Architectural Mitigation in OpenFIM |
|---|---|---|---|
| **Spoofing** | Attacker spoofs agent identity to inject clean change reports. | Rogue host sends fake gRPC status messages pretending to be Host A. | Strict mutual TLS 1.3 with per-agent unique X.509 client certificates and certificate pinning; agent UID bound to certificate CN. |
| **Tampering** | Attacker poisons or modifies the local baseline to hide a backdoor. | Root attacker alters local SQLite database row: replaces `/bin/login` hash with malicious hash. | Baseline manifest is hashed into a Merkle root and signed with an external Ed25519 private key. Agent verifies signature on every boot and sweep. SQLite file is marked read-only (`chattr +i`). |
| **Tampering** | Timestomping evasion. | Attacker drops webshell into `/var/www/html` and uses `touch -r /etc/passwd webshell.php` to match existing mtime/atime. | Hash verification is decoupled from timestamps. Real-time engine triggers on kernel `close_write` / `FAN_MODIFY` regardless of subsequent timestamp resets via `futimens()`. |
| **Tampering** | Symlink / Hardlink / TOCTOU swap races. | Attacker creates hardlink or swaps symlink to legitimate file while scanning to fool hasher, then swaps back. | Hasher uses `O_NOFOLLOW` and `O_PATH` file descriptors. It compares `st_dev` and `st_ino` between open and hash completion, detecting any inode substitution during the read window. |
| **Tampering** | Local log tampering or truncation. | Attacker executes `echo "" > /var/log/fim/events.json` or modifies historical change records. | Events are streamed immediately over mTLS to central ClickHouse. Local spool uses an HMAC-chained append-only SQLite log (`Hash_n = SHA256(Hash_{n-1} || Event_n)`). Any truncation breaks the hash chain. |
| **Repudiation** | Attacker claims file changes were routine administrative updates. | Attacker edits `/etc/sudoers` from an interactive root shell and denies making the edit. | eBPF process attribution captures exact audit trail: `uid`, `euid`, `session_id`, `loginuid`, `comm`, parent tree, and shell TTY, binding the file modification to a specific user session. |
| **Information Disclosure** | Unauthorized extraction of sensitive monitored file contents. | Attacker attempts to read diffs of `/etc/shadow` or private SSH keys from FIM manager console. | Policies support `nodiff: true` flag. For sensitive files, the agent computes and transmits hashes only; file content diffs are never stored or transmitted over the wire. |
| **Denial of Service** | Disabling or killing the FIM agent. | Attacker executes `kill -9 $(pidof openfim-agent)` or floods inotify queue with millions of file creations. | Dual-watchdog protection: systemd watchdog (`WatchdogSec=10s`) + supervisor process automatically restarts agent. Inotify/fanotify queue overflow triggers fallback to high-speed reconciliation sweep. |
| **Elevation of Privilege** | Abuse of update / policy push channel. | Attacker compromises manager and pushes a malicious policy script or binary update to gain root on 5,000 agents. | Policy bundles and agent binary upgrades require dual-signature Ed25519 verification. Policies are declarative data only (no shell execution). Agents reject unsigned binaries unconditionally. |
| **Evasion** | Evading detection via excluded paths, bind mounts, and containers. | Attacker creates a private mount namespace or bind-mounts `/bin` to an unmonitored path. | Fanotify filesystem marks (`FAN_MARK_FILESYSTEM`) and eBPF VFS hooks operate at the virtual filesystem layer across all mount namespaces, capturing changes regardless of chroot or container isolation. |
