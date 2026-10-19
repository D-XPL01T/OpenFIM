# 14. Testing & Validation

The integrity monitoring agent operates in adversarial environments where sophisticated attackers actively attempt to bypass, deceive, or disable security sensors. OpenFIM mandates a rigorous defensive validation harness.

---

## 14.1 Red-Team Evasion Validation Test Suite

The test suite systematically executes simulated attacker techniques to prove detection efficacy and sensor resilience:

| Attack Scenario | Adversary Technique Under Test | Verification Test Procedure | Expected OpenFIM Defense & Result |
|---|---|---|---|
| **Evasion 1: Timestomping** | Attacker modifies file content and uses `touch -r` or `futimens()` to reset timestamps to match the pristine baseline. | Script modifies `/etc/sudoers`, records original `mtime`, writes backdoor, then restores original `mtime` and `atime` via `utimensat()`. | **PASS**: Real-time engine triggers on kernel `FAN_CLOSE_WRITE`. Content hash mismatch is detected regardless of timestamp. |
| **Evasion 2: Hardlink Substitution** | Attacker creates a hardlink to a legitimate binary, points execution to it, and alters the target file. | Script creates hardlink `ln /bin/login /tmp/login_link`, modifies `/bin/login`. | **PASS**: Agent tracks `st_nlink` (link count increased from 1 to 2) and `st_ino`, flagging an attribute anomaly immediately. |
| **Evasion 3: Symlink Swap Attack** | Attacker rapidly swaps a symlink from a benign file to a malicious payload to fool scanner. | Script swaps symlink target via atomic `renameat2(RENAME_EXCHANGE)` while agent is hashing the path. | **PASS**: Agent resolves paths with `O_NOFOLLOW` and compares `st_ino`/`st_dev` pre- and post-read, catching TOCTOU substitutions. |
| **Evasion 4: Local Log Truncation** | Attacker gains root, attempts to erase traces of an intrusion by truncating local spool database. | Attacker executes `sqlite3 /var/lib/openfim/spool.db "DELETE FROM event_spool WHERE sequence_id=42;"` | **PASS**: Cryptographic HMAC chain breaks at record 43; manager flags `TAMPERED_OFFLINE_LOG_DETECTED`. |
| **Evasion 5: Sensor Disablement** | Attacker sends `SIGKILL` (`kill -9`) to `openfim-agent` daemon. | Automated harness executes `killall -9 openfim-agent`. | **PASS**: Systemd watchdog restarts the agent in < 2.0 seconds; boot-time integrity sweep immediately flags any changes made while offline. |
| **Evasion 6: Namespace / Chroot Evasion** | Attacker spawns an isolated mount namespace via `unshare -m` and mounts a rogue filesystem over `/etc`. | Script executes `unshare -m`, mounts malicious tmpfs over `/etc/shadow`. | **PASS**: eBPF VFS hooks operate at the kernel VFS layer across all mount namespaces, capturing the mount and underlying file access. |

---

## 14.2 Automated Parser Fuzzing Plan

File parsers running as root represent a high-value vulnerability surface. OpenFIM mandates continuous fuzzing using `cargo-fuzz` (LLVM `libFuzzer`):

```
+-----------------------------------------------------------------------------------------+
|                                FUZZING TARGET SUITE                                     |
+-----------------------------------------------------------------------------------------+
| 1. Policy Parser Fuzzer    | Feeds malformed, oversized, and recursive YAML payloads    |
|                            | into the serde-yaml deserializer to catch panics or OOMs.  |
| 2. Manifest Parser Fuzzer  | Injects corrupted CBOR/JSON baseline manifests with deeply |
|                            | nested arrays and invalid unicode strings.                 |
| 3. Checksum File Fuzzer    | Fuzzes GNU `.sha256`, `.md5`, and `.sfv` text parsers      |
|                            | with boundary escape characters and formatting glitches.   |
| 4. gRPC Framing Fuzzer     | Streams randomized binary Protobuf frames into the manager |
|                            | ingestion server to identify memory leaks or deadlocks.    |
+-----------------------------------------------------------------------------------------+
```

---

## 14.3 False-Positive & False-Negative Benchmark Harness

To empirically validate the Change Intelligence Engine, OpenFIM includes a dual-metric validation benchmark:

1. **False-Positive Measurement (Target: < 0.1% on system updates)**:
   - Deploy clean Ubuntu 24.04 and RHEL 9 test nodes.
   - Execute a full OS upgrade: `apt-get dist-upgrade -y` (modifying ~12,000 files).
   - *Benchmark Criterion*: 100% of package-owned modified binaries must be classified as `EXPECTED_PACKAGE_UPDATE`. The number of false `CRITICAL` alerts must be exactly **0**.
2. **False-Negative Measurement (Target: 0% on unauthorized mutations)**:
   - Inject 50 randomized micro-tampering events (single-byte modification in `/bin/ls`, permission change on `/etc/shadow`, new SUID binary in `/tmp`, added cron line in `/etc/crontab`).
   - *Benchmark Criterion*: 50 out of 50 tampering events must be detected and attributed within 1,000 milliseconds.
