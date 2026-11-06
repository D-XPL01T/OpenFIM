# Master Index: OpenFIM Enterprise Architecture Specification

This repository contains the complete, production-grade defensive reference architecture for **OpenFIM**, a next-generation Host-based File Integrity Monitoring (FIM) and Intrusion Detection System.

## Architecture Documentation Map

| Section | Document | Summary |
|---|---|---|
| **01** | [`01_REFERENCE_ANALYSIS.md`](file:///d:/VibeCode/file_integrity/docs/01_REFERENCE_ANALYSIS.md) | Comparative matrix of OSSEC, SolarWinds SEM, Jam.dev, Aback Tools, AIDE, Samhain, Kekkai, Achiefs FIM. |
| **02** | [`02_REQUIREMENTS_AND_THREAT_MODEL.md`](file:///d:/VibeCode/file_integrity/docs/02_REQUIREMENTS_AND_THREAT_MODEL.md) | Functional & Non-Functional Requirements, Trust Boundaries, STRIDE Threat Model of the FIM itself. |
| **03** | [`03_HIGH_LEVEL_ARCHITECTURE.md`](file:///d:/VibeCode/file_integrity/docs/03_HIGH_LEVEL_ARCHITECTURE.md) | Component architecture, data flow diagrams, system topology (Mermaid). |
| **04** | [`04_AGENT_DESIGN.md`](file:///d:/VibeCode/file_integrity/docs/04_AGENT_DESIGN.md) | Rust agent internals: eBPF/fanotify/auditd attribution, bounded hashing, metadata capture, self-defense. |
| **05** | [`05_POLICY_RULE_ENGINE.md`](file:///d:/VibeCode/file_integrity/docs/05_POLICY_RULE_ENGINE.md) | Declarative YAML policy grammar, glob matching, complete enterprise Linux security baseline policy. |
| **06** | [`06_BASELINE_DATA_MODEL.md`](file:///d:/VibeCode/file_integrity/docs/06_BASELINE_DATA_MODEL.md) | SQLite agent schema, ClickHouse event schema, PostgreSQL manager schema, manifest lifecycle. |
| **07** | [`07_TAMPER_EVIDENCE_AND_CRYPTOGRAPHY.md`](file:///d:/VibeCode/file_integrity/docs/07_TAMPER_EVIDENCE_AND_CRYPTOGRAPHY.md) | Ed25519 manifests, Merkle/HMAC append-only log chains, mTLS, TPM/enclave binding, compromise blast radius. |
| **08** | [`08_CHANGE_INTELLIGENCE_FALSE_POSITIVE_REDUCTION.md`](file:///d:/VibeCode/file_integrity/docs/08_CHANGE_INTELLIGENCE_FALSE_POSITIVE_REDUCTION.md) | Package manager verification (dpkg/rpm), CI/CD change windows, publisher allowlisting, hash reputation. |
| **09** | [`09_EVENT_PIPELINE_CORRELATION_RESPONSE.md`](file:///d:/VibeCode/file_integrity/docs/09_EVENT_PIPELINE_CORRELATION_RESPONSE.md) | ECS normalization, CEL/Starlark stateful correlation, SIEM forwarding, guarded active response. |
| **10** | [`10_CLIENT_SIDE_VERIFIER_MODULE.md`](file:///d:/VibeCode/file_integrity/docs/10_CLIENT_SIDE_VERIFIER_MODULE.md) | Standalone browser-based zero-upload streaming verifier specification (Web Crypto API & Wasm). |
| **11** | [`11_INTERFACES.md`](file:///d:/VibeCode/file_integrity/docs/11_INTERFACES.md) | CLI commands, gRPC Protobuf definitions, REST API OpenAPI 3.0 specification, Web UI wireframes. |
| **12** | [`12_COMPLIANCE_MAPPING.md`](file:///d:/VibeCode/file_integrity/docs/12_COMPLIANCE_MAPPING.md) | Mapping matrix to PCI DSS 11.5, NIST 800-53 SI-7, CIS Controls v8, ISO/IEC 27001:2022. |
| **13** | [`13_PERFORMANCE_SCALE_RELIABILITY.md`](file:///d:/VibeCode/file_integrity/docs/13_PERFORMANCE_SCALE_RELIABILITY.md) | Resource budgets (<15MB RSS, <1% CPU), IOPS throttling, backpressure, 5,000 endpoint sizing. *(Budgets are design targets; not yet measured — see plan §18.5.2 item 3.8.)* |
| **14** | [`14_TESTING_AND_VALIDATION.md`](file:///d:/VibeCode/file_integrity/docs/14_TESTING_AND_VALIDATION.md) | Unit/integration testing, red-team evasion validation suite (timestomp, hardlink swap, TOCTOU). |
| **15** | [`15_DEPLOYMENT_AND_OPERATIONS.md`](file:///d:/VibeCode/file_integrity/docs/15_DEPLOYMENT_AND_OPERATIONS.md) | Packaging (deb/rpm/oci), Ansible/Helm deployment, observability metrics, incident runbooks. |
| **16** | [`16_ROADMAP.md`](file:///d:/VibeCode/file_integrity/docs/16_ROADMAP.md) | MVP (6 weeks), v1.0, v2.0 roadmap milestones, risk register, open technical questions. |
| **17** | [`17_ARCHITECTURE_DECISION_RECORDS.md`](file:///d:/VibeCode/file_integrity/docs/17_ARCHITECTURE_DECISION_RECORDS.md) | ADR-001 through ADR-007 covering all fundamental architectural trade-offs. |
| **18** | [`18_HARDENING_AND_PRODUCTIONIZATION_PLAN.md`](file:///d:/VibeCode/file_integrity/docs/18_HARDENING_AND_PRODUCTIONIZATION_PLAN.md) | Phased plan to enforce the full policy contract, harden operations, and reach portfolio grade. |
| **Plan** | [`BUILD_ORDER_CHECKLIST.md`](file:///d:/VibeCode/file_integrity/docs/BUILD_ORDER_CHECKLIST.md) | Concrete implementation checklist for the initial build (Weeks 1 and 2). |

## Standalone Artifacts
- **Client-Side Verifier Tool**: [`web/verifier.html`](file:///d:/VibeCode/file_integrity/web/verifier.html) (Zero-upload, offline streaming checksum & manifest verifier running 100% in the browser).

---

## Capability Matrix

The 17 documents above describe the **target** architecture. This table describes what
the **current code** actually does, per platform. It is maintained deliberately, because
a security tool that overstates its coverage produces false assurance — which is worse
than a documented gap.

Legend: **✅ enforced** · **◐ partial** · **❌ unsupported on this platform** · **⬜ planned, not implemented**

| Control | Linux | Windows | macOS | Notes |
|---|:--:|:--:|:--:|---|
| SHA-256 / BLAKE3 / SHA-512 content hashing | ✅ | ✅ | ✅ | Bounded 64 KB streaming reads, rate-throttled. |
| Streaming hash of large files | ✅ | ✅ | ✅ | Verified against FIPS 180-4 and BLAKE3 reference vectors. |
| Page-cache protection | ✅ | ✅ | ◐ | `POSIX_FADV_DONTNEED` on Linux, `FILE_FLAG_SEQUENTIAL_SCAN` on Windows. No macOS equivalent wired up. |
| TOCTOU substitution detection | ✅ | ✅ | ✅ | Handle identity vs. post-read path identity: `(st_dev, st_ino)` on Unix, volume serial + NTFS file index on Windows. |
| Recursive crawl with glob exclusions | ✅ | ✅ | ✅ | Separator- and case-normalized. |
| SQLite baseline + diff | ✅ | ✅ | ✅ | WAL mode, batched inserts, scoped diff. |
| Ed25519 signed policies | ✅ | ✅ | ✅ | Detached signatures; verification before load. |
| HMAC-SHA256 append-only audit chain | ✅ | ✅ | ✅ | All 15 event fields authenticated, length-prefixed, domain-separated. |
| Audit-log tamper detection | ✅ | ✅ | ✅ | Payload edits, interior deletion, and tail truncation (via signed chain anchor). |
| Real-time change detection | ◐ | ◐ | ◐ | inotify / `ReadDirectoryChangesW`. Events can be dropped on queue overflow; no reconciliation sweep yet (plan §18.3.4). |
| Active response (quarantine / restore) | ✅ | ✅ | ✅ | Circuit-breaker limited to 3/hour by default. |
| `checks.hash` | ✅ | ✅ | ✅ | |
| `checks.permissions` | ◐ | ◐ | ◐ | Compares `st_mode` only. On Windows that is attribute bits, so ACL changes are invisible. ACL hashing is plan §18.3.2. |
| `checks.size` | ⬜ | ⬜ | ⬜ | Parsed, not enforced. Caught incidentally by `hash`. |
| `checks.ownership` | ⬜ | ❌ | ⬜ | Not enforced. On Windows `uid`/`gid` are always 0, so it cannot work there without SID capture. |
| `checks.timestamps` | ⬜ | ⬜ | ⬜ | Parsed, not enforced. |
| `checks.attributes` | ⬜ | ⬜ | ⬜ | Parsed, not enforced. |
| `checks.xattrs` | ⬜ | ⬜ | ⬜ | Parsed, not enforced; `xattrs_hash` is always `NULL`. |
| `globals.default_hash` | ⬜ | ⬜ | ⬜ | Parsed and displayed; the hasher is hardcoded to SHA-256. |
| `globals.max_io_rate_mb_s` | ⬜ | ⬜ | ⬜ | Parsed; throttling comes from `--throttle-mb-s` instead. |
| `globals.scan_nice_priority` | ⬜ | ⬜ | ⬜ | Parsed, never applied. |
| `globals.realtime_fallback_sweep_interval` | ⬜ | ⬜ | ⬜ | Parsed; no sweep exists. |
| `rule.mode` (`scheduled` / `on_boot`) | ⬜ | ⬜ | ⬜ | Parsed; all modes behave as `realtime`. |
| `rule.nodiff` | ⬜ | ⬜ | ⬜ | Parsed; moot until diff capture exists. |
| **Process attribution (who-data)** | ⬜ | ⬜ | ⬜ | Not implemented. Reported honestly as `UNATTRIBUTED`; needs fanotify `FAN_REPORT_PIDFD`, eBPF, or a Windows minifilter. |
| Central manager / gRPC / SIEM forwarding | ⬜ | ⬜ | ⬜ | Roadmap Phase 2. |
| Package-manager change intelligence | ⬜ | ⬜ | ⬜ | Roadmap Phase 2. |
| TPM 2.0 key sealing | ⬜ | ⬜ | ⬜ | Roadmap Phase 3. |

**12 of 18 policy fields are parsed but not yet enforced.** Closing that gap is Phase 1
of [`18_HARDENING_AND_PRODUCTIONIZATION_PLAN.md`](file:///d:/VibeCode/file_integrity/docs/18_HARDENING_AND_PRODUCTIONIZATION_PLAN.md).

---

## Current Limitations

Read this before deploying OpenFIM anywhere you care about.

- **No process attribution.** OpenFIM tells you *what* changed, not *who* changed it.
  This is the main capability that distinguishes a FIM from a checksum script, and it
  requires kernel support that is not yet implemented. Alerts say `UNATTRIBUTED` rather
  than guessing.
- **Most of the policy schema is not yet enforced.** See the capability matrix. A policy
  file that loads cleanly and displays as active may configure controls that do nothing.
- **Real-time monitoring can miss events.** The watcher drops events under load
  (inotify queue overflow, `ReadDirectoryChangesW` buffer overrun), and there is no
  reconciliation sweep yet, so a miss is permanent and silent.
- **The agent does not defend itself.** The baseline database is an ordinary file. An
  attacker who can modify monitored files can usually also delete `openfim.db` or stop
  the agent. The audit chain proves the log was not *edited*; a retained off-host
  checkpoint would be needed to prove it was not *destroyed*.
- **The audit chain does not survive host compromise.** The HMAC key must be available
  to the agent, so an attacker with root can read it and forge history from that point
  on. Signed off-host checkpoints and TPM sealing are the planned mitigations.
- **Single host only.** No central manager, no fleet view, no SIEM forwarding.
- **Not packaged.** No installers or binary releases; build from source with Cargo. No
  service or daemon integration, so the sensor is a foreground process that stops when
  its terminal closes and nothing restarts it.
- **Windows coverage is narrower than Linux.** Ownership checks cannot work, and
  permission checks see attribute bits rather than ACLs.

**Suitable today for:** a technical user, on a single host, answering "has anything
under this directory changed since I took a snapshot" — with genuinely tamper-evident
logging and cryptographically signed policy.

**Not yet suitable for:** unattended production deployment, fleet monitoring, or any
situation where you need to know which process made a change.

---

## Interactive Metasploit-Style Console

To launch the interactive defensive console, run `openfim-cli` with no arguments:

```bash
cargo run --bin openfim-cli
# or execute:
./target/debug/openfim-cli.exe
```

The console opens with a Metasploit-style cyber defense banner, status statistics, and a numbered menu:
- `[1] Quick File Check` — On-demand file inspection, baseline diff, and WhoData forensic event logs.
- `[2] Setup Protection` — Guided wizard: keypair generation, declarative policy creation, digital signing, and baseline database snapshots.
- `[3] Monitor & Remediate` — Real-time sensor daemon with automated active response rollback and quarantine.
- `[4] Forensics & Audit Log` — Cryptographic HMAC chain verification and recent intrusion history.
- `[5] Exit Console` — Clean termination.

*Security Retry Rule*: Entering an invalid option displays an alert in red text and allows up to 3 tries before initiating security lockout and terminating.


---

## License

OpenFIM is licensed under the **Apache License, Version 2.0**. See [`LICENSE`](file:///d:/VibeCode/file_integrity/LICENSE) for the full text.

This matches the `license = "Apache-2.0"` declaration in the workspace `Cargo.toml`, and includes an explicit patent grant — allowing the agent to be deployed, embedded, and redistributed in commercial environments without copyleft obligations.
