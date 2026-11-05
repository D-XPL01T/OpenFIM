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
| **13** | [`13_PERFORMANCE_SCALE_RELIABILITY.md`](file:///d:/VibeCode/file_reliability/docs/13_PERFORMANCE_SCALE_RELIABILITY.md) | Resource budgets (<15MB RSS, <1% CPU), IOPS throttling, backpressure, 5,000 endpoint sizing. |
| **14** | [`14_TESTING_AND_VALIDATION.md`](file:///d:/VibeCode/file_integrity/docs/14_TESTING_AND_VALIDATION.md) | Unit/integration testing, red-team evasion validation suite (timestomp, hardlink swap, TOCTOU). |
| **15** | [`15_DEPLOYMENT_AND_OPERATIONS.md`](file:///d:/VibeCode/file_integrity/docs/15_DEPLOYMENT_AND_OPERATIONS.md) | Packaging (deb/rpm/oci), Ansible/Helm deployment, observability metrics, incident runbooks. |
| **16** | [`16_ROADMAP.md`](file:///d:/VibeCode/file_integrity/docs/16_ROADMAP.md) | MVP (6 weeks), v1.0, v2.0 roadmap milestones, risk register, open technical questions. |
| **17** | [`17_ARCHITECTURE_DECISION_RECORDS.md`](file:///d:/VibeCode/file_integrity/docs/17_ARCHITECTURE_DECISION_RECORDS.md) | ADR-001 through ADR-007 covering all fundamental architectural trade-offs. |
| **Plan** | [`BUILD_ORDER_CHECKLIST.md`](file:///d:/VibeCode/file_integrity/docs/BUILD_ORDER_CHECKLIST.md) | Concrete day-by-day implementation checklist for Weeks 1 and 2. |

## Standalone Artifacts
- **Client-Side Verifier Tool**: [`web/verifier.html`](file:///d:/VibeCode/file_integrity/web/verifier.html) (Zero-upload, offline streaming checksum & manifest verifier running 100% in the browser).

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

