# 12. Compliance Mapping Matrix

OpenFIM is engineered to satisfy the strictest regulatory compliance requirements for host integrity monitoring and unauthorized change detection.

---

## 12.1 Regulatory Standard Mapping Table

| Framework & Control ID | Regulatory Requirement Summary | OpenFIM Implementation Mechanism | Mandatory Auditor Evidence Generated |
|---|---|---|---|
| **PCI DSS v4.0 Control 11.5.2** | Deploy a change-detection mechanism (e.g. FIM) to detect unauthorized modification of critical system files, configuration files, or content files; perform comparisons at least weekly. | Continuous real-time eBPF/fanotify monitoring + weekly scheduled deep cryptographic baseline sweeps. | Exportable PDF/CSV report certifying baseline comparison timestamp, list of monitored paths, Ed25519 manifest signature, and unresolved alerts. |
| **NIST SP 800-53 Rev. 5 SI-7** | Software, Firmware, and Information Integrity: Employ integrity verification tools to detect unauthorized changes to software, firmware, and information. | SHA-256 and BLAKE3 cryptographic hash verification against offline-signed Merkle trees across `/bin`, `/boot`, `/etc`, and `/usr`. | Cryptographic verification logs, list of flagged binaries, and signed manifest inclusion proofs. |
| **NIST SP 800-53 Rev. 5 SI-7(1)** | Integrity Checks: Perform integrity checks of software, firmware, and information at startup, periodically, and upon command. | Native on-boot sweep (`Before=network.target`), hourly incremental scans, and `openfim-cli agent scan` on-demand execution. | Boot-time audit timestamps, agent startup sequence verification in system journal, and CLI execution logs. |
| **NIST SP 800-53 Rev. 5 SI-7(7)** | Integration of Detection and Response: Incorporate detection of unauthorized changes into the incident response capability. | Guarded Active Response engine with automated rollback and SIEM alert dispatch (CEF / Syslog / Webhook). | Incident response ticket integration (Jira/ServiceNow), rollback audit ledger record, and SIEM forwarder acknowledgments. |
| **CIS Controls v8 Control 8.5** | Authorized Software Monitoring: Ensure that only authorized software is permitted to execute; monitor files for unauthorized changes. | Package manager cross-verification (`dpkg`/`rpm`) + detection of SUID bits and untrusted binary drops into system paths. | Package integrity audit report cross-referencing modified files against official vendor GPG signatures. |
| **CIS Controls v8 Control 10.5** | Centrally Manage Integrity Scanners: Centrally manage file integrity monitoring tools across enterprise endpoints. | Central Manager cluster orchestrating policies, signed manifests, and health heartbeats over mTLS 1.3 across 5,000 agents. | Central fleet inventory report displaying agent versions, policy sync state, and mTLS certificate serial numbers. |
| **ISO/IEC 27001:2022 Control 8.9** | Configuration Management: Configurations, including security configurations, shall be established, documented, implemented, monitored, and reviewed. | Declarative YAML configuration policies enforcing file permissions (`0640`), ownership (`root:shadow`), and content hashes. | Policy enforcement history, diff viewer audit logs of approved configuration changes, and baseline promotion tickets. |
| **ISO/IEC 27001:2022 Control 8.16** | Monitoring Activities: Networks, systems, and applications shall be monitored for abnormal behavior and security events. | Real-time kernel event streaming into ClickHouse with SEM-style multi-vector correlation (CEL rules). | ClickHouse historical change ledger, correlation alert logs, and SOC analyst acknowledgment timestamps. |

---

## 12.2 Automated Compliance Evidence Generation

To eliminate manual audit preparation, the OpenFIM Compliance Reporting Engine compiles cryptographically verifiable **Audit Evidence Bundles**:

### Standard Audit Evidence Package Contents:
1. **Manifest Authenticity Certificate**:
   - The complete JSON baseline manifest containing SHA-256 digests of all in-scope files.
   - The detached Ed25519 cryptographic signature and the corresponding public verification certificate.
2. **Execution Frequency Verification Log**:
   - Cryptographic timestamp logs demonstrating that file integrity scans were executed continuously in real time and that deep sweeps were executed at least once every 7 days (PCI DSS 11.5.2 proof).
3. **Change Attribution & Authorization Trail**:
   - For every change detected during the audit period, a normalized record showing:
     - Exact timestamp (nanosecond UTC)
     - Who made the change (User UID, loginuid, process binary, PPID)
     - The corresponding change ticket reference (e.g. `RFC-10492`)
     - State transition (`UNAUTHORIZED_ANOMALY` vs `APPROVED_PACKAGE_UPDATE`)
4. **Tamper-Evident Ledger Integrity Proof**:
   - Verification output of the HMAC hash chain proving that no intermediate change records were deleted or altered by the administrator during the audit period.
