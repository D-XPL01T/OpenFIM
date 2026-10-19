# 16. Implementation Roadmap & Risk Register

---

## 16.1 Phased Delivery Roadmap

```
+-----------------------------------------------------------------------------------------+
|                                    DELIVERY ROADMAP                                     |
+-----------------------------------------------------------------------------------------+
| Phase 1: MVP (Weeks 1 - 6)   | Standalone Rust Agent + SQLite Baseline + Fanotify       |
|                              | + SHA-256 Hasher + Offline Verifier HTML.                 |
+------------------------------+----------------------------------------------------------+
| Phase 2: v1.0 (Months 2 - 4) | Go Central Manager + PostgreSQL/ClickHouse Ingest        |
|                              | + eBPF Attribution + Package Intelligence + Web Console. |
+------------------------------+----------------------------------------------------------+
| Phase 3: v2.0 (Months 5 - 8) | Windows USN/ETW Support + macOS Endpoint Security        |
|                              | + Guarded Active Response + TPM 2.0 Key Sealing.         |
+-----------------------------------------------------------------------------------------+
```

### Phase 1: MVP Release (Weeks 1 - 6)
- **Scope**: Fully functional standalone Linux agent, local SQLite baseline, fanotify real-time detection, Ed25519 manifest verification, and the standalone browser verifier (`verifier.html`).
- **Exit Criteria**:
  - Agent compiles to a standalone static binary under 10 MB on `x86_64-musl`.
  - Hashing 100,000 files completes under 10 minutes with < 5% CPU utilization.
  - Successfully detects real-time modification of `/etc/shadow` and `/bin/login`.
  - Zero crashes during a 48-hour continuous stress crawl.

### Phase 2: v1.0 Enterprise Production (Months 2 - 4)
- **Scope**: Central Go Manager, gRPC mTLS 1.3 telemetry pipe, PostgreSQL relational store, ClickHouse event store, dpkg/rpm package intelligence resolver, and Web Dashboard.
- **Exit Criteria**:
  - Ingestion cluster tested to 10,000 events/sec sustained load.
  - Routine OS package upgrade (`apt-get upgrade`) triggers zero false critical alerts.
  - Automated compliance evidence export (PDF/CSV) validated against PCI DSS 11.5.

### Phase 3: v2.0 Cross-Platform & Hardening (Months 5 - 8)
- **Scope**: Windows Agent (USN Journal + ETW file filter), macOS Agent (Endpoint Security API), TPM 2.0 platform key sealing, and Guarded Active Response rollback.
- **Exit Criteria**:
  - Atomic file rollback tested and proven race-free via `renameat2(RENAME_EXCHANGE)`.
  - Full feature parity on Windows Server 2022 and Ubuntu 24.04 LTS.

---

## 16.2 Technical Risk Register

| Risk ID | Description & Vulnerability | Likelihood | Impact | Architectural Mitigation Strategy |
|---|---|---|---|---|
| **RSK-01** | Kernel eBPF verifier rejection across varying custom Linux enterprise kernels. | Medium | High | Implement adaptive fallback to Linux Fanotify marks (`FAN_MODIFY`, `FAN_CLOSE_WRITE`) which are stable across all Linux kernels >= 4.19. |
| **RSK-02** | Package manager database locking during concurrent `apt` or `dnf` transactions. | Medium | Medium | The agent never invokes package manager binaries directly; it reads package database files directly with read-only shared locks or inspects file caches in `/var/lib/dpkg/info`. |
| **RSK-03** | Local disk exhaustion on disconnected endpoints with high event volume. | Low | High | Enforce strict 500 MB disk quota on SQLite spool; automatically drop low-severity informational events when spool reaches 90% capacity. |
| **RSK-04** | Accidental automated rollback destroying legitimate production database data. | Low | Critical | Active response is alert-only by default; automated rollback is strictly restricted to static configuration directories and guarded by circuit breakers (max 3 reverts/hour). |

---

## 16.3 Open Technical Questions

1. **Linux Landlock LSM Integration**: Can OpenFIM leverage the newly stabilized Linux Landlock LSM to sandbox its own crawler thread from accessing unmonitored user directories, providing defense-in-depth against parser exploits?
2. **eBPF CO-RE Portability on RHEL 7/8 Backported Kernels**: In enterprise environments with heavily patched non-standard kernel trees, what percentage of hosts require the fallback Fanotify engine versus native Aya eBPF probes?
3. **WebAssembly BLAKE3 SIMD Browser Support**: While Web Crypto API provides native SHA-256, will BLAKE3 Wasm SIMD execution be universally supported across legacy auditor enterprise browsers without degradation?
