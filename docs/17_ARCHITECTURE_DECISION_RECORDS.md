# 17. Architecture Decision Records (ADRs)

---

### ADR-001: Language Choice for the Endpoint Agent
- **Status**: ACCEPTED
- **Context**: The endpoint FIM agent executes as a privileged root daemon on production Linux servers, requiring absolute memory safety, minimal memory footprint, low CPU usage, and high-performance kernel event handling.
- **Decision**: Implement the endpoint agent in **Rust**.
- **Consequences**:
  - *Positive*: Zero garbage collection pauses, predictable sub-15MB memory footprint, compile-time memory safety eliminating buffer overflow risks, and direct C-ABI interoperability with Aya eBPF and libc.
  - *Negative*: Steeper learning curve and longer compilation times compared to Go.
- **Alternatives Considered**: 
  - *C/C++*: Rejected due to high risk of memory corruption vulnerabilities in daemons parsing untrusted file systems.
  - *Go*: Rejected due to garbage collection memory spikes, higher resident set size (>35MB), and less idiomatic kernel eBPF memory sharing.

---

### ADR-002: Storage Engine for Agent Local Baseline & Spool
- **Status**: ACCEPTED
- **Context**: The agent requires local persistence for baseline state and offline event spooling during network disconnections.
- **Decision**: Utilize **SQLite in Write-Ahead Log (WAL) mode** with memory-mapped I/O (`rusqlite`).
- **Consequences**:
  - *Positive*: Full ACID transactional consistency, high-speed multi-index queries for diff calculations, automatic crash recovery on power loss, and zero background daemon processes.
  - *Negative*: Slightly higher binary size (~1.5 MB) compared to bare flat-file formats.
- **Alternatives Considered**:
  - *LMDB*: Rejected due to higher operational complexity in managing secondary indexes and dynamic schema migrations.
  - *Flat JSON/CBOR files*: Rejected due to lack of atomic crash recovery and the need to re-serialize the entire database on single-file mutations.

---

### ADR-003: Real-Time Kernel Interception Strategy
- **Status**: ACCEPTED
- **Context**: Detecting file changes in real-time requires kernel-level hooks. Linux environments range from modern 6.x kernels in public clouds to older 4.19+ enterprise kernels.
- **Decision**: Implement an **Adaptive Dual-Engine**: eBPF CO-RE (via Aya) as primary on Linux >= 5.8, with automatic fallback to Linux Fanotify (`FAN_MODIFY`, `FAN_CLOSE_WRITE`) on older kernels.
- **Consequences**:
  - *Positive*: Delivers deep, low-overhead process attribution via eBPF on modern systems while ensuring seamless backward compatibility on legacy enterprise distributions.
  - *Negative*: Requires maintaining two kernel event consumer implementations within the agent.
- **Alternatives Considered**:
  - *Pure inotify*: Rejected due to directory recursion limits, lack of filesystem-wide marks, and silent event drops during `IN_Q_OVERFLOW`.
  - *Linux Auditd Netlink Socket*: Rejected due to heavy CPU overhead (4-8%) and socket buffer competition with host `auditd`.

---

### ADR-004: Manager Telemetry & Event Storage Architecture
- **Status**: ACCEPTED
- **Context**: The central manager must ingest up to 10,000 events/sec from 5,000 endpoints and provide sub-second query performance across months of forensic history.
- **Decision**: Deploy a **Hybrid PostgreSQL 16 + ClickHouse** datastore architecture.
- **Consequences**:
  - *Positive*: PostgreSQL provides ACID guarantees for agent enrollment, RBAC, and signed manifests; ClickHouse provides columnar indexing with 10x compression and instant aggregations across millions of events.
  - *Negative*: Requires operating and backing up two distinct database engines.
- **Alternatives Considered**:
  - *Pure PostgreSQL*: Rejected due to vacuum degradation and disk bloat under 10k events/sec write pressure.
  - *Elasticsearch*: Rejected due to heavy JVM memory consumption, garbage collection pauses, and substantial server hardware costs.

---

### ADR-005: Cryptographic Baseline Integrity Verification
- **Status**: ACCEPTED
- **Context**: Storing baselines locally on endpoints introduces the risk that an attacker who escalates to root can alter the baseline database to conceal dropped backdoors.
- **Decision**: Compile baseline manifests into a **Merkle Tree** and authenticate the Merkle Root with an external **Ed25519 digital signature**.
- **Consequences**:
  - *Positive*: Provides $O(1)$ signature verification on agent boot and $O(\log N)$ cryptographic inclusion proofs for individual files, with mathematical immunity against local baseline tampering.
  - *Negative*: Baseline updates require signing via a private key held outside the standard agent runtime.
- **Alternatives Considered**:
  - *Signing Individual SQLite Rows*: Rejected due to prohibitive CPU overhead during initial baseline verification across 100,000 files.
  - *HMAC with symmetric local key*: Rejected because an attacker with root privileges can extract the symmetric key from agent memory.

---

### ADR-006: Policy & Stateful Correlation Grammar
- **Status**: ACCEPTED
- **Context**: Correlation rules must express multi-stage attack scenarios across sliding time windows without requiring code recompilation or unsafe arbitrary script execution.
- **Decision**: Standardize on **Declarative YAML Rules with Common Expression Language (CEL)** evaluation.
- **Consequences**:
  - *Positive*: Memory-safe, non-Turing-complete, highly auditable rule grammar with sub-microsecond evaluation speeds and zero sandbox escape vulnerabilities.
  - *Negative*: Slightly less expressive for complex procedural loops compared to embedded Lua.
- **Alternatives Considered**:
  - *Embedded Lua / Python*: Rejected due to security vulnerabilities associated with running scripting interpreters inside privileged security daemons.
  - *Static Regex*: Rejected due to inability to evaluate multi-event temporal relationships.

---

### ADR-007: Client-Side Verifier Delivery Model
- **Status**: ACCEPTED
- **Context**: Operators, auditors, and forensic teams frequently need to verify files and manifests in disconnected, air-gapped environments without installing third-party binaries or uploading sensitive files to cloud services.
- **Decision**: Package the verifier as a **Self-Contained Standalone HTML5 Application** leveraging the browser's native **Web Crypto API**.
- **Consequences**:
  - *Positive*: Zero installation, zero cloud upload (100% client-side memory execution), double-clickable on air-gapped workstations, and completely free of build-tool dependencies.
  - *Negative*: Browser memory limits on older browsers require chunked streaming for ultra-large files (>5 GB).
- **Alternatives Considered**:
  - *Server-Side Upload Portal*: Rejected because uploading sensitive proprietary ISOs or binaries violates enterprise security and data sovereignty policies.
  - *CLI-Only Tool*: Rejected because non-technical compliance auditors require an intuitive visual interface with color-coded integrity indicators.
