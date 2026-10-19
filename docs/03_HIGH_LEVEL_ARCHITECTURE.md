# 3. High-Level Architecture

## 3.1 System Component Architecture

The OpenFIM architecture is divided into three distinct operational domains:
1. **Endpoint Agent (Rust)**: High-performance, low-footprint daemon running on monitored targets (bare metal, VMs, Kubernetes worker nodes).
2. **Central Manager Cluster (Go)**: Horizontally scalable ingestion, policy management, baseline orchestration, and correlation platform backed by PostgreSQL and ClickHouse.
3. **Auditor / Operator Tools**: Modern browser-based web console, admin CLI, and an offline zero-upload client-side verifier.

```mermaid
flowchart TB
    subgraph AUDITOR_OPERATOR_TIER["Auditor & Operator Tier"]
        CLI["OpenFIM Admin CLI (Rust/Go)"]
        WEB["OpenFIM Web Console (Vue/Vite)"]
        VERIFIER["Standalone Browser Verifier (HTML5/WebCrypto/Wasm)"]
    end

    subgraph MANAGER_CLUSTER["Central Manager Tier (Go)"]
        direction TB
        API_GW["gRPC / REST API Gateway (mTLS 1.3, TLS Termination)"]
        
        subgraph MANAGER_SERVICES["Manager Micro-Services"]
            AUTH_SRV["Auth & Agent Enrollment Service"]
            POLICY_SRV["Policy & Baseline Manifest Orchestrator"]
            CORR_ENGINE["Stateful Correlation Engine (CEL / Sliding Windows)"]
            ALERT_ROUTER["Alert Dispatcher & SIEM Forwarder"]
            PACKAGE_INTEL["Package Repo & Known-Good Hash Resolver"]
        end

        subgraph MANAGER_DATASTORE["Manager Storage Cluster"]
            PG_DB[("PostgreSQL 16: Relational State\n- Hosts & Agent Inventory\n- Policies & YAML Definitions\n- Signed Manifest Registry\n- Audit Ledger (HMAC chained)")]
            CH_DB[("ClickHouse: High-Volume Analytics\n- Partitioned Change Event Telemetry\n- Process Attribution Lineage\n- Raw Forensic Telemetry")]
        end
    end

    subgraph ENDPOINT_TIER["Monitored Endpoint (Linux / Win / macOS)"]
        direction TB
        
        subgraph KERNEL_SPACE["Host Kernel Space"]
            EBPF_PROG["eBPF Probes (CO-RE Aya): sys_enter_openat2, vfs_write"]
            FANOTIFY_ENG["Fanotify Engine: FAN_MODIFY, FAN_CLOSE_WRITE"]
            RING_BUF[("Kernel BPF Ring Buffer / Fanotify Queue")]
        end

        subgraph AGENT_USER_SPACE["OpenFIM Agent (Rust Daemon: openfim-agent)"]
            SENSOR["Event Consumer & Kernel Multiplexer"]
            ATTR_ENG["Process Attribution Engine (/proc, cgroups, eBPF ctx)"]
            THROTTLE_HASH["Streaming Hasher (SHA-256 / BLAKE3, 64KB, posix_fadvise)"]
            POLICY_EVAL["Local Policy Evaluator & Diff Engine"]
            LOCAL_STORE[("Local SQLite WAL Database:\n- Active Signed Baseline Cache\n- Encrypted Offline Event Ring Spool")]
            CRYPTO_MOD["Ed25519 Manifest Verifier & HMAC Logger"]
            COMM_MGR["mTLS gRPC Client & Compression (zstd)"]
            WATCHDOG["Local Watchdog / Systemd Supervisor"]
        end
    end

    subgraph EXTERNAL_DESTINATIONS["External Enterprise Systems"]
        SIEM["Enterprise SIEM (Splunk, Elastic, Sentinel, Chronicle)"]
        SLACK["Alert Channels (Slack, Teams, PagerDuty, Webhook)"]
        OS_REPOS["Vendor Repos (Ubuntu, RHEL, Alpine Package Mirrors)"]
    end

    %% Wiring
    CLI -->|mTLS / REST| API_GW
    WEB -->|HTTPS / JWT| API_GW
    VERIFIER -.->|Air-gapped Manifest Drop| WEB

    EBPF_PROG --> RING_BUF
    FANOTIFY_ENG --> RING_BUF
    RING_BUF --> SENSOR
    SENSOR --> ATTR_ENG
    ATTR_ENG --> POLICY_EVAL
    POLICY_EVAL --> THROTTLE_HASH
    THROTTLE_HASH --> LOCAL_STORE
    LOCAL_STORE --> CRYPTO_MOD
    CRYPTO_MOD --> COMM_MGR
    WATCHDOG -.->|Supervises| AGENT_USER_SPACE

    COMM_MGR <==|Bidirectional mTLS 1.3 (gRPC + zstd)|==> API_GW

    API_GW --> AUTH_SRV
    API_GW --> POLICY_SRV
    API_GW --> CORR_ENGINE
    
    POLICY_SRV <--> PG_DB
    AUTH_SRV <--> PG_DB
    CORR_ENGINE --> CH_DB
    COMM_MGR -.->|Event Ingest Batch| CH_DB
    PACKAGE_INTEL <--> OS_REPOS
    PACKAGE_INTEL --> PG_DB

    CORR_ENGINE --> ALERT_ROUTER
    ALERT_ROUTER --> SIEM
    ALERT_ROUTER --> SLACK
```

---

## 3.2 End-to-End Data Flow Architecture

The data flow diagram below traces a file tampering event from initial file modification in kernel space to process attribution, cryptographic hashing, local SQLite buffering, central ingestion, sliding-window correlation, and SIEM alerting.

```mermaid
sequenceDiagram
    autonumber
    actor Adversary as Attacker / Rogue Process
    participant Kernel as Linux Kernel (VFS / eBPF / Fanotify)
    participant Agent as OpenFIM Agent (Rust)
    participant LocalDB as Local SQLite WAL (Spool)
    participant Manager as Central Manager (Go Ingestion)
    participant ClickHouse as ClickHouse Event Store
    participant CEL as CEL Correlation Engine
    participant SIEM as SOC SIEM / Alert Router

    Note over Adversary,Kernel: Step 1: Malicious File Write
    Adversary->>Kernel: openat2("/etc/sudoers", O_WRONLY) + write() + close()
    
    Note over Kernel,Agent: Step 2: Kernel Interception & Attribution
    Kernel->>Agent: BPF RingBuffer Event: FAN_CLOSE_WRITE + PID=4892, UID=0, PPID=4810, Comm="nano"
    Agent->>Agent: Capture Process Context: /proc/4892/exe, cmdline, cgroup, TTY
    
    Note over Agent: Step 3: Throttled Hashing & Policy Evaluation
    Agent->>Agent: Check Policy for "/etc/sudoers" -> Hash required: SHA-256
    Agent->>Agent: Stream read (64KB chunks, posix_fadvise DONTNEED) -> Compute SHA-256
    Agent->>Agent: Compare against local active baseline SQLite cache -> MISMATCH DETECTED
    
    Note over Agent,LocalDB: Step 4: Local Immutability & Event Spooling
    Agent->>LocalDB: Append to local encrypted spool (HMAC chained record)
    
    Note over Agent,Manager: Step 5: Secure Transport
    Agent->>Manager: gRPC StreamEventBatch (mTLS 1.3, zstd compressed)
    Manager->>ClickHouse: INSERT into fim_change_events (partitioned by day)
    Manager->>LocalDB: ACK Event Batch -> Agent marks local spool record processed
    
    Note over Manager,CEL: Step 6: SEM-Style Stateful Correlation
    Manager->>CEL: Evaluate Correlation Rule: "Sudoers_Mod + New_User_Within_300s"
    CEL->>ClickHouse: Query sliding window [T - 300s, T] for related host telemetry
    CEL-->>Manager: Rule Matched: Severity 9.5 (Critical Privilege Escalation)
    
    Note over Manager,SIEM: Step 7: Notification & SIEM Routing
    Manager->>SIEM: Stream ECS JSON Alert over TLS Syslog
    Manager->>SIEM: Fire Webhook to PagerDuty / SOC Alert Channel
```

---

## 3.3 Core Design Decisions & Trade-Offs

1. **Rust for Endpoint Agent**:
   - *Rationale*: Zero runtime garbage collection avoids unpredictable memory and CPU latency spikes on production database/web servers, while memory safety prevents buffer overflows in untrusted file parsers.
   - *Alternative Rejected*: C/C++ (high risk of memory corruption vulnerabilities in daemons running as root); Go (higher resident memory footprint >35MB and runtime GC jitter).
2. **Go for Central Manager**:
   - *Rationale*: Excellent native gRPC/Protobuf concurrency, rapid development velocity, mature cloud-native ecosystem, and simple single-binary deployment for the backend services.
   - *Alternative Rejected*: Java/Spring (heavyweight enterprise footprint like SolarWinds SEM); Python (insufficient throughput for 10k events/sec ingestion).
3. **Hybrid PostgreSQL + ClickHouse Manager Datastore**:
   - *Rationale*: PostgreSQL excels at ACID-compliant relational asset registries, user permissions, and signed baseline manifest storage, while ClickHouse delivers sub-second analytical querying across billions of change events with 5x-10x zstd compression.
   - *Alternative Rejected*: Pure PostgreSQL (struggles with index bloat and high write throughput at 10,000 events/sec sustained); Elasticsearch (resource-intensive JVM cluster requiring substantial RAM).
4. **Local SQLite WAL for Agent Offline Spooling**:
   - *Rationale*: SQLite in Write-Ahead Log (WAL) mode provides crash-resilient local persistence, low CPU overhead (<5MB memory), and zero daemon maintenance for disconnected operation.
   - *Alternative Rejected*: Flat JSON log spooling (susceptible to file truncation on power loss); Redis/RocksDB (excessive binary bloat and memory footprint).
5. **gRPC over mTLS 1.3 Transport**:
   - *Rationale*: Strict bidirectional authentication with client certificate pinning, HTTP/2 multiplexing, compact Protobuf binary serialization, and built-in streaming backpressure.
   - *Alternative Rejected*: Unencrypted syslog/UDP (vulnerable to eavesdropping and packet loss); Custom proprietary TCP framing (high development and maintenance overhead).
