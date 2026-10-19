# 11. Interfaces Specification

The OpenFIM system provides four unified interaction surfaces: a high-performance operator CLI, a gRPC agent-manager interface, a RESTful OpenAPI 3.0 control plane, and a modern web management console.

---

## 11.1 CLI Commands Specification

The OpenFIM CLI (`openfim-cli`) provides command-line control for security engineers, system administrators, and CI/CD pipelines.

```
+-----------------------------------------------------------------------------------------+
|                                  OPENFIM-CLI COMMAND TREE                               |
+-----------------------------------------------------------------------------------------+
| openfim-cli                                                                             |
|   ├── baseline                                                                          |
|   │     ├── create   --policy <file> [--output <manifest>] [--sign-key <ed25519.pem>]   |
|   │     ├── verify   --manifest <manifest.json> [--path <dir>]                          |
|   │     ├── diff     --old <v1.json> --new <v2.json>                                    |
|   │     └── promote  --host <id> --ticket <JIRA-ID> [--notes <str>]                     |
|   ├── agent                                                                             |
|   │     ├── status   [--json]                                                           |
|   │     ├── scan     [--mode full|incremental] [--throttle-mb-s <int>]                  |
|   │     ├── rollback --path <file> [--dry-run]                                          |
|   │     └── health   [--check-kernel-ebpf]                                              |
|   ├── policy                                                                            |
|   │     ├── validate --file <policy.yaml>                                               |
|   │     ├── sign     --file <policy.yaml> --key <priv.pem> --out <policy.sig>           |
|   │     └── test     --policy <policy.yaml> --sample-dir <path>                         |
|   └── report                                                                            |
|         └── compliance --standard pci-dss-11.5 --format pdf|csv|json                    |
+-----------------------------------------------------------------------------------------+
```

### Key CLI Execution Examples:
```bash
# 1. Generate an initial signed baseline manifest on a clean gold master
openfim-cli baseline create \
  --policy /etc/openfim/policies/pci_baseline.yaml \
  --output /var/lib/openfim/manifests/v1.0.json \
  --sign-key /root/.keys/ed25519_secops.pem

# 2. Trigger an ad-hoc high-speed incremental scan with 15 MB/s rate limit
openfim-cli agent scan --mode incremental --throttle-mb-s 15

# 3. Two-way baseline comparison diff between two versioned manifests
openfim-cli baseline diff \
  --old /var/lib/openfim/manifests/v1.0.json \
  --new /var/lib/openfim/manifests/v1.1.json
```

---

## 11.2 gRPC Protocol Specification (Agent-to-Manager)

```protobuf
syntax = "proto3";
package openfim.v1;

service AgentIngestionService {
  // Bidirectional streaming connection for real-time telemetry and control commands
  rpc ConnectStream(stream AgentMessage) returns (stream ManagerMessage);
  
  // Batch upload of spooled offline events
  rpc PushSpoolBatch(SpoolBatchRequest) returns (SpoolBatchResponse);
  
  // Fetch active signed policy and baseline manifest
  rpc PullActiveManifest(ManifestRequest) returns (ManifestResponse);
}

message AgentMessage {
  string agent_id = 1;
  uint64 sequence_number = 2;
  int64 timestamp_nano = 3;
  bytes nonce = 4;
  oneof payload {
    Heartbeat heartbeat = 5;
    FileChangeEvent change_event = 6;
    AnomalyEvent anomaly_event = 7;
  }
}

message FileChangeEvent {
  string event_id = 1;
  string path = 2;
  enum ActionType {
    CREATED = 0;
    MODIFIED = 1;
    DELETED = 2;
    ATTRIBUTES_CHANGED = 3;
  }
  ActionType action = 3;
  uint32 severity = 4;
  string old_sha256 = 5;
  string new_sha256 = 6;
  uint64 file_size = 7;
  uint32 mode = 8;
  uint32 uid = 9;
  uint32 gid = 10;
  
  // Who-Data Attribution Block
  ProcessContext process = 11;
  string diff_snippet = 12; // Null if nodiff: true
}

message ProcessContext {
  uint32 pid = 1;
  uint32 ppid = 2;
  uint32 uid = 3;
  uint32 euid = 4;
  string comm = 5;
  string exe_path = 6;
  string cmdline = 7;
  string cgroup = 8;
}

message ManagerMessage {
  uint64 ack_sequence = 1;
  enum CommandType {
    NOOP = 0;
    TRIGGER_SCAN = 1;
    UPDATE_POLICY = 2;
    EXECUTE_ROLLBACK = 3;
    ISOLATE_HOST = 4;
  }
  CommandType command = 2;
  bytes command_payload = 3;
}
```

---

## 11.3 REST API (OpenAPI 3.0 Outline)

The manager provides a standard REST API over HTTPS on port 8443 for web console interactions and automated orchestrations:

- `GET /api/v1/hosts`: Lists all registered endpoints with status, kernel version, and active baseline version.
- `GET /api/v1/hosts/{id}/timeline`: Returns paginated, ECS-normalized change events from ClickHouse.
- `POST /api/v1/baselines/promote`: Approves a detected change, creates an incremented signed manifest, and records a change ticket in the immutable audit ledger.
- `POST /api/v1/policies`: Uploads and cryptographically verifies a new declarative YAML policy bundle.
- `GET /api/v1/reports/compliance/{standard}`: Generates regulatory audit evidence reports (PCI DSS 11.5, NIST 800-53 SI-7).

---

## 11.4 Web Console Wireframe Specifications

```
+-----------------------------------------------------------------------------------------+
| [OpenFIM Logo]  Dashboard   Hosts(4,982)   Timeline   Diff Viewer   Policies   Compliance |
+-----------------------------------------------------------------------------------------+
| SYSTEM HEALTH: [ 4,980 Healthy | 2 Out-of-Sync | 0 Offline ]        SEV-10 ALERTS: [ 0 ]|
+-----------------------------------------------------------------------------------------+
| [ WIDGET 1: 24h Event Volume ]         | [ WIDGET 2: Top Modified Directories ]         |
| 12,410 Expected (Package Updates)      | 1. /var/www/html (4,210 events)                |
|    142 Suspicious (Review Required)    | 2. /etc/nginx    (890 events)                  |
|      3 Critical (Active Response)      | 3. /usr/bin      (420 events)                  |
+-----------------------------------------------------------------------------------------+
| LIVE CHANGE STREAM:                                                                     |
| TIME (UTC)   HOST           PATH             ACTOR           ACTION      SEV    STATUS  |
| 05:34:12     srv-db-01      /etc/shadow      nano (uid=0)    MODIFIED    10     [DIFF]  |
| 05:33:50     web-app-04     /var/www/index   deploy (ci)     MODIFIED    2      [AUTO]  |
| 05:32:01     jump-host      /usr/bin/sshd    dpkg (apt)      MODIFIED    1      [PKG]   |
+-----------------------------------------------------------------------------------------+
```

### The 6 Core Web Console Views:
1. **Executive Dashboard**: Real-time fleet health, event velocity gauge, top changed directories, and active correlation triggers.
2. **Host Detail View**: Agent runtime statistics (RSS memory, CPU, kernel hook mode: eBPF vs fanotify), local spool backlog, and baseline manifest fingerprint.
3. **Change Timeline**: High-velocity forensic timeline querying ClickHouse with millisecond precision, filterable by host, user, container ID, and file path.
4. **Syntax-Highlighted Diff Viewer**: Side-by-side or unified green/red diff display showing exact line additions/deletions for text configuration files (with automatic masking for passwords/keys).
5. **Interactive Policy Editor**: In-browser YAML editor with live schema linting, path glob simulation, regex validation, and Ed25519 signing integration.
6. **Compliance Audit Reports**: One-click regulatory audit packet generator compiling baseline verification proofs, change tickets, and tamper-evident audit logs.
