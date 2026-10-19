# 15. Deployment & Operations

OpenFIM is engineered for seamless rollout across bare-metal datacenters, multi-cloud virtual machines, and containerized Kubernetes clusters.

---

## 15.1 Packaging & System Requirements

| Artifact | Target Platform | Build Specs & Dependencies |
|---|---|---|
| **`openfim-agent`** | Linux (x86_64, aarch64) | Statically compiled via Rust `musl` target. Zero dynamic library dependencies. Packed as `.deb` and `.rpm`. |
| **`openfim-manager`**| Linux Server | Single Go binary with embedded web assets. Distributed as binary and official OCI container image. |
| **`openfim-daemonset`**| Kubernetes / OpenShift | Privileged DaemonSet mounting `/` as `/host` (read-only for crawler, r/w for baseline cache). |
| **`verifier.html`** | Cross-Platform Browser | Single, zero-dependency offline HTML/JS file for auditor workstations. |

### Systemd Service Configuration (`openfim-agent.service`):
```ini
[Unit]
Description=OpenFIM Defensive Integrity Sensor
Documentation=https://github.com/openfim/openfim
After=local-fs.target
Before=network.target

[Service]
Type=notify
ExecStart=/usr/local/bin/openfim-agent --config /etc/openfim/agent.yaml
Restart=always
RestartSec=3s
WatchdogSec=10s

# Resource Constraints & Hardening
CPUQuota=10%
MemoryMax=64M
TasksMax=32
Nice=10
ProtectSystem=full
ProtectHome=read-only
ReadOnlyPaths=/usr /bin /sbin /lib /lib64
ReadWritePaths=/var/lib/openfim /var/log/openfim

[Install]
WantedBy=multi-user.target
```

---

## 15.2 Kubernetes DaemonSet Architecture

For containerized environments, `openfim-agent` runs as a DaemonSet to monitor host nodes and container storage layers:

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: openfim-agent
  namespace: security-system
spec:
  selector:
    matchLabels:
      app: openfim-agent
  template:
    metadata:
      labels:
        app: openfim-agent
    spec:
      hostPID: true                   # Required for accurate process attribution in host namespaces
      hostNetwork: false
      containers:
        - name: agent
          image: ghcr.io/openfim/agent:v1.0.0
          securityContext:
            privileged: false
            capabilities:
              add: ["CAP_SYS_ADMIN", "CAP_BPF", "CAP_DAC_READ_SEARCH"]
          resources:
            limits:
              cpu: "100m"
              memory: "64Mi"
            requests:
              cpu: "20m"
              memory: "24Mi"
          volumeMounts:
            - name: host-root
              mountPath: /host
              readOnly: true
            - name: host-sys-kernel
              mountPath: /sys/kernel
            - name: agent-storage
              mountPath: /var/lib/openfim
      volumes:
        - name: host-root
          hostPath:
            path: /
        - name: host-sys-kernel
          hostPath:
            path: /sys/kernel
        - name: agent-storage
          hostPath:
            path: /var/lib/openfim
            type: DirectoryOrCreate
```

---

## 15.3 Observability & Prometheus Metrics

The agent and manager export standard Prometheus metrics at `:9100/metrics`:
- `openfim_agent_memory_rss_bytes`: Resident memory in bytes.
- `openfim_agent_scanned_files_total`: Number of files inspected.
- `openfim_events_detected_total{severity="10"}`: Counter of tampering events by severity.
- `openfim_kernel_buffer_overflows_total`: Counter of `FAN_Q_OVERFLOW` events.
- `openfim_offline_spool_backlog_records`: Number of unsent events stored in local SQLite.

---

## 15.4 Incident Response Runbook for Confirmed Tampering

When a `SEV_10_UNAUTHORIZED_MODIFICATION` alert fires in the SOC:

```
+-----------------------------------------------------------------------------------------+
|                         INCIDENT RESPONSE RUNBOOK: FIM-01                               |
+-----------------------------------------------------------------------------------------+
| 1. TRIAGE & ATTRIBUTION:                                                                |
|    - Open OpenFIM Web Console -> Host View.                                             |
|    - Review "Process Attribution": Identify acting UID, PPID, executable path, and TTY.|
|    - Check if change maps to an open Jira/ServiceNow RFC ticket.                        |
|                                                                                         |
| 2. EVIDENCE PRESERVATION:                                                               |
|    - Trigger memory snapshot & download signed cryptographic event proof from console.  |
|    - Ensure local spool is intact and HMAC chain verified.                              |
|                                                                                         |
| 3. CONTAINMENT & REMEDIATION:                                                           |
|    - If unauthorized backdoor confirmed:                                                |
|      a. Issue network isolation command via Manager: openfim-cli agent isolate --host X |
|      b. Terminate acting rogue PID tree: kill -9 <PID>                                  |
|      c. Atomic rollback: openfim-cli agent rollback --path <tampered_file>              |
|                                                                                         |
| 4. ROOT-CAUSE ANALYSIS & CLOSURE:                                                       |
|    - Inspect parent process cmdline and network connections in ClickHouse timeline.     |
|    - Generate incident audit packet for compliance compliance team.                     |
+-----------------------------------------------------------------------------------------+
```
