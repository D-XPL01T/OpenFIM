# 5. Policy & Rule Engine

The OpenFIM Policy Engine evaluates monitored filesystem paths against human-readable, cryptographically signed declarative YAML policy manifests. 

---

## 5.1 Policy Grammar & Schema Specification

Every policy file contains metadata, global scanning throttles, and an ordered list of rule definitions:

```yaml
version: "1.0"
policy_id: "pol-linux-pci-baseline"
name: "Production Linux Hardened FIM Policy"
author: "Security Architecture Team"
signature_algorithm: "ed25519"

globals:
  default_hash: "sha256"              # sha256 | blake3 | sha512
  max_io_rate_mb_s: 20                # Throttle disk read during full scans
  scan_nice_priority: 10              # Process priority for crawler thread
  realtime_fallback_sweep_interval: 3600 # Fallback deep scan every 1 hour

rules:
  - id: "RULE_IDENTIFIER"
    description: "Human readable purpose"
    paths:
      - "/path/pattern"               # Supports exact paths, directory roots, and globs
    recursive: true                   # Walk directory sub-trees
    mode: "realtime"                  # realtime | scheduled | on_boot
    checks:
      hash: true                      # Compute cryptographic content hash
      size: true                      # File size in bytes
      permissions: true               # UNIX mode (octal permissions, SUID, SGID)
      ownership: true                 # UID and GID
      timestamps: false               # Track mtime (false to avoid false positives)
      attributes: true                # Inode, hardlink count, device ID
      xattrs: true                    # Extended attributes (SELinux, AppArmor, capabilities)
    nodiff: false                     # If true, suppresses recording file byte diffs in alerts
    ignore:
      - "*.tmp"                       # Glob ignore patterns
      - "/path/regex_pattern"         # Regex ignore paths
    severity: 8                       # 1 (Informational) to 10 (Critical Incident)
    whodata: true                     # Capture acting PID, UID, process path via eBPF
    active_response:
      action: "none"                  # none | restore_baseline | kill_process | quarantine
```

---

## 5.2 Enterprise Linux Production Security Policy

Below is the complete reference policy configuration for production Linux servers, fully mapped to PCI DSS 11.5, NIST 800-53 SI-7, and CIS Linux Benchmarks.

```yaml
version: "1.0"
policy_id: "pol-linux-enterprise-server-v1"
name: "CIS Benchmark & PCI DSS 11.5 Defensive Linux Policy"
author: "Principal Security Architect"
signature_algorithm: "ed25519"

globals:
  default_hash: "sha256"
  max_io_rate_mb_s: 25
  scan_nice_priority: 10
  realtime_fallback_sweep_interval: 7200

rules:
  # =========================================================================
  # 1. CORE AUTHENTICATION & PRIVILEGED CONFIGURATION (/etc)
  # =========================================================================
  - id: "ETC_AUTH_CRITICAL"
    description: "Monitors core authentication credentials and privilege escalation gates"
    paths:
      - "/etc/passwd"
      - "/etc/shadow"
      - "/etc/group"
      - "/etc/gshadow"
      - "/etc/sudoers"
      - "/etc/sudoers.d"
      - "/etc/pam.d"
      - "/etc/security"
    recursive: true
    mode: "realtime"
    checks:
      hash: true
      size: true
      permissions: true
      ownership: true
      timestamps: false               # Ignore mtime; focus purely on content and permissions
      attributes: true
      xattrs: true
    nodiff: true                      # CRITICAL: Prevent leakage of hashed passwords in /etc/shadow
    severity: 10
    whodata: true
    active_response:
      action: "none"                  # Alert-only; manual SOC approval required for auth rollback
    # Justification: Tampering with /etc/shadow or /etc/sudoers is the hallmark of backdoor creation 
    # and privilege persistence. nodiff: true prevents sensitive credential leakage.

  # =========================================================================
  # 2. SYSTEM BINARIES & PRIVILEGED EXECUTABLES (/bin, /sbin, /usr)
  # =========================================================================
  - id: "SYSTEM_BINARIES_IMMUTABLE"
    description: "Guards root-owned system binaries against rootkits and trojans"
    paths:
      - "/bin"
      - "/sbin"
      - "/usr/bin"
      - "/usr/sbin"
      - "/usr/local/bin"
      - "/usr/local/sbin"
      - "/lib"
      - "/lib64"
      - "/usr/lib"
    recursive: true
    mode: "realtime"
    checks:
      hash: true
      size: true
      permissions: true
      ownership: true
      timestamps: false
      attributes: true
      xattrs: true
    nodiff: true                      # Binaries do not produce meaningful text diffs
    ignore:
      - "/usr/lib/locale/**"          # Ignore high-churn locale compile caches
      - "/usr/lib/modules/**/modules.*" # Ignore dynamic kernel module map files
    severity: 9
    whodata: true
    active_response:
      action: "quarantine"            # Isolate unauthorized modified binaries
    # Justification: Detects trojanized binaries (e.g. backdoored sshd, ps, netstat) and SUID binary drops.

  # =========================================================================
  # 3. KERNEL & BOOT-TIME INTEGRITY (/boot)
  # =========================================================================
  - id: "BOOT_INTEGRITY"
    description: "Detects bootkits, malicious initramfs injections, and grub bootloader alterations"
    paths:
      - "/boot"
    recursive: true
    mode: "realtime"
    checks:
      hash: true
      size: true
      permissions: true
      ownership: true
      timestamps: false
      attributes: true
      xattrs: true
    nodiff: true
    severity: 10
    whodata: true
    active_response:
      action: "none"
    # Justification: Any modification to vmlinuz or initramfs represents an existential machine compromise.

  # =========================================================================
  # 4. SECURE SHELL INFRASTRUCTURE & CREDENTIALS
  # =========================================================================
  - id: "SSH_DAEMON_AND_KEYS"
    description: "Detects unauthorized SSH server alterations and backdoored root authorized_keys"
    paths:
      - "/etc/ssh"
      - "/root/.ssh"
      - "/home/*/.ssh"
    recursive: true
    mode: "realtime"
    checks:
      hash: true
      size: true
      permissions: true
      ownership: true
      timestamps: false
      attributes: true
      xattrs: true
    nodiff: false                     # Allows SOC to see unauthorized public key strings injected
    ignore:
      - "**/.ssh/known_hosts*"        # Known hosts rotate on outbound connections
    severity: 9
    whodata: true
    active_response:
      action: "restore_baseline"      # Automatically revert unauthorized injected root keys
    # Justification: Injected authorized_keys are the primary method of backdoor persistence.

  # =========================================================================
  # 5. SCHEDULED TASKS & PERSISTENCE HOOKS (Cron & Systemd)
  # =========================================================================
  - id: "PERSISTENCE_CRON_SYSTEMD"
    description: "Monitors cron tables, at jobs, systemd service units, and init scripts"
    paths:
      - "/etc/cron*"
      - "/etc/crontab"
      - "/var/spool/cron"
      - "/etc/systemd/system"
      - "/lib/systemd/system"
      - "/etc/init.d"
      - "/etc/rc.local"
    recursive: true
    mode: "realtime"
    checks:
      hash: true
      size: true
      permissions: true
      ownership: true
      timestamps: false
      attributes: true
      xattrs: true
    nodiff: false                     # Review textual unit changes and cron commands
    severity: 8
    whodata: true
    active_response:
      action: "none"
    # Justification: Adversaries commonly establish persistence via rogue cron jobs or systemd services.

  # =========================================================================
  # 6. DYNAMIC WEB APPLICATION ROOTS (/var/www)
  # =========================================================================
  - id: "WEB_ROOT_INTEGRITY"
    description: "Protects web application code against webshell injection and code defacement"
    paths:
      - "/var/www/html"
      - "/srv/www"
    recursive: true
    mode: "realtime"
    checks:
      hash: true
      size: true
      permissions: true
      ownership: true
      timestamps: false
      attributes: true
      xattrs: false
    nodiff: false
    ignore:
      - "**/cache/**"                 # Ignore dynamic application cache files
      - "**/logs/**"                  # Ignore application runtime logs
      - "**/uploads/**"               # Dynamic uploads tracked separately for execution flags
    severity: 9
    whodata: true
    active_response:
      action: "none"
    # Justification: Detects uploaded webshells (e.g. .php, .jsp) and unauthorized modifications to index files.
```

---

## 5.3 Policy Parsing & Evaluation Mechanics

1. **Deterministic Glob & Regex Matching**:
   - The agent compiles glob patterns into a prefix trie and evaluates file paths in $O(\log N)$ time.
2. **Rule Precedence**:
   - More specific path rules override broader parent directory rules (e.g., `/etc/shadow` rule with `nodiff: true` overrides the generic `/etc` rule).
3. **Cryptographic Signature Verification**:
   - Every policy file is signed with an accompanying `.sig` file containing an Ed25519 signature generated by the security administrator. The agent refuses to load any policy with an invalid signature or mismatched policy hash.
