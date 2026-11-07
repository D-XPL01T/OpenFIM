# Deployment

Installation assets for running OpenFIM as a long-lived service, plus the operational
steps that are easy to get subtly wrong.

| Path | Purpose |
|---|---|
| [`systemd/openfim-agent.service`](file:///d:/VibeCode/file_integrity/packaging/systemd/openfim-agent.service) | Hardened systemd unit for Linux. |

Windows Service support is **not yet implemented** — see "Windows" below for what
running it there currently looks like and why the service wrapper is not here yet.

---

## Linux (systemd)

### 1. Build and place the binaries

```bash
cargo build --release
sudo install -m 0755 target/release/openfim-agent /usr/local/bin/
sudo install -m 0755 target/release/openfim-cli /usr/local/bin/
```

### 2. Create the directories

```bash
sudo install -d -m 0750 /etc/openfim /var/lib/openfim /var/lib/openfim/backups
```

### 3. Generate the administrative keypair — on a different machine

```bash
openfim-cli policy keygen --out-dir ./openfim-keys
```

The **private** key signs policies and chain checkpoints. It should never live on a
monitored host: an attacker who finds it there can both authorise their own policy and
mint checkpoints matching a forged audit log, which defeats the one check that survives
host compromise.

Copy only the public half to the host:

```bash
sudo install -m 0644 ./openfim-keys/openfim_admin.pub /etc/openfim/
```

### 4. Write and sign the policy

```bash
openfim-cli policy lint --policy policy.yaml        # fix anything it reports
openfim-cli policy sign --policy policy.yaml --privkey ./openfim-keys/openfim_admin.key
sudo install -m 0600 policy.yaml     /etc/openfim/
sudo install -m 0600 policy.yaml.sig /etc/openfim/
```

`policy lint` exits non-zero on anything actionable, so it belongs in CI as well as
here. It catches the configurations that parse but do nothing — a check this platform
cannot enforce, a rule whose own ignore pattern swallows its target, a rule matching no
path on disk.

### 5. Create the chain key

```bash
head -c 32 /dev/urandom | base64 | sudo tee /etc/openfim/chain.key > /dev/null
sudo chmod 600 /etc/openfim/chain.key
```

This is a **root** key: the key that actually signs the audit chain is derived from it
per-database with HKDF-SHA256, so reusing this value across a fleet does not give every
host the same chain key.

The agent **refuses to start** if this file is group- or world-readable, the way OpenSSH
refuses an exposed private key.

### 6. Baseline, and capture pristine copies

```bash
sudo openfim-cli baseline snapshot --dir /etc --db /var/lib/openfim/openfim.db
sudo openfim-cli baseline backup --db /var/lib/openfim/openfim.db \
                                 --out /var/lib/openfim/backups
```

Baseline **before** the host is exposed, and only when you believe its current state is
good: a baseline taken after a compromise records the compromise as correct.

The backup store is only needed for `restore_baseline` active response. It holds verbatim
copies of monitored files, **including any secrets among them**, so protect it to the
same standard as the files it mirrors.

### 7. Install and start the unit

```bash
sudo install -m 0644 packaging/systemd/openfim-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now openfim-agent
```

```bash
systemctl status openfim-agent && journalctl -u openfim-agent -n 50 -o cat
```

The unit sets `--log-format json`, so `-o cat` yields raw JSON lines for a collector to
tail. Each integrity violation is one object with `event_type`, `severity`, `path` and
`change_count` as top-level keys, so a SIEM can filter without parsing prose.

### 8. Take checkpoints off-host — the step people skip

```bash
sudo openfim-cli audit checkpoint \
    --db /var/lib/openfim/openfim.db \
    --privkey ./openfim-keys/openfim_admin.key \
    --ledger ./checkpoints.jsonl \
    --host "$(hostname)"
```

**The ledger's value is entirely in living somewhere the attacker cannot reach.** Stored
next to the database it attests to, it is worth nothing: anyone who can rewrite the
spool can delete the ledger beside it.

Run this from an administrative host on a schedule, pulling each database or running
over SSH, and keep the ledger on that host. To verify:

```bash
openfim-cli audit verify --db openfim.db \
    --checkpoint-ledger checkpoints.jsonl \
    --pubkey openfim_admin.pub
```

Without the ledger, `audit verify` proves no event was edited or deleted by anything
lacking the chain key — but the agent holds that key, so an attacker with host access
could have replaced the whole log. The command says so when run without a ledger.

### What the unit hardening assumes

- **It runs as root**, because a file integrity monitor must read files that exclude
  every other account. The capability set is narrowed to `CAP_DAC_READ_SEARCH` and
  `CAP_LINUX_IMMUTABLE` instead, so an exploited agent cannot load modules, change the
  clock, or open a network socket.
- **`ProtectSystem=strict`** gives a read-only filesystem except `/var/lib/openfim`. If
  you enable `restore_baseline` or `quarantine`, the agent needs write access to the
  monitored directories — add them to `ReadWritePaths` or remediation will fail.
- **`Restart=always` with `StartLimitIntervalSec=0`** on purpose. The default start limit
  would permanently disable the unit after repeated restarts, which is the outcome an
  attacker wants. The startup reconciliation sweep means a restart costs a sweep rather
  than a blind spot.

---

## Windows

**Service installation is not implemented yet.** The agent currently runs as a
foreground process, which means it stops when its console closes and nothing restarts
it — so it is not yet suitable for unattended use on Windows.

Running it manually:

```powershell
$env:OPENFIM_HMAC_KEY = "<root key>"
.\openfim-agent.exe --config policy.yaml --db openfim.db --log-format json
```

What works on Windows today: content hashing, genuine NTFS file identity (volume serial
plus file index), DACL and owner-SID monitoring, alternate data stream detection, the
tamper-evident chain, signed checkpoints, and DPAPI wrapping of the key file so copying
it to another machine renders it useless.

What is missing beyond the service wrapper: `restrict_to_owner` is a no-op, because a
hand-built DACL that is half-correct is worse than an inherited one — it looks
deliberate. The file inherits its directory's ACL, so place `openfim.db` and the key
file in a directory whose ACL you have set.

Implementing the service needs the `windows-service` crate and a dispatcher entry point,
and it needs to be verified on a machine where a service can actually be installed and
restarted — which is why it is not here rather than shipped untested.

---

## Upgrading

The audit chain format is versioned by a domain tag (`openfim.event_spool.v2`). A
database written by a build with a different tag will not verify against a newer one.
That is intentional: reinterpreting old records under new rules would be worse than
refusing them.

To upgrade across a format change, re-baseline into a fresh database and take a new
checkpoint. Keep the old database and its ledger for as long as you need the history.
