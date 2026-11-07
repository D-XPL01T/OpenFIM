# Security Policy

OpenFIM is a defensive file integrity monitor. This document states what it proves,
what it does **not** prove, and how to report a vulnerability in it.

It is deliberately as specific about the limits as the README is about the capabilities.
A security tool that overstates its guarantees is worse than one with fewer of them,
because the operator stops looking.

---

## Reporting a Vulnerability

Please report security issues privately rather than opening a public issue.

- Open a [GitHub security advisory](https://github.com/D-XPL01T/OpenFIM/security/advisories/new)
  on this repository, which is private until published.
- Include the version or commit, the platform, and the smallest reproduction you have.

Expect an acknowledgement within a week. There is no bug bounty: this is a personal
research project, not a funded product.

**In scope:** anything that lets an attacker change a monitored file without OpenFIM
reporting it, forge or destroy audit records undetectably, read secrets OpenFIM was
supposed to keep out of its own storage, or escalate privilege through OpenFIM itself.

**Out of scope:** the unimplemented features listed below and in the README's capability
matrix. They are documented gaps, not vulnerabilities.

---

## What the Audit Chain Proves

Each spooled event is chained with HMAC-SHA256 over **every** security-relevant field —
severity, path, event type, all who-data, both digests, and the diff snippet — with
length prefixing and a domain tag.

This proves, to anyone holding the chain key:

- **No event was edited.** Changing any authenticated field breaks the MAC.
- **No event was deleted from the middle.** A gap in the autoincrement sequence is
  detected.
- **No event was deleted from the end.** A persisted anchor records the expected chain
  head, so truncation is detected rather than verifying as a shorter clean chain.

## What the Audit Chain Does Not Prove

**The chain alone does not survive host compromise.** This is the most important
sentence in this document.

The agent must hold the HMAC key in order to append events. An attacker with root on
the monitored host therefore also holds it, and with it they can discard the spool and
rebuild a clean, internally consistent chain from scratch. Verification then passes.

The mitigation is **signed checkpoints**:

```bash
openfim-cli audit checkpoint --db openfim.db --privkey admin.key --ledger cp.jsonl
```

A checkpoint records the chain head, signed with the Ed25519 **administrative** key —
whose private half lives offline and never touches the monitored host. The agent holds
only the public key, so it can verify checkpoints but cannot mint them. Verifying
against a ledger closes the gap:

```bash
openfim-cli audit verify --db openfim.db --checkpoint-ledger cp.jsonl --pubkey admin.pub
```

Its value is **entirely** in the ledger living somewhere the attacker cannot reach. A
checkpoint ledger stored next to the database it attests to is worth nothing.

Even then, the honest limit: checkpoints make wholesale replacement of the log
**detectable**. They do not prevent tampering, and they do not protect events recorded
*after* a compromise — nothing can, while the signing key needed to append is on the
compromised host. Hardware-backed signing (TPM 2.0 key sealing) is the real answer and
is roadmap Phase 3.

---

## Threat Model Summary

| Adversary capability | OpenFIM's response |
|---|---|
| Modifies a monitored file's contents | Detected: content digest comparison. |
| Modifies it while the agent is stopped | Detected: startup reconciliation sweep. |
| Modifies it during a watcher-overflow window | Detected: overflow is recorded as `WATCH_OVERFLOW` and forces an immediate sweep. |
| Backdates the mtime to hide a change (timestomp) | Detected: content hashing is independent of timestamps. |
| Replaces the file via rename or hardlink swap | Detected: filesystem identity comparison, which runs unconditionally. |
| Replaces a config file with a symlink elsewhere | Detected: entry-kind and symlink-target comparison, also unconditional. |
| Grants itself access via ACL without touching the mode | Detected: POSIX ACL digest on Linux, DACL digest on Windows. |
| Escalates a binary via `security.capability` | Detected: extended attribute digest. |
| Hides a payload in an NTFS alternate data stream | Detected: stream enumeration (names and sizes). |
| Edits or deletes audit records | Detected: HMAC chain plus the persisted anchor. |
| **Deletes the whole audit log and rebuilds it** | Detected **only** with an off-host signed checkpoint ledger. |
| Stops the agent | Visible as a gap: periodic `HEARTBEAT` events and `SENSOR_STOPPED` on clean exit. |
| Deletes the baseline database | Detectable against a retained checkpoint; the database itself is not replicated. |
| Changes a file and OpenFIM reports it | **Not prevented.** OpenFIM detects and optionally rolls back; it is not an access control system. |
| Acts as the user the agent runs as | **Not defended.** See below. |

### Known gaps, stated plainly

- **No process attribution.** OpenFIM reports *what* changed, not *who* changed it.
  A userspace watcher is told the path and nothing about the actor, so events are
  recorded as `UNATTRIBUTED` rather than guessing. Real attribution needs fanotify
  `FAN_REPORT_PIDFD`, eBPF, or a Windows minifilter.
- **Not a preventive control.** OpenFIM is detective. Active response can quarantine or
  roll back *after* the fact, rate-limited by a circuit breaker.
- **ACL monitoring is a digest, not an explanation.** It can tell you the access control
  policy changed; it cannot tell you which entry changed. Parsing security descriptors
  on the scanning path was judged not worth the attack surface (ADR-008).
- **An attacker with the agent's own privileges defeats it.** They can stop it, read its
  key, and rewrite its database. Heartbeats and off-host checkpoints make that
  *visible*; they do not make it impossible.
- **Windows ACL tightening is not implemented.** `restrict_to_owner` is a no-op there:
  a half-correct hand-built DACL is worse than an inherited one, because it looks
  deliberate. The file inherits its directory's ACL, and the operator is told so.

---

## Secret Handling

OpenFIM is a tool that reads files for a living, so the rules about what it writes down
matter.

- **Content diffs are suppressed by default for secret-shaped paths.** `rule.nodiff` is
  tri-state: unset means *suppressed* for paths matching a secret heuristic
  (`shadow`, `*.pem`, `*.key`, `.env`, `id_rsa`, and similar). Forgetting the field
  fails safe. Suppression is applied **before** any content is read, so for such a path
  the bytes never exist in memory destined for the database.
- **Diffs are bounded and never binary.** Capped at 4 KB, binary content refused, and
  unchanged context omitted — so a diff shows what changed, not the surrounding
  material.
- **An explicit `nodiff: false` on a secret-shaped path is flagged** by
  `openfim-cli policy lint` as `SECRET_WITH_DIFF_ENABLED`, which exits non-zero.
- **Private keys are never printed.** `policy keygen` writes the signing key to a file
  with owner-only permissions and prints only the public key. A key written to stdout
  leaks into shell history, terminal scrollback and CI logs.
- **Key material readable by other users is refused.** Like OpenSSH, OpenFIM will not
  start with a group- or world-readable key file. A secret the whole host can read is
  not a secret.
- **The chain key is never logged**, and is read from `OPENFIM_HMAC_KEY` or a file in
  preference to a command-line argument, which is visible to every local user through
  the process table. There is deliberately **no default key**: a built-in one would make
  every deployment's audit chain forgeable by anyone holding the binary.
- **A backup store holds verbatim copies** of monitored files, including secrets if you
  back them up. Protect it to the same standard as the files it mirrors. `policy lint`
  notes this when a `nodiff` path also has `restore_baseline` configured.

---

## Cryptography

| Purpose | Primitive | Notes |
|---|---|---|
| Content digests | SHA-256 (default), BLAKE3, SHA-512 | MD5 and SHA-1 are rejected at parse time, not merely discouraged. |
| Audit chain | HMAC-SHA256 | All event fields, length-prefixed, domain-separated (`openfim.event_spool.v2`). |
| Policy signing | Ed25519 | Detached signatures, verified before the policy is loaded. |
| Chain checkpoints | Ed25519 | Separate domain tag, so a checkpoint signature cannot be replayed as a policy signature. |
| Backup store addressing | SHA-256 | Content-addressed, verified again after restore. |

No custom cryptographic primitives are implemented. All of the above come from
`sha2`, `blake3`, `hmac` and `ed25519-dalek`.

---

## Supported Versions

This is pre-1.0 research software with no released versions. Only `main` is supported,
and there are no security backports.

The audit chain format is versioned by its domain tag. A database written by a build
with a different tag will not verify against this one; that is intentional, and such a
database needs re-baselining rather than reinterpretation.
