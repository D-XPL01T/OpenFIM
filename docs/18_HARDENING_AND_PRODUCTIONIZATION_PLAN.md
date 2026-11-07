# 18. Hardening & Productionization Plan

**Status:** In progress — Phase 0 complete; Phase 1 partially complete
**Created:** 2026-11-07
**Baseline commit:** `6154173` (post-audit, 97 tests passing, clippy clean)

## Progress

| Phase | State | Notes |
|---|---|---|
| **Phase 0** — documentation truth | **done** | Capability matrix and limitations published; checklist claims corrected. |
| **Phase 1** — policy contract | **done** | 1.1–1.5 (`detect.rs`, all call sites routed), 1.6–1.8 (xattr, ACL and owner-SID capture), 1.9 (attributes split from permissions), 1.10–1.13 (globals honoured, spool quota), 1.14–1.17 (rule modes, reconciliation sweep, overflow detection, heartbeats), 1.18–1.20 (bounded diff capture with fail-safe `nodiff`), 1.21–1.23 (schema closed, `policy lint`, capability matrix as code). |
| **Phase 2** — operational hardening | **partial** | Done: 2.1–2.4 (content-addressed backup store, `baseline backup`, digest-verified restore, legacy layout refused), 2.5 + 2.12 (owner-only state and key material, exposed keys refused), 2.7 (self-monitoring of own binary, policy, key and baseline), 2.8–2.9 (Ed25519 signed off-host checkpoints and `audit verify --checkpoint-ledger`), 2.13 (SECURITY.md threat model), 2.14–2.15 (spool quota, `audit stats`). Outstanding: 2.17 (Windows Service, which needs a machine where a service can actually be installed and verified). Also done: 2.16 (hardened systemd unit), 2.18 (structured logging with JSON output), 2.19 (restart reconciliation, via the startup sweep). Also done: 2.6 (opt-in Linux append-only spool), 2.10 (HKDF-SHA256 per-database chain key derivation), 2.11 (DPAPI key-at-rest wrapping on Windows; the Linux keyring remains unimplemented and is reported as such). |
| **Phase 3** — portfolio grade | **partial** | Done: 3.1 (three-platform CI). Outstanding: 3.2–3.17. |

**All 19 policy fields** are now either enforced or explicitly refused with a stated
reason, up from 6 at the baseline commit. The test suite has grown from 97 to 267.

The two refusals are `checks.attributes` on Unix (the `chattr` inode flag set is not
captured, and aliasing it to the POSIX mode would silently duplicate
`checks.permissions`) and `rule.whodata`, which needs the kernel attribution tracked in
§18.7. Both are reported by `policy lint`, by `policy capabilities`, and in every
verdict that requested them.

Phase 1's §18.6.4 constraint 4 was honoured: diff capture (1.18) and the `nodiff`
guarantee (1.19, 1.20) landed in the same change, so there was never a build in which
OpenFIM wrote monitored file contents to its database without the suppression default
in place.

This plan closes the gap between what OpenFIM's policy schema *accepts* and what the
engine *enforces*, then raises the surrounding project to the standard expected of a
portfolio-grade defensive security tool.

It is written to be executed in order. Every work item names the files it touches, the
acceptance criteria that prove it done, and the test that keeps it done.

---

## 18.1 The Core Problem: A Policy Contract That Is Not Honoured

An audit of the current `main` found that the majority of the declarative policy
surface is parsed, schema-validated, printed back to the operator by
`openfim-cli policy check` — and then ignored by the engine.

This is the single most serious class of defect in the project, and it is worse than a
missing feature. A missing feature is visible. A policy field that loads cleanly,
displays as active, and silently does nothing produces **false assurance**: the
operator believes they have configured a control that does not exist. For a security
tool, that is the defect that matters most.

### 18.1.1 Verified enforcement status

| Policy field | Parsed | Displayed | **Enforced** | Consequence of the gap |
|---|---|---|---|---|
| `checks.hash` | yes | yes | **yes** | — |
| `checks.permissions` | yes | yes | **partial** | Compares `st_mode` only. On Windows that is attribute bits, not the ACL, so a permission grant to a new principal is invisible. |
| `checks.size` | yes | yes | **no** | A size-only change is caught incidentally by `hash`; with `hash: false` it is missed entirely. |
| `checks.ownership` | yes | yes | **no** | `chown` of a monitored file is never reported. On Windows `uid`/`gid` are hardcoded to 0, so this check could not work even if wired up. |
| `checks.timestamps` | yes | yes | **no** | Timestomping is undetectable via this control (content hashing still catches content edits). |
| `checks.attributes` | yes | yes | **no** | Setting hidden / system / read-only is never reported. |
| `checks.xattrs` | yes | yes | **no** | `xattrs_hash` is permanently `NULL`. Extended attributes, SELinux labels, capability bits and Windows alternate data streams are entirely unmonitored. |
| `globals.default_hash` | yes | yes | **no** | The hasher is hardcoded to SHA-256. Setting `blake3` changes nothing. |
| `globals.max_io_rate_mb_s` | yes | yes | **no** | Throttling comes from the `--throttle-mb-s` flag; the policy value is inert. |
| `globals.scan_nice_priority` | yes | no | **no** | No scheduling priority is ever applied. |
| `globals.realtime_fallback_sweep_interval` | yes | yes | **no** | No reconciliation sweep exists, so events dropped by the watcher are lost permanently and silently. |
| `rule.mode` (`realtime`/`scheduled`/`on_boot`) | yes | yes | **no** | All three behave identically: real-time only. `scheduled` and `on_boot` rules appear configured but never run a sweep. |
| `rule.nodiff` | yes | yes | **no** | Moot today because `diff_snippet` is never populated at all, but it becomes a secret-leakage risk the moment diff capture is added. |
| `rule.recursive` | yes | yes | **yes** | — |
| `rule.ignore` | yes | yes | **yes** | — |
| `rule.severity` | yes | yes | **yes** | — |
| `rule.active_response` | yes | yes | **yes** | Guarded by a circuit breaker as of `6154173`. |
| `rule.whodata` | yes | yes | **no** | Kernel attribution is unimplemented; correctly reported as unattributed as of `6154173`. |

**Scale of the gap: 12 of 18 policy fields are not enforced.**

### 18.1.2 Design principle adopted by this plan

> A policy field must be enforced, or the tool must refuse to pretend otherwise.

Three mechanisms implement that principle:

1. **Enforce it** — the default, and the bulk of Phase 1.
2. **Declare it unsupported on this platform** — a machine-readable capability matrix,
   surfaced by a new `policy lint` command, so `ownership: true` on Windows produces a
   loud warning instead of silent acceptance.
3. **Reject it** — unknown fields fail the parse (`#[serde(deny_unknown_fields)]`), so a
   typo such as `cheks:` is an error rather than a silently-defaulted control.

---

## 18.2 Phase 0 — Truth in Documentation

Do this first and in isolation. The repository currently makes claims the code does not
support; correcting that is a precondition for trusting anything else in it.

| # | Task | Files |
|---|---|---|
| 0.1 | Replace the Day 6 "fanotify" claim with the actual mechanism (`notify`: inotify / `ReadDirectoryChangesW`). | `docs/BUILD_ORDER_CHECKLIST.md` |
| 0.2 | Replace the Day 7 "acting PID" claim; attribution records the *observing* process and is reported as unattributed. | `docs/BUILD_ORDER_CHECKLIST.md` |
| 0.3 | Correct the stale test count (97, not 26) and fix the `file_reliability` → `file_integrity` link typo in the doc table row 13. | `docs/BUILD_ORDER_CHECKLIST.md`, `README.md` |
| 0.4 | Add an honest **Capability Matrix** to the README: every control × {Linux, Windows, macOS} × {enforced, partial, unsupported, planned}. | `README.md` |
| 0.5 | Add a "Current Limitations" section stating plainly: no attribution, no central manager, single-host, policy gaps pending Phase 1. | `README.md` |

**Acceptance:** no statement in `README.md` or `docs/` describes behaviour absent from
the code. A reviewer reading only the docs forms an accurate expectation.

---

## 18.3 Phase 1 — Honour the Policy Contract

The core of this plan. Introduces one authoritative comparison engine so that policy
semantics live in exactly one place rather than being re-implemented ad hoc in the
agent, the CLI and the console.

### 18.3.1 Extract a single change-detection engine

**New module: `crates/openfim-common/src/detect.rs`**

Today the agent compares baseline to current inline, checking only `hash` then
`permissions`, and the console's in-process sensor has its own near-duplicate copy of
that logic. Two implementations of a security decision will drift.

```rust
/// One observed difference between baseline and current state.
pub enum ChangeKind {
    Content   { old: String, new: String },
    Size      { old: u64, new: u64 },
    Mode      { old: u32, new: u32 },
    Ownership { old_uid: u32, new_uid: u32, old_gid: u32, new_gid: u32 },
    Timestamps{ old_mtime: i64, new_mtime: i64 },
    Attributes{ old: u32, new: u32 },
    Xattrs    { old: Option<String>, new: Option<String> },
    Acl       { old: Option<String>, new: Option<String> },
}

/// Evaluates every check the rule enables, skipping those unsupported here.
pub fn evaluate(
    baseline: &FileMetadata,
    current:  &FileMetadata,
    checks:   &RuleChecks,
) -> ChangeSet;

pub struct ChangeSet {
    pub changes: Vec<ChangeKind>,
    /// Checks the rule requested that this platform cannot perform.
    pub skipped_unsupported: Vec<&'static str>,
}
```

| # | Task | Files |
|---|---|---|
| 1.1 | Implement `detect.rs` with `evaluate` covering all seven `checks` fields. | `detect.rs` (new) |
| 1.2 | Rewrite the agent's comparison to call `evaluate` and emit one event per `ChangeKind`, replacing the `hash`-then-`permissions` if/else chain. | `crates/openfim-agent/src/main.rs` |
| 1.3 | Delete the console's duplicate detection logic; call `evaluate`. | `crates/openfim-cli/src/console.rs` |
| 1.4 | Route `baseline diff` and `verify-file` through `evaluate` so CLI and daemon verdicts cannot disagree. | `crates/openfim-cli/src/main.rs`, `db.rs` |
| 1.5 | Add event types: `SIZE_CHANGED`, `OWNERSHIP_CHANGED`, `TIMESTAMP_CHANGED`, `ATTRIBUTES_CHANGED`, `XATTRS_CHANGED`, `ACL_CHANGED`. | `db.rs`, agent |

**Acceptance:** a table-driven test asserts, for each of the seven checks, that enabling
it detects the corresponding mutation and disabling it does not. Mutating a file's
`mtime` with `checks.timestamps: false` must produce no timestamp event.

### 18.3.2 Capture the metadata the checks need

`xattrs_hash` and `acl_hash` exist in both the struct and the SQLite schema and are
always `NULL`. Two checks cannot work until they are populated.

| # | Task | Platform detail |
|---|---|---|
| 1.6 | Extended attributes. Linux: `listxattr`/`getxattr`, sorted name=value pairs hashed canonically. macOS: equivalent. Windows: enumerate alternate data streams via `FindFirstStreamW`. | `fsident.rs` or new `xattr.rs` |
| 1.7 | ACL hashing. Linux: `system.posix_acl_access`. Windows: `GetNamedSecurityInfoW` → hash the owner SID, group SID and DACL in a canonical form. | new `acl.rs` |
| 1.8 | Populate real `st_uid`/`st_gid` on Windows from the owner SID (store the SID string; keep the numeric fields Unix-only and document it). | `metadata.rs` |
| 1.9 | Make `attributes` distinct from `permissions`: on Windows `permissions` → ACL hash, `attributes` → `file_attributes`. On Unix `permissions` → mode bits, `attributes` → `chattr` flags (`FS_IOC_GETFLAGS`). | `metadata.rs`, `detect.rs` |

**Acceptance:** `setfattr` / `icacls` / `chattr` on a monitored file raises exactly the
matching event and nothing else. A test asserts canonical hashing is order-independent
(adding two xattrs in either order yields the same hash).

> **Why ACL hashing rather than ACL parsing:** a hash detects *that* the security
> descriptor changed without the agent having to interpret every ACE, which keeps a
> privileged parser off the hot path. The trade-off — no human-readable "what changed" —
> is accepted here and recorded as **ADR-008**.

### 18.3.3 Honour the globals

| # | Task | Notes |
|---|---|---|
| 1.10 | `default_hash` drives the hasher. Parse to `HashAlgorithm`; reject unsupported values at load, not at first use. | Algorithm must also be recorded per baseline entry so a policy change does not silently invalidate comparisons. |
| 1.11 | `max_io_rate_mb_s` becomes the default throttle; `--throttle-mb-s` overrides it. Log which source won. | Precedence: CLI flag > policy > built-in default. |
| 1.12 | `scan_nice_priority` applied via `setpriority(PRIO_PROCESS)` on Unix and `SetThreadPriority` on Windows, best-effort with a warning on failure. | |
| 1.13 | Add `max_spool_mb` (default 500) to globals, implementing RSK-03. | See 18.4.4. |

**Acceptance:** `policy check` prints the *effective* configuration — resolved values
and their source — not merely the parsed file.

### 18.3.4 Implement rule modes and the fallback sweep

This is the most security-significant item in Phase 1. Real-time watchers drop events:
inotify queue overflow, `ReadDirectoryChangesW` buffer overrun, a watch registered
after a change. Without reconciliation those misses are permanent and silent.

| # | Task | Detail |
|---|---|---|
| 1.14 | Scheduler that dispatches rules by `mode`: `Realtime` → watcher; `Scheduled` → sweep every `realtime_fallback_sweep_interval`; `OnBoot` → one sweep at startup. | New `scheduler.rs` in the agent. |
| 1.15 | Periodic reconciliation sweep for `Realtime` rules too — the fallback the field is named for. Re-crawls and diffs, catching anything the watcher missed. | Throttled; must not starve the event loop. |
| 1.16 | Detect watcher overflow explicitly: handle `notify`'s `Flag::Rescan` and emit a `WATCH_OVERFLOW` event, then force an immediate sweep. | A dropped-event window must appear in the audit log, not vanish. |
| 1.17 | Emit a periodic signed `HEARTBEAT` event so a gap in agent coverage is visible as a gap in the chain rather than as an absence of evidence. | Closes "attacker stops the agent" from being indistinguishable from "nothing happened". |

**Acceptance:** an integration test registers a watch, suppresses the watcher, mutates a
file, and asserts the sweep still reports it. A second test asserts a `Flag::Rescan`
produces a `WATCH_OVERFLOW` event.

### 18.3.5 Make `nodiff` meaningful

| # | Task |
|---|---|
| 1.18 | Implement diff capture for text files: bounded unified diff into `diff_snippet` (cap ~4 KB, binary detection, redact nothing). |
| 1.19 | Guarantee `nodiff: true` suppresses capture entirely — never captured, never written, never logged. |
| 1.20 | Default `nodiff` to **true** for any rule whose path matches a built-in secret heuristic (`shadow`, `*.key`, `*.pem`, `.env`, `id_rsa`), requiring an explicit `nodiff: false` to opt out. |

**Acceptance:** a test writes a known secret into a `nodiff` path, mutates it, and greps
the entire database file plus all stdout for the secret, asserting zero occurrences.
This is the test that makes the control trustworthy.

### 18.3.6 Close the schema

| # | Task |
|---|---|
| 1.21 | `#[serde(deny_unknown_fields)]` on `Policy`, `PolicyRule`, `RuleChecks`, `PolicyGlobals`. |
| 1.22 | `openfim-cli policy lint` — validates against the capability matrix and reports: unenforceable-on-this-platform checks, rules matching zero paths on disk, shadowed rules, ignore patterns that exclude the rule's own target, severity outside 1–10. |
| 1.23 | Capability matrix as code: `openfim_common::capabilities()` returning per-check support for the current platform, consumed by `policy lint`, the daemon banner, and the README generator. |

**Acceptance:** `ownership: true` on Windows produces a warning naming the field, the
platform and the reason. `policy lint` exits non-zero on any unenforceable control,
making it usable as a CI gate.

---

## 18.4 Phase 2 — Operational Hardening

### 18.4.1 Fix the backup path collision *(correctness bug, do first)*

`RestoreBaseline` resolves backups as `backup_dir.join(file_name)` — a flat namespace.
Two monitored files named `config.yaml` in different directories collide, and a restore
can write the **wrong file's contents** over a live file. Safe in the single-file demo;
dangerous on a real tree.

| # | Task |
|---|---|
| 2.1 | Content-addressed backup store: `backup_dir/objects/<sha256[0:2]>/<sha256>` plus a `manifest.json` mapping normalized path + version → digest. |
| 2.2 | `openfim-cli baseline backup --db … --out …` to populate and refresh the store from the current baseline. |
| 2.3 | Restore verifies the digest after copying and fails loudly on mismatch. |
| 2.4 | Reject legacy flat backup directories with a migration message rather than guessing. |

**Acceptance:** a test monitors two same-named files in different directories, tampers
with both, restores both, and asserts each receives its own original content.

### 18.4.2 Agent self-defense

The baseline database is an ordinary file with inherited permissions, and the agent
takes no steps to protect it or itself. An attacker who can modify monitored files can
usually also delete `openfim.db`.

| # | Task |
|---|---|
| 2.5 | Create the database and key material owner-only (0600 Unix; explicit DACL on Windows). Warn loudly at startup if the existing file is group- or world-readable. |
| 2.6 | Optional append-only spool on Linux via `chattr +a`, documented as requiring `CAP_LINUX_IMMUTABLE`. |
| 2.7 | Self-monitoring: the agent watches its own binary, policy, public key and database, with these rules non-removable by policy. |
| 2.8 | **Signed chain checkpoints.** Periodically sign `(last_sequence_id, last_hmac, event_count, timestamp)` with the Ed25519 *admin* key and write it to a separate append-only file. HMAC alone cannot survive host compromise, because the verifying key lives on the host. A checkpoint exportable off-host makes wholesale log replacement detectable. |
| 2.9 | `openfim-cli audit verify --checkpoint <file>` cross-checks the chain against checkpoints. |

**Acceptance:** a test deletes the database entirely and asserts that verification
against a retained checkpoint reports evidence destruction rather than a clean empty
chain.

### 18.4.3 Key management

| # | Task |
|---|---|
| 2.10 | HKDF-SHA256 derivation of the chain key from a root key file, with per-database salt, so one leaked key does not compromise every host. |
| 2.11 | OS keystore integration: DPAPI on Windows, Secret Service / kernel keyring on Linux. File-based fallback retained. |
| 2.12 | Refuse to start if the key file is group- or world-readable (matching OpenSSH's behaviour for private keys). |
| 2.13 | Document the threat model plainly: an attacker with root on the monitored host can read the chain key and forge history from that point forward. Checkpoints (2.8) and off-host export are the mitigation; TPM sealing per doc 07 remains future work. |

**Acceptance:** `SECURITY.md` states exactly what the audit chain does and does not
prove under host compromise. No test can substitute for saying this clearly.

### 18.4.4 Spool quota (RSK-03)

| # | Task |
|---|---|
| 2.14 | Enforce `max_spool_mb` (default 500). At 90% capacity, shed lowest-severity unsent events first, never breaking the chain — record a signed `SPOOL_PRUNED` event stating what was dropped. |
| 2.15 | `openfim-cli audit stats` reporting spool size, event count, unsent backlog and oldest unsent event. |

**Acceptance:** a test fills the spool past the cap and asserts the chain still verifies
and the prune is itself an auditable chained event.

### 18.4.5 Run as a service

| # | Task |
|---|---|
| 2.16 | systemd unit with hardening directives (`ProtectSystem=strict`, `NoNewPrivileges`, `CapabilityBoundingSet`, `ReadWritePaths`). |
| 2.17 | Windows Service support via the `windows-service` crate, with `install` / `uninstall` / `start` / `stop` subcommands. |
| 2.18 | Structured logging (`tracing`) with JSON output, replacing `println!`, plus a `--log-format json` flag for SIEM ingestion. |
| 2.19 | Graceful restart that reconciles on startup, so a restart window becomes a logged sweep rather than a silent gap. |

---

## 18.5 Phase 3 — Portfolio Grade

Phases 0–2 make the tool correct and operable. This phase makes the *repository*
demonstrate professional security engineering, which is what a reviewer actually
assesses.

### 18.5.1 Continuous integration

There is currently **no CI at all** — no `.github/` directory. This is the single
highest-signal gap for a portfolio project.

| # | Workflow | Content |
|---|---|---|
| 3.1 | `ci.yml` | Matrix: {ubuntu-latest, windows-latest, macos-latest} × {stable, MSRV}. `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test --workspace`. |
| 3.2 | `security.yml` | `cargo-audit` (RUSTSEC advisories), `cargo-deny` (licenses, duplicate and banned crates), scheduled weekly plus on every PR. |
| 3.3 | `coverage.yml` | `cargo-llvm-cov` → Codecov, with a README badge and a ratchet that fails on regression. |
| 3.4 | `fuzz.yml` | Nightly `cargo-fuzz` run with a persisted corpus. |
| 3.5 | `release.yml` | Tag-triggered cross-compiled artifacts: `x86_64-unknown-linux-musl` (static), `x86_64-pc-windows-msvc`, `aarch64-apple-darwin`; SBOM; checksums; `cosign`-signed. |

**Acceptance:** every badge in the README reflects a real, passing, reproducible job.

### 18.5.2 Testing depth

| # | Task | Why it matters for this project specifically |
|---|---|---|
| 3.6 | **Fuzz targets** for the YAML policy parser, the `.sha256` / JSON manifest parsers, `normalize_path_str`, and `verify_spool_chain`. | These four parse untrusted or semi-trusted input. A FIM that panics on a malformed manifest is a denial-of-service against the monitor. |
| 3.7 | **Property tests** (`proptest`) for path normalization and rule matching: normalization is idempotent; a path matching a rule never also matches that rule's ignore set; specificity precedence is a total order. | Path matching is where false negatives hide, and false negatives are invisible. |
| 3.8 | **Criterion benchmarks**: hashing throughput by chunk size, 100k-file crawl wall time and peak RSS, event-loop throughput under write storms. | Doc 13 commits to <15 MB RSS and <1% CPU. Those numbers are currently unmeasured assertions. |
| 3.9 | **Expanded red-team suite**: hardlink swap, symlink swap mid-read, rename race, TOCTOU under concurrent writers, timestomp, Windows alternate data streams, sparse files, paths >260 chars, Unicode normalization and case-collision pairs, `.quarantine` reentrancy. | The existing suite has four scenarios; doc 14 promises a red-team validation suite. |
| 3.10 | **STRIDE traceability matrix**: `docs/19_THREAT_TEST_TRACEABILITY.md` mapping every threat in doc 02 to the test that exercises it, with explicit `UNTESTED` and `ACCEPTED` rows. | This is the artifact that distinguishes a security project from a project that mentions security. |

**Acceptance:** doc 02 contains no threat without either a named test or an explicit,
justified acceptance.

### 18.5.3 Compliance evidence

Doc 12 maps OpenFIM to PCI DSS 11.5, NIST 800-53 SI-7, CIS v8 and ISO 27001. Nothing
produces evidence against those mappings.

| # | Task |
|---|---|
| 3.11 | `openfim-cli report --framework {pci-dss,nist-800-53,cis-v8,iso-27001} --format {json,csv,html}` emitting control-by-control evidence: monitored scope, baseline age, events by severity, chain verification result, remediation actions taken. |
| 3.12 | Include the chain verification verdict and checkpoint status, so the evidence is self-attesting rather than merely asserted. |

### 18.5.4 Repository presentation

| # | Task |
|---|---|
| 3.13 | README rewrite: one-paragraph value proposition, architecture diagram, 60-second quickstart, the honest capability matrix from 0.4, benchmark numbers from 3.8, badges from 3.1–3.3. |
| 3.14 | An asciinema recording (or GIF) of the end-to-end detect → alert → remediate → audit flow. A reviewer who watches 30 seconds of working tool is worth more than one who reads 17 design documents. |
| 3.15 | `SECURITY.md` (disclosure policy, threat model summary, the host-compromise limitation from 2.13), `CONTRIBUTING.md`, `CHANGELOG.md` (keepachangelog), documented MSRV. |
| 3.16 | `ADR-008` ACL hashing over parsing; `ADR-009` content-addressed backup store; `ADR-010` signed checkpoints over HMAC-only chaining. |
| 3.17 | Publish the fixed policy-field semantics as a versioned **policy schema reference** with a JSON Schema for editor autocompletion and CI validation. |

---

## 18.6 Sequencing

Phases are ordered by dependency, not by schedule. The phase numbers say what must be
true before the next thing is worth building; they are not a timeline, and work should
move as fast as the dependency graph allows.

### 18.6.1 Dependency chain

```
  Phase 0 ── documentation truth
     │        (unblocks trust in everything below)
     ▼
  0.4 capability matrix ─────────────┐
     │                              │ consumed by
     ▼                              ▼
  1.1 detect.rs ──► 1.6-1.9 ──► 1.21-1.23
  (one engine)      (metadata)   (schema closure)
     │                              │
     ▼                              ▼
  1.10-1.13 globals          1.14-1.17 modes + sweep
     │                              │
     └──────────────┬───────────────┘
                    ▼
            1.18-1.20 nodiff / diff capture
                    │
                    ▼
                 Phase 2 ──► Phase 3
```

### 18.6.2 Start now, independent of phase order

These three have no upstream dependency and block or protect everything else, so they
should begin before or alongside Phase 1 rather than waiting their phase number:

| Item | Why it jumps the queue |
|---|---|
| **3.1 CI** | Every subsequent change is safer with a green three-platform gate in place. Landing it last means none of Phase 1 or 2 was protected while it was written. |
| **2.1 Backup collision** | A live data-loss bug: a restore can write the wrong file's contents over a live file. Not a feature gap, and not something to leave sitting behind two phases of work. |
| **0.1–0.5 Documentation** | Small, self-contained, and the rest of the repository cannot be trusted while the docs overstate the code. |

### 18.6.3 Work that can proceed in parallel

Nothing below shares a file or a dependency with the others, so these can run
concurrently once Phase 1's `detect.rs` has landed:

- **1.6/1.7** xattr capture and ACL capture — separate modules, separate platform APIs.
- **2.5–2.9** self-defense and **2.10–2.13** key management — separate concerns.
- **3.6** fuzz targets, **3.7** property tests, **3.8** benchmarks — independent test
  infrastructure, each addressing a different class of defect.
- **3.11/3.12** compliance reporting and **3.13–3.17** repository presentation.

### 18.6.4 Hard ordering constraints

These cannot be reordered or run concurrently, and each has a reason:

1. **0.4 before 1.21–1.23.** `policy lint` validates against the capability matrix, so
   the matrix has to exist first.
2. **1.1 before every other Phase 1 item.** `detect.rs` is where the policy semantics
   live. Wiring individual checks into the current ad-hoc comparison first would mean
   writing each one twice.
3. **1.6–1.9 before enforcing `xattrs` and `permissions`.** The metadata has to be
   captured before a check can compare it; `xattrs_hash` and `acl_hash` are `NULL`
   today.
4. **1.18–1.20 together, never apart.** Diff capture (1.18) makes the tool write file
   contents to disk. It must not land without the `nodiff` suppression guarantee (1.19)
   and the secret-path default (1.20), or the window between them is a tool that leaks
   secrets into its own database.
5. **1.14–1.17 before M3.** A tool that silently loses events cannot be called
   trustworthy, whatever hardening sits on top of it.

### 18.6.5 Milestones

Progress is tracked by these four states, not by elapsed time. Each is a claim that can
be demonstrated on demand.

| Milestone | Definition of done |
|---|---|
| **M1 — Honest** | Docs match code. Capability matrix published. `policy lint` rejects unenforceable configuration. |
| **M2 — Complete** | All 18 policy fields either enforced or explicitly refused. Fallback sweep and heartbeat operational. |
| **M3 — Trustworthy** | Backup collision fixed, self-defense and signed checkpoints in place, spool bounded, runs as a hardened service. |
| **M4 — Presentable** | CI green on three platforms, fuzzing and benchmarks running, STRIDE traceability complete, README and demo recorded. |

---

## 18.7 Explicitly Out of Scope

Named here so their absence is a decision rather than an oversight.

| Item | Rationale |
|---|---|
| Kernel process attribution (fanotify `FAN_REPORT_PIDFD`, eBPF, Windows minifilter) | The largest single piece of remaining work and a project in its own right. Tracked as doc 16 Phase 2. Until it lands, the tool must keep reporting events as unattributed. |
| Central manager, gRPC/mTLS, ClickHouse/PostgreSQL, web console | Doc 16 Phase 2. This plan deliberately perfects the single-host agent first; a distributed system built on an engine that ignores its own policy would compound the problem. |
| Package-manager change intelligence (dpkg/rpm) | Doc 08. High value for false-positive reduction, but it depends on a correct detection engine, so it follows Phase 1. |
| TPM 2.0 key sealing | Doc 07 / doc 16 Phase 3. Phase 2's signed checkpoints are the pragmatic interim mitigation. |
| macOS Endpoint Security API | Doc 16 Phase 3. macOS stays best-effort via the generic `notify` backend, and the capability matrix will say so. |

---

## 18.8 Risks

| Risk | Impact | Mitigation |
|---|---|---|
| ACL and xattr capture needs privileged, platform-divergent APIs | Phase 1 slips | Build behind the capability matrix: ship `unsupported` honestly rather than delaying the rest of Phase 1. |
| The fallback sweep re-hashes large trees and competes with the live workload | Performance regression against doc 13's budget | Reuse the existing token-bucket throttle, stagger sweeps per rule, and gate the change on the 3.8 benchmarks. |
| Diff capture risks writing secrets into the database | Data leak introduced by a security tool | 1.20 defaults `nodiff` on for secret-shaped paths; 1.19's grep-the-database test is the gate. |
| Enforcing previously-inert fields will surface changes operators never saw before | Alert flood on first upgrade | Ship a `--dry-run` reporting what *would* now alert, plus a migration note in `CHANGELOG.md`. |
| Chain format already changed once at `6154173` | Operator confusion | Version the chain explicitly, detect old formats, and provide a one-way re-baseline path rather than a silent reinterpretation. |

---

## 18.9 Definition of Done

This plan is complete when all of the following hold:

1. Every policy field is enforced, or `policy lint` refuses it on this platform.
2. No documented claim lacks a code path, and no code path lacks a test.
3. `cargo clippy --all-targets -- -D warnings` is clean on Linux, Windows and macOS in CI.
4. Every threat in doc 02 maps to a named test or a justified acceptance.
5. Deleting or truncating the audit log is detectable; stopping the agent leaves a visible gap.
6. A reviewer can clone, build, and watch a real detection in under five minutes.
7. `SECURITY.md` states the tool's limits as plainly as the README states its strengths.
