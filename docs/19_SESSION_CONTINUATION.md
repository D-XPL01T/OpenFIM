# 19. Session Continuation Handoff

**Purpose:** resume this work in a fresh chat with zero prior context. Everything needed
to pick up where the last session paused is here.

**Last updated:** 2026-11-07
**Branch:** `master`, tracking `origin/main` on `https://github.com/D-XPL01T/OpenFIM`
**Verified state at handoff:** 267 tests passing, `cargo clippy --all-targets` clean,
`cargo fmt --check` clean, end-to-end demo passing (exit 0).

---

## 19.1 How to Resume

1. Read [`18_HARDENING_AND_PRODUCTIONIZATION_PLAN.md`](file:///d:/VibeCode/file_integrity/docs/18_HARDENING_AND_PRODUCTIONIZATION_PLAN.md).
   Its progress table at the top is the authoritative tracker of what is done.
2. Read [`SECURITY.md`](file:///d:/VibeCode/file_integrity/SECURITY.md) for the threat
   model and, importantly, the stated limits.
3. Read the README's **Capability Matrix** for what is enforced per platform.
4. Run the verification commands in §19.5 to confirm the tree is healthy before changing
   anything.
5. Continue from §19.4, "Next steps".

### Environment notes that cost time to rediscover

- **`cargo` is not on `PATH`.** It lives at `C:\Users\himan\.cargo\bin`. Prefix shell
  commands with `$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"`.
- The project builds with the **`stable-x86_64-pc-windows-gnu`** toolchain. A `1.85.0`
  MSVC toolchain is installed but has **no `link.exe`** in this environment, so
  `cargo +1.85.0` fails at link time. That is an environment limitation, not a code
  problem.
- Use `Bash` for file reads/greps and `PowerShell` for cargo. Beware: inside a
  PowerShell **here-string a backtick is the escape character**, so a literal
  `` `nodiff` `` in a comment silently becomes a newline and corrupts generated YAML.
  This has already broken the demo script once.
- `gh` is **not installed**, so CI results cannot be read from here. CI has been
  triggered five times and has **never been observed running** — see §19.6.

---

## 19.2 What This Project Is

OpenFIM is a host-based file integrity monitor in Rust. Three crates:

| Crate | Role |
|---|---|
| `openfim-common` | All the logic: hashing, metadata, detection, policy, database, crypto. |
| `openfim-agent` | The real-time sensor daemon. |
| `openfim-cli` | Administrative CLI plus an interactive console. |

The work is driven by a four-phase plan sequenced **by dependency, not by schedule** —
the user explicitly asked for no time estimates.

### The governing principle

The audit that started this work found that **12 of 18 policy fields were parsed,
validated, displayed as active by `policy check`, and then ignored by the engine.**

That is worse than a missing feature. A missing feature is visible; a silently inert
control produces **false assurance** — the operator believes a protection exists when it
does not. Every design decision since follows from one rule:

> A policy field must be enforced, or the tool must refuse to pretend otherwise.

Three mechanisms implement it: enforce it, declare it unsupported *with a stated reason*
via the capability matrix, or reject it at parse time.

---

## 19.3 Where Things Stand

### Phase 0 — documentation truth: **complete**
Docs corrected to match code; capability matrix and limitations published.

### Phase 1 — honour the policy contract: **complete**
All 19 policy fields are now either enforced or explicitly refused with a reason.

Key modules introduced:

| Module | Purpose |
|---|---|
| `capabilities.rs` | Single source of truth for which controls are real, per platform, each gap with a stated reason. |
| `detect.rs` | **The** change-detection engine. Previously this logic existed three times (agent, console, CLI), each checking a different subset. |
| `lint.rs` | `policy lint`: 16 checks for configuration that parses but will not act. Exits non-zero to gate CI. |
| `sweep.rs` | Reconciliation sweep — the safety net under real-time watching. |
| `xattr.rs` | Linux `llistxattr` (SELinux labels, file capabilities); Windows NTFS alternate data streams. |
| `acl.rs` | POSIX ACL digest on Linux; DACL digest and owner SID on Windows. |
| `diff.rs` | Bounded content diff with fail-safe `nodiff` suppression. |

### Phase 2 — operational hardening: **partial**

Done: 2.1–2.15 (everything except service install and logging).

| Module | Purpose |
|---|---|
| `backup.rs` | Content-addressed pristine-copy store (fixed a data-loss bug). |
| `checkpoint.rs` | Ed25519 signed off-host chain checkpoints. |
| `protect.rs` | Owner-only permissions on state and key material; opt-in Linux append-only spool. |
| `keymgmt.rs` | HKDF-SHA256 per-database chain key derivation; DPAPI key-at-rest wrapping on Windows. |

**Outstanding in Phase 2:**
- **2.11 (partial)** the Linux kernel keyring / Secret Service backend; DPAPI on Windows is done
- **2.16** systemd unit with hardening directives
- **2.17** Windows Service support (`windows-service` crate)
- **2.18** structured logging via `tracing`, replacing `println!`, with `--log-format json`
- **2.19** graceful restart reconciliation (partly covered by the existing boot sweep)

### Phase 3 — portfolio grade: **partial**
Only **3.1** (CI) is done. Outstanding: 3.2 security workflow (`cargo-audit`,
`cargo-deny`), 3.3 coverage, 3.4 fuzzing, 3.5 release workflow, 3.6–3.10 testing depth
(fuzz targets, property tests, criterion benchmarks, expanded red-team suite, STRIDE
traceability matrix), 3.11–3.12 compliance evidence export, 3.13–3.17 README rewrite,
asciinema demo, CONTRIBUTING/CHANGELOG, ADRs 008–010, JSON Schema for the policy.

---

## 19.4 Next Steps

The highest-value remaining work, in order:

1. **2.18 — structured logging.** Everything currently goes through `println!`. A
   security tool whose output cannot be ingested by a SIEM is hard to operate, and this
   blocks any later forwarding work. Expect ~100 call sites across three crates; a
   surgical option is to route the *event* stream through `tracing` while leaving the
   interactive console output human-readable.
2. **2.16 + 2.17 — service install.** Needed before the tool is usable unattended: the
   daemon is currently a foreground process that dies with its terminal. systemd unit
   with hardening directives (`ProtectSystem=strict`, `NoNewPrivileges`,
   `CapabilityBoundingSet`), and the `windows-service` crate for the Windows side.
3. **3.6 — fuzz targets** for the four parsers that take untrusted input (policy YAML,
   `.sha256` and JSON manifests, `normalize_path_str`, `verify_spool_chain`). A FIM that
   panics on a malformed manifest is a denial of service against the monitor.
4. **3.10 — STRIDE traceability matrix** mapping every threat in doc 02 to the test that
   exercises it. This is the artifact that most distinguishes a security project from a
   project that mentions security.
5. **2.11 remainder** — the Linux kernel keyring or Secret Service backend, so the root
   key is not a plaintext file there. DPAPI already covers Windows.

### Explicitly deferred (do not start without discussion)
Kernel process attribution (fanotify `FAN_REPORT_PIDFD` / eBPF / Windows minifilter),
the central manager and gRPC pipeline, package-manager change intelligence, and TPM 2.0
sealing. All are documented in §18.7 with reasons.

---

## 19.5 Verification Commands

Run these before and after any change. All must pass.

```bash
$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"; cargo fmt --all -- --check
```

```bash
$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"; cargo clippy --workspace --all-targets -- -D warnings
```

```bash
$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"; cargo test --workspace
```

```bash
$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"; .\scripts\test_demo.ps1
```

**The demo matters more than it looks.** It has caught four bugs that every unit test
passed through:

- a path-keying mismatch that made remediation decline while a good backup sat in the store
- stale binaries, because the script only rebuilt when the binary was absent
- sweep alert spam re-reporting the same unresolved divergence every cycle
- a suppression bug in the *fix* for that spam

If a change touches the agent, run the demo.

---

## 19.6 Open Caveats

| Caveat | Detail |
|---|---|
| **CI has never been observed running.** | `.github/workflows/ci.yml` exists and has been pushed five times. `gh` is not installed locally, so results are unreadable from this environment. **Check the Actions tab.** The MSRV leg (`1.85.0` on Linux) is the most likely to fail, since it could not be verified locally. |
| **MSRV is declared but not fully proven.** | `rust-version = "1.85"` in `Cargo.toml`. The *floor* is verified (a 1.82 build fails on `clap_lex`'s edition2024 requirement). Whether 1.85 *suffices* is unverified locally: dependency resolution succeeds, but the compile could not finish for lack of an MSVC linker. The `msrv-declared` CI job exists to stop `Cargo.toml` and the workflow drifting apart. |
| **Audit chain format is versioned and has changed twice.** | Domain tag `openfim.event_spool.v2`. A database from an earlier build will not verify; it needs re-baselining, not reinterpretation. |
| **Windows ACL tightening is a no-op.** | `protect::restrict_to_owner` does nothing on Windows. A hand-built DACL that is half-correct is worse than an inherited one because it looks deliberate. Plan item 2.5 remainder. |
| **`checks.attributes` is refused on Unix.** | The `chattr` inode flag set needs `FS_IOC_GETFLAGS`. Aliasing it to the POSIX mode would silently duplicate `checks.permissions`. |
| **No process attribution.** | Reported honestly as `UNATTRIBUTED`. Needs kernel support. |
| **`.cargo/config.toml` is machine-specific.** | Contains an absolute `-L` path into a gitignored directory, and only affects the `x86_64-pc-windows-gnu` target. Harmless for default builds; worth cleaning up. |

---

## 19.7 Working Conventions Established

Carry these forward.

- **Commit in logical units**, one concern per commit, with a message that explains *why*
  — including the failure mode a fix prevents. The history is intended to be readable as
  the reasoning record.
- **Formatting-only changes get their own commit**, never mixed with functional ones.
- **Every bug fix gets a regression test** whose assertion message explains the defect,
  so a future failure is self-explanatory.
- **Tests assert mechanisms, not snapshots.** When capability-dependent tests were pinned
  to "xattrs is unsupported", they broke as soon as xattrs landed. They now derive
  expectations from the capability matrix so they keep testing the mechanism.
- **Do not fabricate constants.** Cryptographic test vectors were verified against
  published sources; a BLAKE3 vector written from memory was wrong and had to be fetched
  from the BLAKE3 repository.
- **Report honestly.** When a feature cannot work, say so in the code, the docs, the CLI
  output and the startup banner. This is the project's whole thesis.
- **Never commit or push unless asked.** The user directs when work lands.
