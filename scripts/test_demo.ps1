# ==============================================================================
# OpenFIM End-to-End Automated Test & Demonstration Script
# ==============================================================================
param(
    [switch]$KeepSandbox
)

$ErrorActionPreference = "Stop"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "       OpenFIM Defensive Integrity Architecture Demo         " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# 1. Ensure Cargo & Binaries
if (Get-Command "cargo" -ErrorAction SilentlyContinue) {
    $cargoCmd = "cargo"
} elseif (Test-Path "$env:USERPROFILE\.cargo\bin\cargo.exe") {
    $cargoCmd = "$env:USERPROFILE\.cargo\bin\cargo.exe"
} else {
    Write-Host "[!] Cargo not found. Ensure Rust toolchain is installed." -ForegroundColor Red
    exit 1
}

$cliExe = ".\target\debug\openfim-cli.exe"
$agentExe = ".\target\debug\openfim-agent.exe"

# The audit chain has no built-in signing key: a shipped default would be a key every
# adversary also holds, making the tamper-evident log forgeable. Both the agent and the
# CLI read OPENFIM_HMAC_KEY, so setting it once here covers the whole demo.
$env:OPENFIM_HMAC_KEY = "demo-only-hmac-key-do-not-use-in-production"

# Always build. Rebuilding only when the binary is absent means the demo silently
# exercises stale code after any source change, which is exactly when a demo is most
# likely to be wrong and least likely to be doubted. Cargo is a no-op when up to date.
Write-Host "[*] Building OpenFIM workspace binaries..." -ForegroundColor Yellow
& $cargoCmd build --workspace
if ($LASTEXITCODE -ne 0) {
    Write-Host "[!] Build failed; aborting demo." -ForegroundColor Red
    exit 1
}
if (!(Test-Path $cliExe) -or !(Test-Path $agentExe)) {
    Write-Host "[!] Expected binaries not found after build." -ForegroundColor Red
    exit 1
}

# 2. Setup Clean Demo Sandbox
$demoDir = "demo_sandbox"
if (Test-Path $demoDir) {
    Remove-Item -Recurse -Force $demoDir
}
New-Item -ItemType Directory -Force -Path "$demoDir\data" | Out-Null

$targetFile = "$demoDir\data\production_config.env"
# Pristine copies live in a content-addressed store populated by
# `openfim-cli baseline backup`, not a flat directory keyed by filename. A flat layout
# maps two monitored files with the same name onto one backup, so a restore can write
# the wrong file's contents over a live file.
$backupStore = "$demoDir\backup_store"
$initialSecret = "DATABASE_URL=postgres://app_user:s3cur3p@ss@db.internal:5432/core`nENCRYPTION_KEY=0x9f8b7c6d5e4a3b2c1"

Set-Content -Path $targetFile -Value $initialSecret

Write-Host "`n[STEP 1] Generating Ed25519 Administrative Security Keys..." -ForegroundColor Green
& $cliExe policy keygen --out-dir $demoDir

# 3. Create Declarative Policy
$policyFile = "$demoDir\policy.yaml"
$policyYaml = @"
version: "1.0"
policy_id: "sec-prod-policy-01"
name: "Production Configuration Guard"
author: "Chief Information Security Officer"
signature_algorithm: "ed25519"
globals:
  default_hash: "sha256"
  max_io_rate_mb_s: 50
  realtime_fallback_sweep_interval: 10
rules:
  - id: "rule-prod-env"
    description: "Defend production configuration from unauthorized modification"
    paths:
      - "$demoDir/data"
    recursive: true
    mode: "realtime"
    # nodiff is deliberately left unset. The monitored file is a .env holding an
    # encryption key, so the safe default applies and its contents are never written
    # into the event log. Setting 'nodiff: false' here would opt that secret into diff
    # capture, which is exactly what 'openfim-cli policy lint' warns about.
    # (No backticks in this block: inside a PowerShell here-string a backtick is the
    # escape character, so 'n' after one would become a literal newline.)
    whodata: true
    severity: 10
    checks:
      hash: true
      size: true
      permissions: true
      ownership: true
      timestamps: true
      xattrs: false
    active_response:
      action: "restore_baseline"
"@
Set-Content -Path $policyFile -Value $policyYaml

Write-Host "`n[STEP 2] Digitally Signing Policy with Admin Private Key..." -ForegroundColor Green
& $cliExe policy sign --policy $policyFile --privkey "$demoDir\openfim_admin.key"

Write-Host "`n[STEP 3] Verifying Signed Policy Authenticity..." -ForegroundColor Green
& $cliExe policy check --policy $policyFile --pubkey "$demoDir\openfim_admin.pub"

# 4. Create Baseline Snapshot
$dbFile = "$demoDir\openfim.db"
Write-Host "`n[STEP 4] Generating Cryptographic Baseline Database Snapshot..." -ForegroundColor Green
& $cliExe baseline snapshot --dir "$demoDir\data" --db $dbFile

# 4b. Capture pristine copies while the file is still known-good
Write-Host "`n[STEP 4b] Capturing Pristine Copies Into Content-Addressed Backup Store..." -ForegroundColor Green
& $cliExe baseline backup --db $dbFile --out $backupStore --version "demo-v1"

Write-Host "`n[STEP 4c] Verifying Backup Store Integrity..." -ForegroundColor Green
& $cliExe baseline verify-backup --store $backupStore

# 5. Export Manifests for Air-Gapped / Web GUI
Write-Host "`n[STEP 5] Exporting Portable Manifests for Zero-Upload Web GUI..." -ForegroundColor Green
& $cliExe baseline export --db $dbFile --out "$demoDir\manifest.json" --format json
& $cliExe baseline export --db $dbFile --out "$demoDir\manifest.sha256" --format sha256
Write-Host "[+] Exported JSON & SHA256 manifests to $demoDir\" -ForegroundColor Cyan

# 6. Verify Clean File on Demand
Write-Host "`n[STEP 6] Inspecting Target File On-Demand (Clean Baseline)..." -ForegroundColor Green
& $cliExe check-file $targetFile --db $dbFile --policy $policyFile

# 7. Simulate Adversary Tampering
Write-Host "`n[STEP 7] Simulating Adversary Tampering (Injecting Backdoor)..." -ForegroundColor Red
Add-Content -Path $targetFile -Value "`nATTACKER_C2_SERVERS=https://evil-c2.attacker.net/exfil"

Write-Host "`n[STEP 8] Inspecting Target File On-Demand (Tampered State)..." -ForegroundColor Yellow
& $cliExe check-file $targetFile --db $dbFile --policy $policyFile

# 8. Start Real-time Daemon with Active Response Remediation
Write-Host "`n[STEP 9] Launching Real-time Sensor Daemon with Automated Active Remediation..." -ForegroundColor Green
$agentProcess = Start-Process -FilePath $agentExe -ArgumentList "--config $policyFile --db $dbFile --key $demoDir\openfim_admin.pub --remediation --backup-dir $backupStore" -PassThru -NoNewWindow
Start-Sleep -Seconds 2

Write-Host "`n[*] Injecting secondary malicious tamper while real-time daemon is watching..." -ForegroundColor Red
Add-Content -Path $targetFile -Value "`nRANSOMWARE_PAYLOAD_DROP=malware.bin"
Start-Sleep -Seconds 2

# Terminate agent
Stop-Process -Id $agentProcess.Id -Force
Write-Host "[*] Stopped real-time sensor daemon." -ForegroundColor Gray

# Check file restored state
$restoredContent = Get-Content $targetFile -Raw
Write-Host "`n[STEP 10] Checking File State After Real-time Automated Remediation:" -ForegroundColor Green
Write-Host $restoredContent -ForegroundColor White

# ---- Assertions -------------------------------------------------------------
# The banner at the end of this script used to print unconditionally, so a demo in
# which remediation silently declined still reported "ALL TESTS PASSED". A
# demonstration that cannot fail demonstrates nothing.
$failures = @()

if ($restoredContent -match "RANSOMWARE_PAYLOAD_DROP") {
    $failures += "Remediation did not roll back the live tamper: the ransomware line is still present."
}
if ($restoredContent -match "ATTACKER_C2_SERVERS") {
    $failures += "Remediation did not restore the pristine baseline: the C2 line is still present."
}
if ($restoredContent -notmatch "ENCRYPTION_KEY") {
    $failures += "Restored file is missing its original content."
}

# 9. Verify Cryptographic Event Spool Chain
Write-Host "`n[STEP 11] Verifying Tamper-Evident HMAC Audit Chain..." -ForegroundColor Green
& $cliExe audit verify --db $dbFile
if ($LASTEXITCODE -ne 0) {
    $failures += "Audit chain verification failed (exit $LASTEXITCODE)."
}

# Note: tail-truncation and field-tampering detection are exercised by the integration
# suite rather than here, because doing it from a shell script would require shipping a
# "delete the evidence" command in the product itself. See
# `test_adversary_cannot_erase_evidence_by_truncating_the_log` and
# `test_every_forensic_field_is_authenticated`.

# 10. Check File again (showing WhoData forensic history)
Write-Host "`n[STEP 12] Final On-Demand Verification with Forensic WhoData Audit History:" -ForegroundColor Green
& $cliExe check-file $targetFile --db $dbFile --policy $policyFile

if (!$KeepSandbox) {
    Remove-Item -Recurse -Force $demoDir
    Write-Host "`n[*] Cleaned up demo sandbox. Pass -KeepSandbox to inspect artifacts." -ForegroundColor Gray
}

Write-Host ""
if ($failures.Count -gt 0) {
    Write-Host "============================================================" -ForegroundColor Red
    Write-Host "                  DEMO FAILED                               " -ForegroundColor Red
    Write-Host "============================================================" -ForegroundColor Red
    foreach ($f in $failures) {
        Write-Host "  [x] $f" -ForegroundColor Red
    }
    exit 1
}

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "             ALL TESTS & VERIFICATIONS PASSED!              " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

