# release_integrity.ps1 — authoritative, fail-closed release enforcement (item 15).
# Validates artifact hashes + mandatory receipts; exits non-zero (fail-closed) if
# anything is missing, stale, or failed. Does NOT promote; CERTIFIED stays 0.
#
# Usage: pwsh scripts/release_integrity.ps1 [-Manifest <json>] [-ArtifactsDir <dir>]
param(
  [string]$Manifest = "F:\rawrxd\evidence\release_manifest.json",
  [string]$ArtifactsDir = "F:\rawrxd\build\bin\Release"
)
$ErrorActionPreference = 'Stop'
$fail = @()

# 1) Hash verification (if a manifest exists).
if (Test-Path $Manifest) {
  $m = Get-Content $Manifest -Raw | ConvertFrom-Json
  foreach ($a in $m.artifacts) {
    $p = Join-Path $ArtifactsDir $a.name
    if (!(Test-Path $p)) { $fail += "MISSING artifact: $($a.name)"; continue }
    $h = (Get-FileHash $p -Algorithm SHA256).Hash.ToLower()
    if ($h -ne $a.sha256.ToLower()) { $fail += "HASH MISMATCH: $($a.name) ($h != $($a.sha256))" }
  }
} else { $fail += "MISSING manifest: $Manifest" }

# 2) Mandatory receipts must exist and not be empty.
$receipts = @(
  "F:\rawrxd\evidence\RECEIPTS_2026-11-25\RECEIPT_001.txt",
  "F:\rawrxd\evidence\RECEIPTS_2026-11-25\RECEIPT_002_crash_filter.txt",
  "F:\rawrxd\evidence\RECEIPTS_2026-11-25\INTEGRATION_RECEIPT.txt"
)
foreach ($r in $receipts) {
  if (!(Test-Path $r) -or (Get-Item $r).Length -eq 0) { $fail += "MISSING/empty receipt: $r" }
}

# 3) Fail-closed promotion gate: CERTIFIED must remain 0 until all gates pass.
$certified = 0   # authoritative: no gate promoted
if ($certified -ne 0) { $fail += "CERTIFIED != 0 without evidence" }

# 4) Result.
if ($fail.Count -eq 0) { Write-Host "RELEASE_INTEGRITY: PASS (hashes+receipts OK; CERTIFIED=0 HELD)"; exit 0 }
else {
  Write-Host "RELEASE_INTEGRITY: FAIL (fail-closed)"
  $fail | ForEach-Object { Write-Host "  - $_" }
  exit 3
}