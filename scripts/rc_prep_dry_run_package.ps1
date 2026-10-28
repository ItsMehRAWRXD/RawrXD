#Requires -Version 5.1
<#
.SYNOPSIS
  Phase 10 PREP dry-run package only (NOT certify / NOT promote).

.DESCRIPTION
  Stages TIP_FREEZE_001 product EXE+PDB (+ LICENSE) into a ZIP under
  evidence/WIN32IDE_RC_PREP_001/dry_run/. Does not run installers, does not
  claim RC PASS, PRODUCT_CERTIFIED, or PROMOTE.

.NOTES
  GhostText ABSORB=NOT_AUTHORIZED. TIP_CLIMB=HOLD. PROMOTE=0.
#>
[CmdletBinding()]
param(
    [string]$RepoRoot = "",
    [string]$TipExe = "",
    [string]$OutDir = ""
)

$ErrorActionPreference = "Stop"

if (-not $RepoRoot) {
    $here = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
    $RepoRoot = (Resolve-Path (Join-Path $here "..")).Path
}

$ExpectedTipSha = "748B210A8F17C6C47685BE1E2718CB0113C070E47881AD3A76B2EBB013934145"
if (-not $TipExe) {
    $TipExe = Join-Path $RepoRoot "evidence\TIP_FREEZE_001\bin\RawrXD-Win32IDE.exe"
}
if (-not $OutDir) {
    $OutDir = Join-Path $RepoRoot "evidence\WIN32IDE_RC_PREP_001\dry_run"
}

Write-Host "WIN32IDE_RC_PREP_001 dry-run package"
Write-Host "  PROMOTE=0 PRODUCT_CERTIFIED=0 RC_PASS=NOT_CLAIMED"
Write-Host "  TIP expected=$ExpectedTipSha"

if (-not (Test-Path -LiteralPath $TipExe)) {
    throw "TIP EXE missing: $TipExe"
}

$actualSha = (Get-FileHash -LiteralPath $TipExe -Algorithm SHA256).Hash
if ($actualSha -ne $ExpectedTipSha) {
    throw "TIP SHA mismatch. expected=$ExpectedTipSha actual=$actualSha (refuse dry-run on non-frozen tip)"
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$stage = Join-Path $OutDir "stage_RawrXD-Win32IDE_TIP_FREEZE"
if (Test-Path -LiteralPath $stage) {
    Remove-Item -LiteralPath $stage -Recurse -Force
}
New-Item -ItemType Directory -Force -Path (Join-Path $stage "bin") | Out-Null

Copy-Item -LiteralPath $TipExe -Destination (Join-Path $stage "bin\RawrXD-Win32IDE.exe") -Force
$tipPdb = [System.IO.Path]::ChangeExtension($TipExe, ".pdb")
if (Test-Path -LiteralPath $tipPdb) {
    Copy-Item -LiteralPath $tipPdb -Destination (Join-Path $stage "bin\RawrXD-Win32IDE.pdb") -Force
}

$license = Join-Path $RepoRoot "LICENSE"
if (Test-Path -LiteralPath $license) {
    Copy-Item -LiteralPath $license -Destination (Join-Path $stage "LICENSE") -Force
}

$stamp = Get-Date -Format "yyyyMMddTHHmmssZ"
$manifest = @"
WIN32IDE_RC_PREP_001 / DRY_RUN_MANIFEST
=======================================
ASOF_UTC=$stamp
PROMOTE=0
PRODUCT_CERTIFIED=0
RC_PASS=NOT_CLAIMED
TIP_CLIMB=HOLD
GHOSTTEXT_ABSORB=NOT_AUTHORIZED
TIP_SHA=$actualSha
TIP_SOURCE=$TipExe
PACKAGE_KIND=ZIP_STAGE_DRY_RUN
INSTALLER=NOT_BUILT
CMAKE_INSTALL=NOT_RUN
CERTIFY=NOT_RUN
NOTE=Prep inventory artifact only. Not a release candidate seal.
"@
Set-Content -LiteralPath (Join-Path $stage "DRY_RUN_MANIFEST.txt") -Value $manifest -Encoding UTF8

$zipPath = Join-Path $OutDir "RawrXD-Win32IDE_TIP_FREEZE_748B_dry_run.zip"
if (Test-Path -LiteralPath $zipPath) {
    $bak = Join-Path $OutDir ("RawrXD-Win32IDE_TIP_FREEZE_748B_dry_run.bak_{0}.zip" -f (Get-Date -Format "yyyyMMddHHmmss"))
    try {
        Move-Item -LiteralPath $zipPath -Destination $bak -Force
        Remove-Item -LiteralPath $bak -Force -ErrorAction SilentlyContinue
    } catch {
        # Locked zip: write a new stamped path; keep prior zip as PREP evidence only.
        $zipPath = Join-Path $OutDir ("RawrXD-Win32IDE_TIP_FREEZE_748B_dry_run_{0}.zip" -f (Get-Date -Format "yyyyMMddTHHmmss"))
    }
}
Compress-Archive -Path (Join-Path $stage "*") -DestinationPath $zipPath -Force

$zipSha = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash
$receipt = @"
DRY_RUN_RECEIPT
---------------
ZIP=$zipPath
ZIP_SHA256=$zipSha
TIP_SHA256=$actualSha
STAGE=$stage
PROMOTE=0
PRODUCT_CERTIFIED=0
RC_PASS=NOT_CLAIMED
"@
Set-Content -LiteralPath (Join-Path $OutDir "DRY_RUN_RECEIPT.txt") -Value $receipt -Encoding UTF8

Write-Host "  ZIP=$zipPath"
Write-Host "  ZIP_SHA256=$zipSha"
Write-Host "  DRY_RUN=OK (not certify)"
exit 0
