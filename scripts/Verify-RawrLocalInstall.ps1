# Verify-RawrLocalInstall.ps1
# Fail-closed local install check for RawrXD CLI (P4 / TOP25 readiness).
# PROMOTE=0 — presence + help smoke only; NOT a maturity seal.

[CmdletBinding()]
param(
    [string]$RepoRoot = "",
    [string]$ExePath = "",
    [switch]$RequireSha256,
    [string]$ExpectedSha256 = ""
)

$ErrorActionPreference = "Stop"
$fail = 0

function Write-Check([string]$Name, [bool]$Ok, [string]$Detail = "") {
    $tag = if ($Ok) { "PASS" } else { "FAIL" }
    if (-not $Ok) { $script:fail++ }
    $line = "[$tag] $Name"
    if ($Detail) { $line = "$line :: $Detail" }
    Write-Host $line
}

if (-not $RepoRoot) {
    $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
}
if (-not $ExePath) {
    $ExePath = Join-Path $RepoRoot "build_ninja\bin\rawr.exe"
}

Write-Host "Verify-RawrLocalInstall  PROMOTE=0  ASOF=$(Get-Date -Format o)"
Write-Host "REPO=$RepoRoot"
Write-Host "EXE=$ExePath"

$exists = Test-Path -LiteralPath $ExePath
Write-Check "EXE_PRESENT" $exists $ExePath
if (-not $exists) {
    Write-Host "HINT: cmake -G Ninja -S . -B build_ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo"
    Write-Host "HINT: ninja -C build_ninja bin/rawr.exe"
    Write-Host "RESULT=FAIL  EXIT=2"
    exit 2
}

$hash = (Get-FileHash -LiteralPath $ExePath -Algorithm SHA256).Hash
Write-Host "EXE_SHA256=$hash"

if ($RequireSha256) {
    if (-not $ExpectedSha256) {
        Write-Check "SHA256_PIN" $false "ExpectedSha256 empty"
    } else {
        $ok = ($hash -eq $ExpectedSha256.ToUpperInvariant()) -or ($hash -eq $ExpectedSha256)
        Write-Check "SHA256_PIN" $ok "expected=$ExpectedSha256"
    }
} else {
    Write-Host "[INFO] SHA256_PIN skipped (pass -RequireSha256 -ExpectedSha256 <hex>)"
}

# Help smoke: rawr prints Usage to stderr and may set non-zero; treat text as success.
$helpOut = ""
try {
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $helpOut = (& $ExePath 2>&1 | ForEach-Object { "$_" }) -join "`n"
} finally {
    $ErrorActionPreference = $prevEap
}
$helpOk = $helpOut -match "rawr\s+list" -or $helpOut -match "Usage:"
Write-Check "HELP_USAGE" $helpOk ("elapsed_chars=" + $helpOut.Length)

$installMd = Join-Path $RepoRoot "INSTALL.md"
Write-Check "INSTALL_MD" (Test-Path -LiteralPath $installMd) $installMd

$status = Join-Path $RepoRoot "evidence\PRODUCTION_MATURITY_TOP25_001\STATUS.txt"
Write-Check "MATURITY_STATUS" (Test-Path -LiteralPath $status) $status

if ($fail -gt 0) {
    Write-Host "RESULT=FAIL  FAIL_COUNT=$fail  PROMOTE=0"
    exit 1
}
Write-Host "RESULT=PASS_LOCAL_VERIFY  PROMOTE=0  CERTIFIED=0  (help smoke only; not product maturity)"
exit 0
