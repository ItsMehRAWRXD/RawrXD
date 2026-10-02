# ============================================================================
# git_safety_seal.ps1 — RAWRXD_GIT_SAFETY_AUTHORITY_001
#
# Writes the build seal for the certification binary. Wired as a POST_BUILD
# step, so it runs ONLY after a successful link.
#
# Why this exists
# ---------------
# A failed build leaves the PREVIOUS executable in place, byte-for-byte the one
# a prior certification ran against. That binary is still executable, still
# prints a plausible CHECKS_TOTAL and VERDICT, and is therefore capable of
# inheriting authority for source that was never linked. During this work a
# failed build left a stale binary that produced a convincing
# CHECKS_TOTAL=63 / VERDICT=FAIL describing a build that no longer existed.
#
# The rule this encodes:
#
#     BUILD_EXIT != 0
#         -> EXECUTABLE_FROM_THIS_BUILD = INVALID
#         -> RUNTIME_CERTIFICATION      = NO_VERDICT
#
# POST_BUILD gives exactly that: the seal is rewritten only when a link
# succeeds, so the presence of a current seal IS the evidence of a successful
# link. The driver then refuses to certify if the binary it is running does not
# hash to the sealed value, which closes the stale-binary path structurally
# rather than by remembering to check.
#
# The seal also records a content hash per source file this gate depends on, so
# "the tree moved after the link" is detectable rather than assumed away.
# ============================================================================
param(
    [Parameter(Mandatory = $true)][string] $BinaryPath,
    [Parameter(Mandatory = $true)][string] $SealPath,
    [Parameter(Mandatory = $true)][string] $GateName,
    [Parameter(Mandatory = $true)][string] $Config,
    [Parameter(Mandatory = $true)][string] $RepoRoot,
    [string[]] $SourceFiles = @()
)

$ErrorActionPreference = 'Stop'

function Get-Sha256([string] $Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return "ABSENT" }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
}

$binFull = (Resolve-Path -LiteralPath $BinaryPath).Path
$binItem = Get-Item -LiteralPath $binFull

# Source identity. HEAD is exact; the dirty-file count is a count, not a
# content hash, and is recorded as an observation rather than an identity --
# which is precisely why the per-file hashes below carry the real binding.
$head = "UNKNOWN"
$dirty = "UNKNOWN"
try {
    $head = (& git -C $RepoRoot rev-parse HEAD 2>$null | Select-Object -First 1).Trim()
    if (-not $head) { $head = "NO_GIT" }
} catch { $head = "GIT_ERROR" }
try {
    $dirty = (& git -C $RepoRoot status --porcelain 2>$null | Measure-Object).Count
} catch { $dirty = "GIT_ERROR" }

$lines = New-Object System.Collections.Generic.List[string]
$lines.Add("SEAL_SCHEMA=1")
$lines.Add("GATE=$GateName")
$lines.Add("SOURCE_HEAD=$head")
$lines.Add("SOURCE_DIRTY_FILES=$dirty")
$lines.Add("BUILD_CONFIG=$Config")
# Written by POST_BUILD, so reaching here means the link returned 0.
$lines.Add("LINK_EXIT=0")
$lines.Add("BINARY_PATH=$binFull")
$lines.Add("BINARY_SIZE=$($binItem.Length)")
$lines.Add("BINARY_MTIME_UTC=$($binItem.LastWriteTimeUtc.ToString('o'))")
$lines.Add("BINARY_SHA256=$(Get-Sha256 $binFull)")

foreach ($f in $SourceFiles) {
    $full = Join-Path $RepoRoot $f
    $lines.Add("SRC_SHA256.$f=$(Get-Sha256 $full)")
}

# The seal hashes its own body, so a truncated or edited seal is detectable.
$body = ($lines -join "`n")
$sha = [System.BitConverter]::ToString(
    [System.Security.Cryptography.SHA256]::Create().ComputeHash(
        [System.Text.Encoding]::UTF8.GetBytes($body))).Replace('-', '')

$sealDir = Split-Path -Parent $SealPath
if (-not (Test-Path -LiteralPath $sealDir)) {
    New-Item -ItemType Directory -Path $sealDir -Force | Out-Null
}

# Written WITHOUT a byte-order mark.
#
# `Set-Content -Encoding UTF8` in Windows PowerShell 5.1 prepends EF BB BF.
# That BOM is not part of the $body string that was hashed, so the reader would
# hash bytes the writer never hashed and every legitimate seal would report as
# corrupt. [System.IO.File]::WriteAllText with an explicit no-BOM UTF8 encoding
# makes the bytes on disk exactly the string that was hashed.
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($SealPath, ($body + "`nSEAL_SHA256=$sha"), $utf8NoBom)
Write-Host "git safety seal: $SealPath  binary=$($lines | Where-Object { $_ -like 'BINARY_SHA256*' })"
