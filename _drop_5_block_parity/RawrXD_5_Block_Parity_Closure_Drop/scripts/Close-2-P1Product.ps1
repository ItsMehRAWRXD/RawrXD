param(
    [string]$RepoRoot = "F:\~dev\rawrxd",
    [string]$BuildDir = "build-win32ide-p1",
    [string]$Config = "Release",
    [string]$RuntimeSmokeScript = "",
    [string[]]$RuntimeSmokeArgs = @()
)

$ErrorActionPreference = "Stop"
Set-Location $RepoRoot

$authority = Join-Path $RepoRoot "evidence\HEXMAG_IDE_RUNTIME_CERT_FREEZE"
$freeze = Join-Path $authority "FREEZE.txt"
$auth = Join-Path $authority "AUTHORITY.txt"

if (-not (Test-Path $freeze) -or -not (Test-Path $auth)) {
    throw "BLOCK2_FROZEN_AUTHORITY_MISSING"
}

$build = Join-Path $RepoRoot $BuildDir
$candidates = @(
    (Join-Path $build "bin\RawrXD-Win32IDE.exe"),
    (Join-Path $build "$Config\RawrXD-Win32IDE.exe"),
    (Join-Path $build "bin\$Config\RawrXD-Win32IDE.exe")
)
$exe = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $exe) { throw "BLOCK2_EXE_NOT_FOUND" }

$mapCandidates = @(
    (Join-Path $build "bin\RawrXD-Win32IDE.map"),
    (Join-Path $build "RawrXD-Win32IDE.map")
)
$map = $mapCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $map) { throw "BLOCK2_MAP_NOT_FOUND" }

# Fail closed: the promoted binary must contain HexMag symbols, not merely source files.
$requiredPatterns = @(
    "HexMagRuntimeController",
    "hexmag",
    "RawrXD_HexMag"
)
$mapText = Get-Content $map -Raw
foreach ($p in $requiredPatterns) {
    if ($mapText -notmatch [regex]::Escape($p)) {
        throw "BLOCK2_MAP_SYMBOL_MISSING: $p"
    }
}

if (-not $RuntimeSmokeScript) {
    throw "BLOCK2_RUNTIME_SMOKE_REQUIRED: pass -RuntimeSmokeScript; binary hash alone is not product PASS"
}
if (-not (Test-Path $RuntimeSmokeScript)) {
    throw "BLOCK2_RUNTIME_SMOKE_NOT_FOUND: $RuntimeSmokeScript"
}

& powershell -NoProfile -ExecutionPolicy Bypass -File $RuntimeSmokeScript @RuntimeSmokeArgs
if ($LASTEXITCODE -ne 0) {
    throw "BLOCK2_RUNTIME_SMOKE_FAIL exit=$LASTEXITCODE"
}

$sha = (Get-FileHash $exe -Algorithm SHA256).Hash
$tip = (& git rev-parse HEAD).Trim()
$ev = Join-Path $RepoRoot "evidence\P1_WIN32IDE_BINARY.txt"

@"
P1_WIN32IDE_BINARY
==================
tip=$tip
exe=$exe
sha256=$sha
map=$map
HEXMAG_IDE_RUNTIME_CERT=PASS/FROZEN
authority=evidence\HEXMAG_IDE_RUNTIME_CERT_FREEZE\
runtime_smoke=PASS
controller_rewrite=0
BLOCK2_P1_PRODUCT=PASS
"@ | Set-Content $ev -Encoding ASCII

"BLOCK2_P1_PRODUCT=PASS"
"SHA256=$sha"
"EVIDENCE=$ev"
