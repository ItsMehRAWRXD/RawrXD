[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Model,
    [string]$RepoRoot = 'F:\~dev\rawrxd',
    [string]$ModelRoot = 'G:\OllamaModels',
    [string]$BuildDir = '',
    [int]$LifecycleIterations = 3
)

$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($BuildDir)) { $BuildDir = Join-Path $RepoRoot 'build-ninja' }

$env:RAWRXD_MODEL_ROOT = $ModelRoot
$env:RAWRXD_BLOB_ROOT = Join-Path $ModelRoot 'blobs'

$bin = Join-Path $BuildDir 'bin'
$catalog = Join-Path $bin 'rawrxd_model_catalog_cert.exe'
$lifecycle = Join-Path $bin 'deep2_lifecycle_cert_candidate.exe'
$agent = Join-Path $bin 'RawrXD-Agentic.exe'

if (-not (Test-Path $catalog)) { throw "Missing $catalog — run APPLY_SOVEREIGN_FINISH_NOW.ps1 first." }
if (-not (Test-Path $lifecycle)) { throw "Missing $lifecycle — run APPLY_SOVEREIGN_FINISH_NOW.ps1 first." }
if (-not (Test-Path $agent)) { throw "Missing $agent — run APPLY_SOVEREIGN_FINISH_NOW.ps1 first." }

$ev = Join-Path $RepoRoot 'evidence\SOVEREIGN_FINISH_HOUR'
New-Item -ItemType Directory -Force -Path $ev | Out-Null

& $catalog --root $ModelRoot --model $Model |
    Tee-Object -FilePath (Join-Path $ev 'MODEL_CATALOG_RESOLVE.txt')
if ($LASTEXITCODE -ne 0) { throw "MODEL-CATALOG-001 failed" }

& $lifecycle --model $Model --iterations $LifecycleIterations --tokens 8 --prompt 'Hello' |
    Tee-Object -FilePath (Join-Path $ev 'LIFECYCLE_CERT_CANDIDATE.txt')
if ($LASTEXITCODE -ne 0) { throw "Lifecycle candidate failed" }

Write-Host @"

CERT_NOW complete.
MODEL-CATALOG resolution: exercised.
LIFECYCLE-CERT-001: candidate evidence produced.
STREAMER-CERT-001: use existing certified evidence.
PARITY-CERT-001: intentionally NOT changed; frozen trusted golden is still required.
AUTONOMOUS-E2E-001: intentionally NOT promoted before parity authority is green.

Run a real autonomous smoke:
  New-Item -ItemType Directory -Force F:\scratch\hello | Out-Null
  & '$agent' --model '$Model' --workspace F:\scratch\hello --task 'Create a C++ Hello World program, build it, run it, observe the result, repair any failure, and finish only when it exits 0.'
"@
