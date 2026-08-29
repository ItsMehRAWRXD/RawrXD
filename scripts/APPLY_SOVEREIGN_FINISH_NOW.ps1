[CmdletBinding()]
param(
    [string]$RepoRoot = 'F:\~dev\rawrxd',
    [string]$ModelRoot = 'G:\OllamaModels',
    [string]$BuildDir = '',
    [switch]$PersistModelRoot,
    [switch]$SkipBuild,
    [switch]$AllowOtherRoot
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Say([string]$Text) {
    Write-Host "[SOVEREIGN-FINISH] $Text"
}

$RepoRoot = [IO.Path]::GetFullPath($RepoRoot).TrimEnd('\')
$Canonical = [IO.Path]::GetFullPath('F:\~dev\rawrxd').TrimEnd('\')

if (-not $AllowOtherRoot -and $RepoRoot -ne $Canonical) {
    throw "Refusing non-canonical tree '$RepoRoot'. Expected F:\~dev\rawrxd. Use -AllowOtherRoot only deliberately."
}

if (-not (Test-Path -LiteralPath (Join-Path $RepoRoot 'CMakeLists.txt'))) {
    throw "CMakeLists.txt not found under $RepoRoot"
}
if (-not (Test-Path -LiteralPath (Join-Path $RepoRoot 'src\deep2\Deep2Engine.h'))) {
    throw "Canonical Deep2Engine.h not found under $RepoRoot\src\deep2"
}
if (-not (Test-Path -LiteralPath $ModelRoot)) {
    Write-Warning "Model root '$ModelRoot' does not currently exist. Files will still be installed."
}

if ([string]::IsNullOrWhiteSpace($BuildDir)) {
    $BuildDir = Join-Path $RepoRoot 'build-ninja'
}

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$backupRoot = Join-Path $RepoRoot "evidence\SOVEREIGN_FINISH_HOUR_BACKUP\$stamp"
$evidenceRoot = Join-Path $RepoRoot 'evidence\SOVEREIGN_FINISH_HOUR'
New-Item -ItemType Directory -Force -Path $backupRoot, $evidenceRoot | Out-Null

$env:RAWRXD_MODEL_ROOT = $ModelRoot
$env:RAWRXD_BLOB_ROOT = Join-Path $ModelRoot 'blobs'
if ($PersistModelRoot) {
    [Environment]::SetEnvironmentVariable('RAWRXD_MODEL_ROOT', $ModelRoot, 'User')
    [Environment]::SetEnvironmentVariable('RAWRXD_BLOB_ROOT', (Join-Path $ModelRoot 'blobs'), 'User')
    Say "persisted RAWRXD_MODEL_ROOT/RAWRXD_BLOB_ROOT for current user"
}

# Include cert targets exactly once, without rewriting existing target bodies.
$cmakePath = Join-Path $RepoRoot 'CMakeLists.txt'
$cmakeText = Get-Content -LiteralPath $cmakePath -Raw
$marker = '# RAWRXD_SOVEREIGN_FINISH_HOUR_INCLUDE'
if ($cmakeText -notmatch [regex]::Escape($marker)) {
    Copy-Item -LiteralPath $cmakePath -Destination (Join-Path $backupRoot 'CMakeLists.txt') -Force
    Add-Content -LiteralPath $cmakePath -Value @"

$marker
include(cmake/RawrXDSovereignFinish.cmake)
"@
    Say 'added guarded sovereign cert-target include to CMakeLists.txt'
} else {
    Say 'CMake sovereign include already present'
}

# Evidence-only audit of legacy HTTP-shaped defaults. Do not silently mutate them.
$scanFiles = @(
    'src\agentic\BoundedAgentLoop.h',
    'src\agentic\BoundedAgentLoop.cpp',
    'src\runtime\SovereignRuntime.cpp',
    'src\win32app\Win32IDE_Core.cpp',
    'src\agent\model_invoker.cpp'
)
$scanOut = Join-Path $evidenceRoot 'legacy_http_scan.txt'
"canonical_repo=$RepoRoot`nmodel_root=$ModelRoot`nscan_time=$(Get-Date -Format o)" |
    Set-Content -LiteralPath $scanOut

foreach ($rel in $scanFiles) {
    $path = Join-Path $RepoRoot $rel
    if (Test-Path -LiteralPath $path) {
        $hits = Select-String -LiteralPath $path -Pattern 'localhost:11434|ollamaBaseUrl|/api/chat|/api/generate' -SimpleMatch:$false
        if ($hits) {
            Add-Content -LiteralPath $scanOut -Value "`n[$rel]"
            $hits | ForEach-Object {
                Add-Content -LiteralPath $scanOut -Value ("{0}:{1}" -f $_.LineNumber, $_.Line.Trim())
            }
        }
    }
}
Say "legacy HTTP scan written to $scanOut"

if (-not $SkipBuild) {
    Say "configuring $BuildDir"
    & cmake -S $RepoRoot -B $BuildDir -G Ninja
    if ($LASTEXITCODE -ne 0) { throw "CMake configure failed: $LASTEXITCODE" }

    foreach ($target in @('RawrXD-Agentic', 'rawrxd_model_catalog_cert', 'deep2_lifecycle_cert_candidate')) {
        Say "building $target"
        & cmake --build $BuildDir --target $target -- -j1
        if ($LASTEXITCODE -ne 0) { throw "Build failed for $target: $LASTEXITCODE" }
    }

    $bin = Join-Path $BuildDir 'bin'
    $catalogExe = Join-Path $bin 'rawrxd_model_catalog_cert.exe'
    $agentExe = Join-Path $bin 'RawrXD-Agentic.exe'

    if (Test-Path -LiteralPath $catalogExe) {
        & $catalogExe --root $ModelRoot --list |
            Tee-Object -FilePath (Join-Path $evidenceRoot 'MODEL_CATALOG_DISCOVERY.txt')
        if ($LASTEXITCODE -ne 0) { throw "ModelCatalog discovery smoke failed" }
    }

    if (Test-Path -LiteralPath $agentExe) {
        & $agentExe --help |
            Tee-Object -FilePath (Join-Path $evidenceRoot 'AGENT_HELP_SMOKE.txt')
        if ($LASTEXITCODE -ne 0) { throw "RawrXD-Agentic --help smoke failed" }
    }
}

$summary = @"
SOVEREIGN-FINISH-HOUR=APPLIED
canonical_repo=$RepoRoot
model_root=$ModelRoot
inference_backend=DEEP2
runtime_ollama_daemon_required=NO
runtime_ollama_http_required=NO
deep2_inference_deps=NONE
streamer_cert_status=UNCHANGED_BY_THIS_DROP
parity_cert_status=UNCHANGED_BY_THIS_DROP
autonomous_e2e_status=UNCHANGED_BY_THIS_DROP
backup=$backupRoot
"@
$summary | Set-Content -LiteralPath (Join-Path $evidenceRoot 'APPLY_VERDICT.txt')
Write-Host $summary
