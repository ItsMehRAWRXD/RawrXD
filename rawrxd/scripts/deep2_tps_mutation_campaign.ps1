[CmdletBinding()]
param(
    [string]$GateScript = (Join-Path $PSScriptRoot 'deep2_tps_mutation_gate.ps1'),
    [string]$MutationScript = (Join-Path $PSScriptRoot '..\tools\mutate_qgemv_q6_algebra.ps1'),
    [string]$BuildCommand = 'pwsh',
    [string[]]$BuildArguments = @('-NoProfile', '-File', 'scripts/build_s12_parity.ps1'),
    [string]$ValidationCommand = 'C:\VulkanSDK\1.4.357.0\Bin\spirv-val.exe',
    [string[]]$ValidationArguments = @('--target-env', 'vulkan1.2', 'rawrxd/src/deep2/shaders/deep2_qgemv_batch8row.spv'),
    [string]$BenchmarkScript = (Join-Path $PSScriptRoot 'deep2_gpu_flight_recorder.ps1'),
    [string]$Exe = (Join-Path $PSScriptRoot '..\..\_s12_parity_build\bin\deep2_end_to_end_bench.exe'),
    [string]$Model = 'F:\~dev\qwen2.5-coder-1.5b-base.gguf',
    [double]$BaselineMedianTps = 31.392,
    [double]$MinRelativeGain = 0.005,
    [int]$Tokens = 32,
    [int]$Runs = 3,
    [int]$WarmupRuns = 1,
    [int]$TimeoutSec = 180,
    [string]$OutputDir = '',
    [switch]$ResumeBenchmarks
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$resolvedGate = [System.IO.Path]::GetFullPath($GateScript)
$resolvedMutation = [System.IO.Path]::GetFullPath($MutationScript)
$resolvedBenchmark = [System.IO.Path]::GetFullPath($BenchmarkScript)
$resolvedExe = [System.IO.Path]::GetFullPath($Exe)
$resolvedModel = [System.IO.Path]::GetFullPath($Model)
foreach ($path in @($resolvedGate, $resolvedMutation, $resolvedBenchmark, $resolvedExe, $resolvedModel)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Required path not found: $path" }
}
if ($BaselineMedianTps -le 0) { throw 'BaselineMedianTps must be positive.' }
if ($MinRelativeGain -lt 0) { throw 'MinRelativeGain cannot be negative.' }

if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    $OutputDir = Join-Path (Get-Location) ("deep2_mutation_campaign_{0}" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
}
$OutputDir = [System.IO.Path]::GetFullPath($OutputDir)
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

$files = @(
    'rawrxd/src/deep2/shaders/deep2_qgemv_batch8row.comp',
    'rawrxd/src/deep2/shaders/deep2_qgemv_batch8row.spv',
    'rawrxd/src/deep2/shaders/deep2_qgemv_q6row.comp',
    'rawrxd/src/deep2/shaders/deep2_qgemv_q6row.spv',
    'rawrxd/src/deep2/vulkan_compute.cpp',
    'rawrxd/src/deep2/vulkan_compute.h'
)
$candidates = @(
    [pscustomobject]@{ name = 'primary-hoist-scale'; variant = 'hoist_scale'; primaryOnly = $true; q6SingleRow = $false; tile = '8'; gpu0 = '100'; gpu1 = '0.01' },
    [pscustomobject]@{ name = 'primary-half-load'; variant = 'half_load'; primaryOnly = $true; q6SingleRow = $false; tile = '8'; gpu0 = '100'; gpu1 = '0.01' },
    [pscustomobject]@{ name = 'primary-combined'; variant = 'hoist_scale_half_load'; primaryOnly = $true; q6SingleRow = $false; tile = '8'; gpu0 = '100'; gpu1 = '0.01' },
    [pscustomobject]@{ name = 'primary-batch1-loads'; variant = 'skip_unused_batch_rows'; primaryOnly = $true; q6SingleRow = $false; tile = '8'; gpu0 = '100'; gpu1 = '0.01' },
    [pscustomobject]@{ name = 'primary-combined-auto-tile'; variant = 'hoist_scale_half_load'; primaryOnly = $true; q6SingleRow = $false; tile = 'auto'; gpu0 = '100'; gpu1 = '0.01' },
    [pscustomobject]@{ name = 'primary-single-row'; variant = 'skip_unused_batch_rows'; primaryOnly = $true; q6SingleRow = $true; tile = '8'; gpu0 = '100'; gpu1 = '0.01' },
    [pscustomobject]@{ name = 'split-combined'; variant = 'hoist_scale_half_load'; primaryOnly = $false; q6SingleRow = $false; tile = '8'; gpu0 = '100'; gpu1 = '0.01' }
)

$manifest = [ordered]@{
    schema = 'RAWRXD_DEEP2_TPS_MUTATION_CAMPAIGN_001'
    repo_root = $repoRoot
    benchmark_resume_required = $true
    resume_benchmarks = [bool]$ResumeBenchmarks
    baseline_median_tps = $BaselineMedianTps
    min_relative_gain = $MinRelativeGain
    candidate_count = $candidates.Count
    candidates = @($candidates)
    generated_utc = [DateTime]::UtcNow.ToString('o')
}
$manifestPath = Join-Path $OutputDir 'campaign_manifest.json'
$manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
Write-Output "MANIFEST=$manifestPath"

if (-not $ResumeBenchmarks) {
    Write-Output 'BENCHMARKS=PAUSED'
    exit 0
}

$oldVariant = [Environment]::GetEnvironmentVariable('RAWRXD_MUTATION_VARIANT', 'Process')
$campaignResults = [System.Collections.Generic.List[object]]::new()
$accepted = $false
try {
    $index = 0
    foreach ($candidate in $candidates) {
        $index++
        $candidateDir = Join-Path $OutputDir ("{0:D2}_{1}" -f $index, $candidate.name)
        New-Item -ItemType Directory -Path $candidateDir -Force | Out-Null
        [Environment]::SetEnvironmentVariable('RAWRXD_MUTATION_VARIANT', $candidate.variant, 'Process')
        $benchmarkArguments = @(
            '-Exe', $resolvedExe,
            '-Model', $resolvedModel,
            '-Tokens', $Tokens,
            '-WarmupRuns', $WarmupRuns,
            '-Runs', $Runs,
            '-TimeoutSec', $TimeoutSec,
            '-Q4Hot', '-Q6Hot',
            '-DenseExec', 'LAYER_SPLIT',
            '-Q4Tile', $candidate.tile,
            '-Gpu0Weight', $candidate.gpu0,
            '-Gpu1Weight', $candidate.gpu1,
            '-NoTrace',
            '-OutputDir', (Join-Path $candidateDir 'benchmark')
        )
        if ($candidate.primaryOnly) { $benchmarkArguments += '-PrimaryOnly' }
        if ($candidate.q6SingleRow) { $benchmarkArguments += '-Q6SingleRow' }
        $gateArguments = @(
            '-NoProfile', '-File', $resolvedGate,
            '-MutationScript', $resolvedMutation,
            '-FilesJson', ($files | ConvertTo-Json -Compress),
            '-BuildCommand', $BuildCommand,
            '-BuildArgumentsJson', ($BuildArguments | ConvertTo-Json -Compress),
            '-ValidationCommand', $ValidationCommand,
            '-ValidationArgumentsJson', ($ValidationArguments | ConvertTo-Json -Compress),
            '-BenchmarkScript', $resolvedBenchmark,
            '-BenchmarkArgumentsJson', ($benchmarkArguments | ConvertTo-Json -Compress),
            '-BaselineMedianTps', $BaselineMedianTps,
            '-MinRelativeGain', $MinRelativeGain,
            '-RepoRoot', $repoRoot,
            '-ReportPath', (Join-Path $candidateDir 'gate_report.json'),
            '-LedgerPath', (Join-Path $OutputDir 'mutation_ledger.jsonl'),
            '-KeepRejectedSnapshot'
        )
        if ($ResumeBenchmarks) { $gateArguments += '-ResumeBenchmarks' }
        $consolePath = Join-Path $candidateDir 'gate_console.txt'
        Write-Output ("CANDIDATE={0} VARIANT={1} PRIMARY_ONLY={2}" -f $candidate.name, $candidate.variant, $candidate.primaryOnly)
        $output = @(& pwsh @gateArguments 2>&1 | Tee-Object -FilePath $consolePath)
        $exitCode = if ($null -eq $LASTEXITCODE) { 0 } else { $LASTEXITCODE }
        $acceptedCandidate = $exitCode -eq 0 -and ($output -match 'VERDICT=ACCEPTED')
        $campaignResults.Add([pscustomobject]@{
            name = $candidate.name
            variant = $candidate.variant
            primary_only = [bool]$candidate.primaryOnly
            q6_single_row = [bool]$candidate.q6SingleRow
            exit_code = $exitCode
            accepted = $acceptedCandidate
            report = (Join-Path $candidateDir 'gate_report.json')
        })
        Write-Output ("RESULT={0} EXIT={1} ACCEPTED={2}" -f $candidate.name, $exitCode, $acceptedCandidate)
        if ($acceptedCandidate) {
            $accepted = $true
            break
        }
    }
}
finally {
    [Environment]::SetEnvironmentVariable('RAWRXD_MUTATION_VARIANT', $oldVariant, 'Process')
}

$resultPath = Join-Path $OutputDir 'campaign_result.json'
[ordered]@{
    schema = 'RAWRXD_DEEP2_TPS_MUTATION_CAMPAIGN_RESULT_001'
    verdict = if ($accepted) { 'ACCEPTED' } else { 'NO_ACCEPTED_CANDIDATE' }
    manifest = $manifestPath
    results = @($campaignResults)
    generated_utc = [DateTime]::UtcNow.ToString('o')
} | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $resultPath -Encoding UTF8
Write-Output "RESULT_FILE=$resultPath"
if (-not $accepted) { exit 2 }
