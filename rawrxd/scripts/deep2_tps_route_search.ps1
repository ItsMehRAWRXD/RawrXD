[CmdletBinding()]
param(
    [string]$Recorder = (Join-Path $PSScriptRoot 'deep2_gpu_flight_recorder.ps1'),
    [string]$Exe = (Join-Path $PSScriptRoot '..\..\_s12_parity_build\bin\deep2_end_to_end_bench.exe'),
    [string]$Model = 'F:\~dev\qwen2.5-coder-1.5b-base.gguf',
    [double]$BaselineMedianTps = 30.101,
    [double]$MinRelativeGain = 0.005,
    [int]$Tokens = 32,
    [int]$Runs = 3,
    [int]$WarmupRuns = 1,
    [int]$TimeoutSec = 180,
    [string]$OutputDir = '',
    [switch]$NoTrace,
    [switch]$StopAfterFirstAccepted
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($BaselineMedianTps -le 0) { throw 'BaselineMedianTps must be positive.' }
if ($MinRelativeGain -lt 0) { throw 'MinRelativeGain cannot be negative.' }
if ($Tokens -lt 1) { throw 'Tokens must be positive.' }
if ($Runs -lt 1) { throw 'Runs must be positive.' }
if ($WarmupRuns -lt 0) { throw 'WarmupRuns cannot be negative.' }

$recorderPath = [System.IO.Path]::GetFullPath($Recorder)
$exePath = [System.IO.Path]::GetFullPath($Exe)
$modelPath = [System.IO.Path]::GetFullPath($Model)
if (-not (Test-Path -LiteralPath $recorderPath -PathType Leaf)) { throw "Recorder not found: $recorderPath" }
if (-not (Test-Path -LiteralPath $exePath -PathType Leaf)) { throw "Executable not found: $exePath" }
if (-not (Test-Path -LiteralPath $modelPath -PathType Leaf)) { throw "Model not found: $modelPath" }

if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    $OutputDir = Join-Path (Get-Location) ("deep2_route_search_{0}" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
}
$OutputDir = [System.IO.Path]::GetFullPath($OutputDir)
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

$candidates = @(
    [pscustomobject]@{ name = 'primary-only-tile8'; primaryOnly = $true; gpu0 = '100'; gpu1 = '0.01'; tile = '8' },
    [pscustomobject]@{ name = 'primary-only-auto-tile'; primaryOnly = $true; gpu0 = '100'; gpu1 = '0.01'; tile = 'auto' },
    [pscustomobject]@{ name = 'split-100-0.01-tile8'; primaryOnly = $false; gpu0 = '100'; gpu1 = '0.01'; tile = '8' },
    [pscustomobject]@{ name = 'split-90-10-tile8'; primaryOnly = $false; gpu0 = '90'; gpu1 = '10'; tile = '8' },
    [pscustomobject]@{ name = 'split-80-20-tile8'; primaryOnly = $false; gpu0 = '80'; gpu1 = '20'; tile = '8' },
    [pscustomobject]@{ name = 'split-100-0.01-auto-tile'; primaryOnly = $false; gpu0 = '100'; gpu1 = '0.01'; tile = 'auto' },
    [pscustomobject]@{ name = 'split-100-0.01-tile4'; primaryOnly = $false; gpu0 = '100'; gpu1 = '0.01'; tile = '4' }
)

function Get-Median([double[]]$Values) {
    $ordered = @($Values | Sort-Object)
    if ($ordered.Count -eq 0) { return $null }
    $middle = [int][Math]::Floor($ordered.Count / 2)
    if (($ordered.Count % 2) -eq 1) { return [double]$ordered[$middle] }
    return ([double]$ordered[$middle - 1] + [double]$ordered[$middle]) / 2.0
}

function Invoke-Candidate($candidate, [int]$index) {
    $candidateDir = Join-Path $OutputDir ("{0:D2}_{1}" -f $index, $candidate.name)
    New-Item -ItemType Directory -Path $candidateDir -Force | Out-Null
    $arguments = @(
        '-NoProfile', '-File', $recorderPath,
        '-Exe', $exePath,
        '-Model', $modelPath,
        '-Tokens', $Tokens,
        '-WarmupRuns', $WarmupRuns,
        '-Runs', $Runs,
        '-TimeoutSec', $TimeoutSec,
        '-OutputDir', $candidateDir,
        '-Q4Hot', '-Q6Hot',
        '-DenseExec', 'LAYER_SPLIT',
        '-Q4Tile', $candidate.tile,
        '-Gpu0Weight', $candidate.gpu0,
        '-Gpu1Weight', $candidate.gpu1
    )
    if ($candidate.primaryOnly) { $arguments += '-PrimaryOnly' }
    if ($NoTrace) { $arguments += '-NoTrace' }
    $consolePath = Join-Path $candidateDir 'search_console.txt'
    $output = @(& pwsh @arguments 2>&1 | Tee-Object -FilePath $consolePath)
    $exitCode = if ($null -eq $LASTEXITCODE) { 0 } else { $LASTEXITCODE }
    $reportPath = Join-Path $candidateDir 'flight_recorder_report.json'
    $valid = $false
    $median = $null
    $runTps = @()
    $failure = $null
    if ($exitCode -eq 0 -and (Test-Path -LiteralPath $reportPath -PathType Leaf)) {
        try {
            $report = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
            $passed = @($report.results | Where-Object { $_.pass -and $null -ne $_.decode_tps })
            if ($report.verdict -eq 'PASS' -and $passed.Count -eq $Runs) {
                $runTps = @($passed | ForEach-Object { [double]$_.decode_tps })
                $median = Get-Median $runTps
                $valid = $true
            } else {
                $failure = 'Recorder gate did not pass every requested run.'
            }
        } catch {
            $failure = $_.Exception.Message
        }
    } else {
        $failure = "Recorder exited with $exitCode or produced no report."
    }
    $required = $BaselineMedianTps * (1.0 + $MinRelativeGain)
    $accepted = $valid -and $median -gt $required
    [pscustomobject]@{
        name = $candidate.name
        primary_only = [bool]$candidate.primaryOnly
        gpu0_weight = $candidate.gpu0
        gpu1_weight = $candidate.gpu1
        q4_tile = $candidate.tile
        valid = $valid
        accepted = $accepted
        median_tps = $median
        required_median_tps = $required
        speedup = if ($null -ne $median) { $median / $BaselineMedianTps } else { $null }
        run_tps = @($runTps)
        failure = $failure
        report = $reportPath
    }
}

$results = [System.Collections.Generic.List[object]]::new()
$best = $null
$index = 0
foreach ($candidate in $candidates) {
    $index++
    Write-Output ("CANDIDATE={0} PRIMARY_ONLY={1} GPU0={2} GPU1={3} TILE={4}" -f $candidate.name, $candidate.primaryOnly, $candidate.gpu0, $candidate.gpu1, $candidate.tile)
    $result = Invoke-Candidate $candidate $index
    $results.Add($result)
    if ($result.valid -and ($null -eq $best -or $result.median_tps -gt $best.median_tps)) { $best = $result }
    Write-Output ("RESULT={0} VALID={1} ACCEPTED={2} MEDIAN_TPS={3} RUNS={4}" -f $result.name, $result.valid, $result.accepted, $result.median_tps, (($result.run_tps -join ',')))
    if ($StopAfterFirstAccepted -and $result.accepted) { break }
}

$acceptedResults = @($results | Where-Object { $_.accepted } | Sort-Object median_tps -Descending)
$verdict = if ($acceptedResults.Count -gt 0) { 'ACCEPTED_CONFIGURATION_FOUND' } else { 'NO_ACCEPTED_CONFIGURATION' }
$summary = [ordered]@{
    schema = 'RAWRXD_DEEP2_TPS_ROUTE_SEARCH_001'
    verdict = $verdict
    baseline_median_tps = $BaselineMedianTps
    min_relative_gain = $MinRelativeGain
    required_median_tps = $BaselineMedianTps * (1.0 + $MinRelativeGain)
    tokens = $Tokens
    runs = $Runs
    warmup_runs = $WarmupRuns
    candidates = @($results)
    best = $best
    accepted = @($acceptedResults)
    generated_utc = [DateTime]::UtcNow.ToString('o')
}
$summaryPath = Join-Path $OutputDir 'route_search_summary.json'
$summary | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $summaryPath -Encoding UTF8
Write-Output "SUMMARY=$summaryPath"
Write-Output "VERDICT=$verdict"
if ($null -ne $best) { Write-Output ("BEST={0} MEDIAN_TPS={1}" -f $best.name, $best.median_tps) }
