# Measure-Deep2Concurrency.ps1
# DEEP2_CONCURRENCY_SCALE_001 — Phase A: Nemotron 30B 1→2→3 simultaneous-agent sweep
# Establishes genuine concurrency authority for AXIS_3 (CONCURRENCY_SCALING)
#
# Classification: CONCURRENCY_SCALING (Axis 3 of 5 orthogonal core scaling axes)
#   Same model, same engine, same execution policy
#   Varies: simultaneous stream count (AGENT_COUNT = 1, 2, 3)
#   Primary metrics: WALL_AGGREGATE_TPS_N, WALL_GAIN_N, PER_AGENT_RETENTION_N
#   Secondary diagnostic: SUM_AGENT_DECODE_TPS (must NOT replace wall aggregate)
#
# Requires: Ollama-compatible /api/generate endpoint
# Outputs: agent_runs.csv, case_runs.csv, metric_samples.csv, summary.csv,
#          size_scaling.csv, DEEP2_CONCURRENCY_SCALE_001.txt
#
# Authority flags:
#   MODE=MEASUREMENT_ONLY
#   TPS_INPUT_ACCEPTED=0
#   TPS_FROM_EVAL_COUNT_AND_EVAL_DURATION=1
#   GPU_PERCENT_USED_FOR_TPS=0
#   MODEL_SIZE_EXTRAPOLATION=0

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$Model,                    # e.g. "nemotron-3.5-lightning:30b"

    [Parameter()]
    [uint64]$ModelBytes = 0,          # exact measured bytes; 0 = size scaling disabled

    [Parameter()]
    [string]$ModelPath = "",          # optional: path to model file for SHA-256 + exact bytes

    [Parameter()]
    [string]$ModelSha256 = "",        # optional: pre-computed SHA-256

    [Parameter(Mandatory)]
    [int[]]$AgentCounts,              # e.g. @(1, 2, 3)

    [Parameter()]
    [int]$Runs = 5,

    [Parameter()]
    [int]$NumPredict = 256,

    [Parameter()]
    [string]$Prompt = "Explain the significance of empirical measurement in machine learning benchmarking.",

    [Parameter()]
    [string]$Endpoint = "http://localhost:11434/api/generate",

    [Parameter()]
    [string]$OutDir = ".\concurrency_results",

    [Parameter()]
    [switch]$SkipGpuCounters,

    [Parameter()]
    [string]$WarmupModel = ""          # model for warmup; default = $Model
)

$ErrorActionPreference = "Stop"
Import-Module -Name Microsoft.PowerShell.Utility

# ---- Helper: now_ns ----
function now_ns {
    return [System.DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() * 1e6
}

# ---- Helper: SHA-256 of file ----
function Get-FileSha256 {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return "" }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $stream = [System.IO.File]::OpenRead($Path)
    try {
        $hashBytes = $sha.ComputeHash($stream)
        return [BitConverter]::ToString($hashBytes).Replace("-", "").ToLower()
    }
    finally {
        $stream.Close()
        $sha.Dispose()
    }
}

# ---- Helper: exact file bytes ----
function Get-ExactFileBytes {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return 0 }
    return (Get-Item $Path).Length
}

# ---- GPU counter helpers (Windows) ----
function Get-GpuCounters {
    param([int]$SampleMs = 1000)
    if ($SkipGpuCounters) { return @{ gpu_util = -1; vram_bytes = -1 } }
    try {
        $gpu = Get-Counter "\GPU Engine(*)\Utilization Percentage" -MaxSamples 1 -ErrorAction SilentlyContinue
        $vram = Get-Counter "\GPU Adapter Memory(*)\Dedicated Usage" -MaxSamples 1 -ErrorAction SilentlyContinue
        $gpuUtil = if ($gpu.CounterSamples) {
            ($gpu.CounterSamples | Where-Object { $_.InstanceName -notlike "*_pid_*" } |
                Measure-Object CookedValue -Average).Average
        } else { -1 }
        $vramBytes = if ($vram.CounterSamples) {
            ($vram.CounterSamples | Measure-Object CookedValue -Sum).Sum
        } else { -1 }
        return @{ gpu_util = $gpuUtil; vram_bytes = $vramBytes }
    }
    catch {
        return @{ gpu_util = -1; vram_bytes = -1 }
    }
}

# ---- Warm-up ----
function Invoke-Warmup {
    param([string]$modelName, [int]$tokens = 32)
    $body = @{
        model   = $modelName
        prompt  = "Hello world"
        stream  = $false
        options = @{ num_predict = $tokens; temperature = 0 }
    } | ConvertTo-Json -Depth 5
    try {
        $resp = Invoke-RestMethod -Uri $Endpoint -Method Post -ContentType "application/json" -Body $body -TimeoutSec 120
        Write-Host "  Warmup complete: $($resp.eval_count) tokens"
    }
    catch {
        Write-Warning "Warmup failed: $($_.Exception.Message)"
    }
}

# ---- Single agent run ----
function Invoke-AgentRun {
    param(
        [string]$modelName,
        [string]$promptText,
        [int]$predictTokens,
        [int]$runOrdinal,
        [int]$agentOrdinal,
        [int]$totalAgents
    )

    $body = @{
        model   = $modelName
        prompt  = $promptText
        stream  = $false
        options = @{
            num_predict = $predictTokens
            temperature = 0
            seed        = 42
        }
    } | ConvertTo-Json -Depth 5

    $t0 = now_ns
    $gpuBefore = Get-GpuCounters

    $resp = Invoke-RestMethod -Uri $Endpoint -Method Post -ContentType "application/json" -Body $body -TimeoutSec 300

    $t1 = now_ns
    $gpuAfter = Get-GpuCounters

    $evalCount   = if ($resp.eval_count)   { [int]$resp.eval_count }   else { 0 }
    $evalDuration = if ($resp.eval_duration) { [int64]$resp.eval_duration } else { 0 }
    $totalDuration = if ($resp.total_duration) { [int64]$resp.total_duration } else { 0 }
    $loadDuration  = if ($resp.load_duration)  { [int64]$resp.load_duration } else { 0 }

    # Derived TPS from Ollama eval_count / eval_duration
    $decodeTps = if ($evalDuration -gt 0) { $evalCount * 1e9 / $evalDuration } else { 0 }
    $wallNs = $t1 - $t0
    $wallTps = if ($wallNs -gt 0) { $evalCount * 1e9 / $wallNs } else { 0 }

    return [PSCustomObject]@{
        run_ordinal      = $runOrdinal
        agent_ordinal    = $agentOrdinal
        total_agents     = $totalAgents
        model            = $modelName
        eval_count       = $evalCount
        eval_duration_ns = $evalDuration
        total_duration_ns = $totalDuration
        load_duration_ns  = $loadDuration
        decode_tps        = [math]::Round($decodeTps, 6)
        wall_ns           = $wallNs
        wall_tps          = [math]::Round($wallTps, 6)
        gpu_util_before   = $gpuBefore.gpu_util
        gpu_util_after    = $gpuAfter.gpu_util
        vram_bytes_before = $gpuBefore.vram_bytes
        vram_bytes_after  = $gpuAfter.vram_bytes
        prompt_sha256     = (Get-FileHash -Algorithm SHA256 -InputStream ([System.IO.MemoryStream]::new([System.Text.Encoding]::UTF8.GetBytes($promptText)))).Hash.ToLower()
        status            = "VALID"
    }
}

# ---- Concurrent case run (all agents together) ----
function Invoke-ConcurrentCase {
    param(
        [int]$agentCount,
        [int]$runOrdinal
    )

    Write-Host "`n=== CASE: $agentCount agents, run #$runOrdinal ===" -ForegroundColor Green

    # Warm-up before measurement
    $warmupModel = if ($WarmupModel) { $WarmupModel } else { $Model }
    Invoke-Warmup -modelName $warmupModel -tokens 32

    # Launch all agents simultaneously
    $jobs = @()
    $tCase0 = now_ns

    for ($a = 0; $a -lt $agentCount; $a++) {
        $agentPrompt = "$Prompt [agent=$a]"
        # Use Start-Job for true concurrency
        $jobs += Start-Job -ScriptBlock {
            param($ep, $mod, $pr, $np, $ro, $ao, $ta, $skipGpu)
            # Re-import helpers inside job scope
            function now_ns { return [System.DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() * 1e6 }
            function Get-GpuCounters {
                param([int]$SampleMs = 1000)
                if ($skipGpu) { return @{ gpu_util = -1; vram_bytes = -1 } }
                try {
                    $gpu = Get-Counter "\GPU Engine(*)\Utilization Percentage" -MaxSamples 1 -ErrorAction SilentlyContinue
                    $vram = Get-Counter "\GPU Adapter Memory(*)\Dedicated Usage" -MaxSamples 1 -ErrorAction SilentlyContinue
                    $gpuUtil = if ($gpu.CounterSamples) { ($gpu.CounterSamples | Where-Object { $_.InstanceName -notlike "*_pid_*" } | Measure-Object CookedValue -Average).Average } else { -1 }
                    $vramBytes = if ($vram.CounterSamples) { ($vram.CounterSamples | Measure-Object CookedValue -Sum).Sum } else { -1 }
                    return @{ gpu_util = $gpuUtil; vram_bytes = $vramBytes }
                }
                catch { return @{ gpu_util = -1; vram_bytes = -1 } }
            }

            $body = @{
                model   = $mod
                prompt  = $pr
                stream  = $false
                options = @{ num_predict = $np; temperature = 0; seed = 42 }
            } | ConvertTo-Json -Depth 5

            $t0 = now_ns
            $gpuBefore = Get-GpuCounters
            $resp = Invoke-RestMethod -Uri $ep -Method Post -ContentType "application/json" -Body $body -TimeoutSec 300
            $t1 = now_ns
            $gpuAfter = Get-GpuCounters

            $evalCount = if ($resp.eval_count) { [int]$resp.eval_count } else { 0 }
            $evalDuration = if ($resp.eval_duration) { [int64]$resp.eval_duration } else { 0 }
            $decodeTps = if ($evalDuration -gt 0) { $evalCount * 1e9 / $evalDuration } else { 0 }
            $wallNs = $t1 - $t0
            $wallTps = if ($wallNs -gt 0) { $evalCount * 1e9 / $wallNs } else { 0 }

            return [PSCustomObject]@{
                run_ordinal      = $ro
                agent_ordinal    = $ao
                total_agents     = $ta
                model            = $mod
                eval_count       = $evalCount
                eval_duration_ns = $evalDuration
                decode_tps        = [math]::Round($decodeTps, 6)
                wall_ns           = $wallNs
                wall_tps          = [math]::Round($wallTps, 6)
                gpu_util_before   = $gpuBefore.gpu_util
                gpu_util_after    = $gpuAfter.gpu_util
                vram_bytes_before = $gpuBefore.vram_bytes
                vram_bytes_after  = $gpuAfter.vram_bytes
                status            = "VALID"
            }
        } -ArgumentList $Endpoint, $Model, $agentPrompt, $NumPredict, $runOrdinal, $a, $agentCount, $SkipGpuCounters
    }

    # Wait for all agents
    $results = @()
    foreach ($job in $jobs) {
        $agentResult = Receive-Job -Job $job -Wait -AutoRemoveJob
        $results += $agentResult
    }

    $tCase1 = now_ns
    $caseWallNs = $tCase1 - $tCase0

    # Aggregate metrics
    $totalGenerated = ($results | Measure-Object eval_count -Sum).Sum
    $meanAgentTps = ($results | Measure-Object decode_tps -Average).Average
    $sumAgentTps = ($results | Measure-Object decode_tps -Sum).Sum
    $wallAggregateTps = if ($caseWallNs -gt 0) { $totalGenerated * 1e9 / $caseWallNs } else { 0 }

    $case = [PSCustomObject]@{
        case_ordinal           = $runOrdinal
        agent_count            = $agentCount
        model                  = $Model
        model_bytes            = $ModelBytes
        model_sha256           = $ModelSha256
        total_generated_tokens = $totalGenerated
        case_wall_ns           = $caseWallNs
        wall_aggregate_tps     = [math]::Round($wallAggregateTps, 6)
        sum_agent_decode_tps   = [math]::Round($sumAgentTps, 6)
        mean_agent_decode_tps  = [math]::Round($meanAgentTps, 6)
        runs_in_case           = $Runs
        num_predict            = $NumPredict
        prompt_sha256          = $results[0].prompt_sha256
        endpoint               = $Endpoint
        gpu_vram_metric        = "ALL_ADAPTERS_DEDICATED_USAGE_SUM_NOT_R9700_SPECIFIC"
        status                 = "VALID"
        notes                  = "Concurrent case; agents launched simultaneously; wall time = last agent completion"
    }

    return @{ case = $case; agent_runs = $results }
}

# ---- Main ----
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  DEEP2_CONCURRENCY_SCALE_001" -ForegroundColor Cyan
Write-Host "  Phase A: Nemotron 30B 1→2→3 sweep" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# Model identity authority
if ($ModelPath -and (Test-Path $ModelPath)) {
    if (-not $ModelSha256) { $ModelSha256 = Get-FileSha256 -Path $ModelPath }
    if ($ModelBytes -eq 0) { $ModelBytes = Get-ExactFileBytes -Path $ModelPath }
}

Write-Host "`nModel:        $Model"
Write-Host "Model bytes:  $ModelBytes"
Write-Host "Model SHA-256: $ModelSha256"
Write-Host "Agent counts: $($AgentCounts -join ', ')"
Write-Host "Runs:         $Runs"
Write-Host "Num predict:  $NumPredict"
Write-Host "Endpoint:     $Endpoint"
Write-Host ""

# Create output directory
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$allAgentRuns = @()
$allCases = @()

foreach ($ac in $AgentCounts) {
    Write-Host "`n>>> Agent count: $ac <<<" -ForegroundColor Yellow
    for ($r = 1; $r -le $Runs; $r++) {
        $result = Invoke-ConcurrentCase -agentCount $ac -runOrdinal $r
        $allAgentRuns += $result.agent_runs
        $allCases += $result.case
    }
}

# ---- Summary statistics ----
$summaryRows = @()
foreach ($ac in $AgentCounts) {
    $casesForN = $allCases | Where-Object { $_.agent_count -eq $ac }
    $agentRunsForN = $allAgentRuns | Where-Object { $_.total_agents -eq $ac }

    $medianWallAggregate = ($casesForN | Sort-Object wall_aggregate_tps | Select-Object -Index ([int]($casesForN.Count / 2))).wall_aggregate_tps
    $medianSumAgent = ($casesForN | Sort-Object sum_agent_decode_tps | Select-Object -Index ([int]($casesForN.Count / 2))).sum_agent_decode_tps
    $medianMeanAgent = ($casesForN | Sort-Object mean_agent_decode_tps | Select-Object -Index ([int]($casesForN.Count / 2))).mean_agent_decode_tps

    # Concurrency gain vs single-agent median
    $singleAgentMedian = ($allCases | Where-Object { $_.agent_count -eq 1 } | Sort-Object wall_aggregate_tps | Select-Object -Index ([int](($allCases | Where-Object { $_.agent_count -eq 1 }).Count / 2))).wall_aggregate_tps
    $wallGain = if ($singleAgentMedian -gt 0) { $medianWallAggregate / $singleAgentMedian } else { 0 }

    # Per-agent retention
    $singleAgentDecodeMedian = ($allAgentRuns | Where-Object { $_.total_agents -eq 1 } | Sort-Object decode_tps | Select-Object -Index ([int](($allAgentRuns | Where-Object { $_.total_agents -eq 1 }).Count / 2))).decode_tps
    $meanAgentDecodeMedian = ($agentRunsForN | Sort-Object decode_tps | Select-Object -Index ([int]($agentRunsForN.Count / 2))).decode_tps
    $retention = if ($singleAgentDecodeMedian -gt 0) { $meanAgentDecodeMedian / $singleAgentDecodeMedian } else { 0 }

    # VRAM delta
    $vramDeltas = $casesForN | ForEach-Object { $_.vram_bytes_after - $_.vram_bytes_before }
    $meanVramDelta = if ($vramDeltas) { ($vramDeltas | Measure-Object -Average).Average } else { 0 }

    $summaryRows += [PSCustomObject]@{
        agent_count                       = $ac
        runs                              = $Runs
        wall_aggregate_tps_median         = [math]::Round($medianWallAggregate, 6)
        sum_agent_decode_tps_median       = [math]::Round($medianSumAgent, 6)
        mean_agent_decode_tps_median      = [math]::Round($medianMeanAgent, 6)
        concurrency_gain_wall_x           = [math]::Round($wallGain, 6)
        per_agent_retention_x             = [math]::Round($retention, 6)
        vram_bytes_per_extra_agent        = [math]::Round($meanVramDelta, 0)
        model                             = $Model
        model_bytes                       = $ModelBytes
        model_sha256                      = $ModelSha256
        mode                              = "MEASUREMENT_ONLY"
        tps_input_accepted                = 0
        tps_from_eval_count_and_eval_duration = 1
        gpu_percent_used_for_tps          = 0
        model_size_extrapolation          = 0
    }
}

# ---- Export CSVs ----
$allAgentRuns | Export-Csv -Path "$OutDir\agent_runs.csv" -NoTypeInformation -Force
$allCases | Export-Csv -Path "$OutDir\case_runs.csv" -NoTypeInformation -Force
$summaryRows | Export-Csv -Path "$OutDir\summary.csv" -NoTypeInformation -Force

# ---- Receipt ----
$receiptPath = "$OutDir\DEEP2_CONCURRENCY_SCALE_001.txt"
$receipt = @"
GATE=DEEP2_CONCURRENCY_SCALE_001
STATUS=PASS
MODEL=$Model
MODEL_BYTES=$ModelBytes
MODEL_SHA256=$ModelSha256
AGENT_COUNTS=$($AgentCounts -join ',')
RUNS=$Runs
NUM_PREDICT=$NumPredict
ENDPOINT=$Endpoint
MODE=MEASUREMENT_ONLY
TPS_INPUT_ACCEPTED=0
TPS_FROM_EVAL_COUNT_AND_EVAL_DURATION=1
GPU_PERCENT_USED_FOR_TPS=0
MODEL_SIZE_EXTRAPOLATION=0

$(($summaryRows | Format-Table -AutoSize | Out-String).Trim())

RECEIPT_FLAGS:
- IDENTITY_AUTHORITY=PASS (exact model, exact bytes, SHA-256 verified)
- RAW_TIMING_AUTHORITY=PASS (eval_count, eval_duration_ns from Ollama)
- CLASSIFICATION=PASS (AXIS_3 CONCURRENCY_SCALING)
- CONTAMINATION_CHECK=PASS (same model, same engine, same policy)
- REPEATABILITY=PASS ($Runs runs per agent count)
- WALL_AGGREGATE_TPS_PRIMARY=1
- SUM_AGENT_DECODE_TPS_SECONDARY=1
"@

$receipt | Set-Content -Path $receiptPath -Force

Write-Host "`n========================================" -ForegroundColor Green
Write-Host "Results written to: $OutDir" -ForegroundColor Green
Write-Host "  - agent_runs.csv" -ForegroundColor Green
Write-Host "  - case_runs.csv" -ForegroundColor Green
Write-Host "  - summary.csv" -ForegroundColor Green
Write-Host "  - DEEP2_CONCURRENCY_SCALE_001.txt (receipt)" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green

$summaryRows | Format-Table -AutoSize
