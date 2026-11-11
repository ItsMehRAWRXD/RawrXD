# ==============================================================================
# Sovereign Correlation Analyzer
# Correlates ring pressure telemetry with inferred completion latency by fill bins.
# ==============================================================================
param(
    [string]$MetricsCsvPath = "d:\rawrxd-ci-bootstrap\sovereign_metrics_sidecar.csv",
    [string]$GateLogPath = "",
    [string]$OutputCsvPath = "d:\rawrxd-ci-bootstrap\sovereign_correlation_report.csv",
    [string]$OutputJsonPath = "d:\rawrxd-ci-bootstrap\sovereign_correlation_report.json",
    [int]$SaturationThreshold = 48,
    [int]$BurnInSamples = 100
)

$ErrorActionPreference = "Stop"

function To-Int64Safe([object]$v) {
    if ($null -eq $v -or $v -eq "") { return [int64]0 }
    return [int64]$v
}

function To-DoubleSafe([object]$v) {
    if ($null -eq $v -or $v -eq "") { return [double]0 }
    return [double]$v
}

function Get-FillBin([int64]$fill) {
    if ($fill -lt 16) { return "0-15" }
    if ($fill -lt 32) { return "16-31" }
    if ($fill -lt 48) { return "32-47" }
    return "48-64"
}

function Get-StdDev([double[]]$values) {
    if ($null -eq $values -or $values.Count -lt 2) { return [double]0 }
    $avg = ($values | Measure-Object -Average).Average
    $sum = 0.0
    foreach ($x in $values) {
        $d = $x - $avg
        $sum += ($d * $d)
    }
    return [Math]::Sqrt($sum / ($values.Count - 1))
}

function Get-P95([double[]]$values) {
    if ($null -eq $values -or $values.Count -eq 0) { return [double]0 }
    $sorted = $values | Sort-Object
    $idx = [Math]::Floor(($sorted.Count - 1) * 0.95)
    return [double]$sorted[[int]$idx]
}

function Parse-GateLogSummary([string]$path) {
    if ([string]::IsNullOrWhiteSpace($path) -or -not (Test-Path $path)) {
        return $null
    }

    $text = Get-Content -Path $path -Raw
    $summary = [ordered]@{
        PassLine = ""
        CancelRecovered = ""
        AvgInferenceMs = ""
        P95InferenceMs = ""
        GatePassed = $false
    }

    $mPass = [regex]::Match($text, "Pass:\s*([^\r\n]+)")
    if ($mPass.Success) { $summary.PassLine = $mPass.Groups[1].Value.Trim() }

    $mCancel = [regex]::Match($text, "Cancel-Recovered:\s*([^\r\n]+)")
    if ($mCancel.Success) { $summary.CancelRecovered = $mCancel.Groups[1].Value.Trim() }

    $mAvg = [regex]::Match($text, "Avg Inference Completion \(ms\):\s*([^\r\n]+)")
    if ($mAvg.Success) { $summary.AvgInferenceMs = $mAvg.Groups[1].Value.Trim() }

    $mP95 = [regex]::Match($text, "P95 Inference Completion \(ms\):\s*([^\r\n]+)")
    if ($mP95.Success) { $summary.P95InferenceMs = $mP95.Groups[1].Value.Trim() }

    if ($text -match "REGRESSION GATE v5 PASSED") {
        $summary.GatePassed = $true
    }

    return [PSCustomObject]$summary
}

if (-not (Test-Path $MetricsCsvPath)) {
    throw "Metrics CSV not found: $MetricsCsvPath"
}

$raw = Import-Csv -Path $MetricsCsvPath
if ($raw.Count -eq 0) {
    throw "Metrics CSV is empty: $MetricsCsvPath"
}

# Normalize and sort samples for deterministic delta computation.
$samples = $raw | ForEach-Object {
    [PSCustomObject]@{
        sample_idx = To-Int64Safe $_.sample_idx
        elapsed_ms = To-Int64Safe $_.elapsed_ms
        fill_level = To-Int64Safe $_.fill_level
        ring_backpressure_delta = To-Int64Safe $_.ring_backpressure_delta
        ring_backpressure = To-Int64Safe $_.ring_backpressure
        ring_dropped_delta = To-Int64Safe $_.ring_dropped_delta
        ring_dropped = To-Int64Safe $_.ring_dropped
        last_timestamp_qpc = To-Int64Safe $_.last_timestamp_qpc
    }
} | Sort-Object sample_idx

if ($BurnInSamples -lt 0) {
    throw "BurnInSamples must be >= 0"
}

$effectiveSamples = if ($BurnInSamples -gt 0) {
    @($samples | Where-Object { $_.sample_idx -ge $BurnInSamples })
} else {
    @($samples)
}

if ($effectiveSamples.Count -eq 0) {
    throw "No samples remain after burn-in exclusion (BurnInSamples=$BurnInSamples, Total=$($samples.Count))"
}

# Infer completion latency from changes in last_timestamp_qpc.
# The source is GetTickCount64 in current worker path, so units are milliseconds.
$prevTs = 0L
$prevSeen = $false
for ($i = 0; $i -lt $effectiveSamples.Count; $i++) {
    $s = $effectiveSamples[$i]
    $bin = Get-FillBin $s.fill_level
    $effectiveSamples[$i] | Add-Member -NotePropertyName fill_bin -NotePropertyValue $bin

    $deltaMs = 0.0
    $isCompletionEvent = $false

    if ($s.last_timestamp_qpc -gt 0) {
        if (-not $prevSeen) {
            $prevSeen = $true
            $prevTs = $s.last_timestamp_qpc
        }
        elseif ($s.last_timestamp_qpc -ne $prevTs) {
            $rawDelta = $s.last_timestamp_qpc - $prevTs
            if ($rawDelta -gt 0 -and $rawDelta -lt 60000) {
                $deltaMs = [double]$rawDelta
                $isCompletionEvent = $true
            }
            $prevTs = $s.last_timestamp_qpc
        }
    }

    $effectiveSamples[$i] | Add-Member -NotePropertyName completion_delta_ms -NotePropertyValue $deltaMs
    $effectiveSamples[$i] | Add-Member -NotePropertyName completion_event -NotePropertyValue ([int]$isCompletionEvent)
}

$binOrder = @("0-15", "16-31", "32-47", "48-64")
$report = New-Object System.Collections.Generic.List[object]

foreach ($bin in $binOrder) {
    $group = $effectiveSamples | Where-Object { $_.fill_bin -eq $bin }
    if ($group.Count -eq 0) {
        $report.Add([PSCustomObject]@{
            FillBin = $bin
            SampleCount = 0
            AvgFill = 0
            MaxFill = 0
            BackpressureEvents = 0
            BackpressureDeltaSum = 0
            DroppedDeltaSum = 0
            AvgBackpressureDeltaPerSample = 0
            CompletionEvents = 0
            AvgLatencyMs = 0
            P95LatencyMs = 0
            StdDevLatencyMs = 0
        })
        continue
    }

    $completionValues = @($group | Where-Object { $_.completion_event -eq 1 } | ForEach-Object { [double]$_.completion_delta_ms })
    $avgLatency = if ($completionValues.Count -gt 0) { [Math]::Round(($completionValues | Measure-Object -Average).Average, 4) } else { 0 }
    $p95Latency = if ($completionValues.Count -gt 0) { [Math]::Round((Get-P95 $completionValues), 4) } else { 0 }
    $stdLatency = if ($completionValues.Count -gt 1) { [Math]::Round((Get-StdDev $completionValues), 4) } else { 0 }

    $bpEvents = @($group | Where-Object { $_.ring_backpressure_delta -gt 0 }).Count
    $bpDeltaSum = [int64](($group | Measure-Object ring_backpressure_delta -Sum).Sum)
    $dropDeltaSum = [int64](($group | Measure-Object ring_dropped_delta -Sum).Sum)
    $avgFill = [Math]::Round(($group | Measure-Object fill_level -Average).Average, 3)
    $maxFill = [int64](($group | Measure-Object fill_level -Maximum).Maximum)
    $avgBpDelta = [Math]::Round(($bpDeltaSum / [double]$group.Count), 6)

    $report.Add([PSCustomObject]@{
        FillBin = $bin
        SampleCount = $group.Count
        AvgFill = $avgFill
        MaxFill = $maxFill
        BackpressureEvents = $bpEvents
        BackpressureDeltaSum = $bpDeltaSum
        DroppedDeltaSum = $dropDeltaSum
        AvgBackpressureDeltaPerSample = $avgBpDelta
        CompletionEvents = $completionValues.Count
        AvgLatencyMs = $avgLatency
        P95LatencyMs = $p95Latency
        StdDevLatencyMs = $stdLatency
    })
}

$kneeBin = ($report | Where-Object { $_.FillBin -eq "48-64" })
$overall = [PSCustomObject]@{
    SamplesTotal = $effectiveSamples.Count
    SamplesRawTotal = $samples.Count
    BurnInSamplesExcluded = $BurnInSamples
    CompletionEventsTotal = @($effectiveSamples | Where-Object { $_.completion_event -eq 1 }).Count
    MaxFillOverall = [int64](($effectiveSamples | Measure-Object fill_level -Maximum).Maximum)
    TotalBackpressureEvents = @($effectiveSamples | Where-Object { $_.ring_backpressure_delta -gt 0 }).Count
    TotalBackpressureDelta = [int64](($effectiveSamples | Measure-Object ring_backpressure_delta -Sum).Sum)
    TotalDroppedDelta = [int64](($effectiveSamples | Measure-Object ring_dropped_delta -Sum).Sum)
    SaturationThreshold = $SaturationThreshold
    SaturationSampleCount = @($effectiveSamples | Where-Object { $_.fill_level -ge $SaturationThreshold }).Count
    SaturationBackpressureEvents = @($effectiveSamples | Where-Object { $_.fill_level -ge $SaturationThreshold -and $_.ring_backpressure_delta -gt 0 }).Count
}

$gateSummary = Parse-GateLogSummary $GateLogPath

$analysis = [PSCustomObject]@{
    GeneratedUtc = [DateTime]::UtcNow.ToString("o")
    MetricsCsvPath = $MetricsCsvPath
    GateLogPath = $GateLogPath
    BurnInSamples = $BurnInSamples
    Overall = $overall
    PerBin = $report
    GateSummary = $gateSummary
}

$report | Export-Csv -Path $OutputCsvPath -NoTypeInformation
$analysis | ConvertTo-Json -Depth 6 | Set-Content -Path $OutputJsonPath -Encoding UTF8

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "SOVEREIGN CORRELATION REPORT" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
$report | Format-Table -AutoSize
Write-Host ""
Write-Host "Overall:" -ForegroundColor Yellow
$overall | Format-List

if ($null -ne $gateSummary) {
    Write-Host "Gate Summary:" -ForegroundColor Yellow
    $gateSummary | Format-List
}

Write-Host ""
Write-Host "Report CSV: $OutputCsvPath"
Write-Host "Report JSON: $OutputJsonPath"
