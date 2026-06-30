# =============================================================================
# Telemetry Log Analyzer for TC15_001
# Phase 15: IDE Integration Diagnostics
# =============================================================================

param(
    [string]$TelemetryPath = "D:\RawrXD\logs\telemetry.log",
    [string]$OutputPath = "D:\RawrXD\logs\tc15_001_analysis.md"
)

Write-Host "=== TC15_001 Telemetry Analyzer ===" -ForegroundColor Green

if (!(Test-Path $TelemetryPath)) {
    Write-Host "Error: Telemetry log not found at $TelemetryPath" -ForegroundColor Red
    exit 1
}

# Read and parse telemetry
$entries = Get-Content $TelemetryPath | ForEach-Object {
    try {
        $_ | ConvertFrom-Json
    } catch {
        $null
    }
} | Where-Object { $_ -ne $null }

if ($entries.Count -eq 0) {
    Write-Host "No valid telemetry entries found." -ForegroundColor Yellow
    exit 0
}

Write-Host "Analyzing $($entries.Count) telemetry entries..." -ForegroundColor Cyan

# Analysis
$analysis = @{
    Summary = @{}
    Latency = @{}
    Throughput = @{}
    Errors = @()
}

# Event counts
$eventCounts = $entries | Group-Object -Property event | Select-Object Name, Count
$analysis.Summary.EventCounts = $eventCounts

# First token latency analysis
$firstTokens = $entries | Where-Object { $_.event -eq "FIRST_TOKEN" }
if ($firstTokens) {
    $latencies = $firstTokens | ForEach-Object { $_.data.latency_ms }
    $analysis.Latency.FirstToken = @{
        Count = $latencies.Count
        Min = ($latencies | Measure-Object -Minimum).Minimum
        Max = ($latencies | Measure-Object -Maximum).Maximum
        Average = ($latencies | Measure-Object -Average).Average
        P95 = ($latencies | Sort-Object)[[math]::Floor($latencies.Count * 0.95)]
        P99 = ($latencies | Sort-Object)[[math]::Floor($latencies.Count * 0.99)]
    }
}

# Completion analysis
$completions = $entries | Where-Object { $_.event -eq "COMPLETION_COMPLETE" }
if ($completions) {
    $totalTimes = $completions | ForEach-Object { $_.data.total_time_ms }
    $tokenCounts = $completions | ForEach-Object { $_.data.total_tokens }
    
    $analysis.Throughput.Completion = @{
        Count = $completions.Count
        AvgTotalTime = ($totalTimes | Measure-Object -Average).Average
        AvgTokenCount = ($tokenCounts | Measure-Object -Average).Average
        TokensPerSecond = ($tokenCounts | Measure-Object -Average).Average / (($totalTimes | Measure-Object -Average).Average / 1000)
    }
}

# Error analysis
$errors = $entries | Where-Object { $_.event -like "*ERROR*" -or $_.event -like "*FAIL*" }
$analysis.Errors = $errors

# Generate report
$report = @"
# TC15_001 Telemetry Analysis Report

**Generated:** $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
**Source:** $TelemetryPath
**Total Entries:** $($entries.Count)

## Event Summary

| Event | Count |
|-------|-------|
$(foreach ($e in $eventCounts) { "| $($e.Name) | $($e.Count) |`n" })

## Latency Analysis

### First Token Latency
$(if ($analysis.Latency.FirstToken) {
    "- **Count:** $($analysis.Latency.FirstToken.Count)`n"
    "- **Min:** $([math]::Round($analysis.Latency.FirstToken.Min, 2)) ms`n"
    "- **Max:** $([math]::Round($analysis.Latency.FirstToken.Max, 2)) ms`n"
    "- **Average:** $([math]::Round($analysis.Latency.FirstToken.Average, 2)) ms`n"
    "- **P95:** $([math]::Round($analysis.Latency.FirstToken.P95, 2)) ms`n"
    "- **P99:** $([math]::Round($analysis.Latency.FirstToken.P99, 2)) ms`n"
    "`n"
    $target = 200
    $avg = $analysis.Latency.FirstToken.Average
    if ($avg -le $target) {
        "✅ **PASS:** Average latency ($([math]::Round($avg, 2)) ms) is within target ($target ms)`n"
    } else {
        "❌ **FAIL:** Average latency ($([math]::Round($avg, 2)) ms) exceeds target ($target ms)`n"
    }
} else {
    "No FIRST_TOKEN events found.`n"
})

## Throughput Analysis

$(if ($analysis.Throughput.Completion) {
    "- **Total Completions:** $($analysis.Throughput.Completion.Count)`n"
    "- **Average Completion Time:** $([math]::Round($analysis.Throughput.Completion.AvgTotalTime, 2)) ms`n"
    "- **Average Token Count:** $([math]::Round($analysis.Throughput.Completion.AvgTokenCount, 2))`n"
    "- **Tokens/Second:** $([math]::Round($analysis.Throughput.Completion.TokensPerSecond, 2))`n"
} else {
    "No COMPLETION_COMPLETE events found.`n"
})

## Error Analysis

$(if ($analysis.Errors.Count -gt 0) {
    "**$($analysis.Errors.Count) Errors Detected:**`n`n"
    foreach ($err in $analysis.Errors) {
        "- $($err.timestamp): $($err.event)`n"
    }
} else {
    "✅ No errors detected.`n"
})

## Recommendations

$(if ($analysis.Latency.FirstToken -and $analysis.Latency.FirstToken.Average -gt 200) {
    "1. **High Latency Detected:** Consider enabling MMAP prefetching or reducing model size.`n"
})
$(if ($analysis.Errors.Count -gt 0) {
    "2. **Errors Present:** Review error logs and ensure IPC bridge is properly configured.`n"
})
$(if ($analysis.Throughput.Completion -and $analysis.Throughput.Completion.TokensPerSecond -lt 10) {
    "3. **Low Throughput:** Consider optimizing KV cache or enabling AVX-512 kernels.`n"
})

---
*Analysis generated by TC15_001 Telemetry Analyzer*
"@

# Save report
$report | Set-Content $OutputPath

Write-Host "`nAnalysis complete!" -ForegroundColor Green
Write-Host "Report saved to: $OutputPath" -ForegroundColor Cyan

# Display summary
Write-Host "`n=== Quick Summary ===" -ForegroundColor Yellow
if ($analysis.Latency.FirstToken) {
    Write-Host "First Token Latency: $([math]::Round($analysis.Latency.FirstToken.Average, 2)) ms (avg)" -ForegroundColor $(if ($analysis.Latency.FirstToken.Average -le 200) { "Green" } else { "Red" })
}
if ($analysis.Throughput.Completion) {
    Write-Host "Throughput: $([math]::Round($analysis.Throughput.Completion.TokensPerSecond, 2)) tokens/sec" -ForegroundColor Cyan
}
Write-Host "Errors: $($analysis.Errors.Count)" -ForegroundColor $(if ($analysis.Errors.Count -eq 0) { "Green" } else { "Red" })
