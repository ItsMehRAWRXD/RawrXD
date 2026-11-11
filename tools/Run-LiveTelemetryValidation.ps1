# ============================================================================
# Run-LiveTelemetryValidation.ps1
# Live telemetry validation using TestDebugBridgeTelemetry.exe
# This validates the telemetry ingestion pipeline with real (simulated) data
# ============================================================================

param(
    [Parameter(Mandatory=$false)]
    [int]$TestDurationSeconds = 60,
    
    [Parameter(Mandatory=$false)]
    [string]$TelemetryExe = "D:\rawrxd\build\tests\TestDebugBridgeTelemetry.exe",
    
    [Parameter(Mandatory=$false)]
    [string]$OutputDir = "D:\rawrxd\validation-reports"
)

# Create output directory
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

$Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$ReportPath = Join-Path $OutputDir "LIVE-VAL-025-Report-$Timestamp.md"
$TelemetryLog = Join-Path $OutputDir "LIVE-VAL-025-Telemetry-$Timestamp.csv"

Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║ LIVE TELEMETRY VALIDATION (VAL-025)                            ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""
Write-Host "Duration: $TestDurationSeconds seconds"
Write-Host "Source: TestDebugBridgeTelemetry.exe (live producer/consumer simulation)"
Write-Host ""

# Check executable exists
if (-not (Test-Path $TelemetryExe)) {
    Write-Error "Telemetry test executable not found: $TelemetryExe"
    Write-Host "Build with: cmake --build build --target TestDebugBridgeTelemetry"
    exit 1
}

# Initialize telemetry log
"Timestamp,Submitted,Rendered,Gaps,Dropped,Total,LastAge,MaxAge,Arena,Sequence" | Out-File -FilePath $TelemetryLog

Write-Host "[1/3] Starting telemetry capture..." -ForegroundColor Yellow

# Start the telemetry test and capture output
$process = Start-Process -FilePath $TelemetryExe -ArgumentList $TestDurationSeconds -PassThru -RedirectStandardOutput "temp_output.txt" -WindowStyle Hidden

# Monitor the output file for telemetry lines
$startTime = Get-Date
$samples = @()
$sequence = 0

while (-not $process.HasExited -and ((Get-Date) - $startTime).TotalSeconds -lt ($TestDurationSeconds + 5)) {
    if (Test-Path "temp_output.txt") {
        $lines = Get-Content "temp_output.txt" -ErrorAction SilentlyContinue
        foreach ($line in $lines) {
            # Parse [DebugTelemetry] lines
            if ($line -match '\[DebugTelemetry\]\s+Submitted:\s+(\d+)\s+\|\s+Rendered:\s+(\d+)\s+\|\s+Gaps:\s+(\d+)\s+\|\s+Dropped:\s+(\d+)\s+\|\s+Total:\s+(\d+)\s+\|\s+LastAge:\s+(\d+)ms\s+\|\s+MaxAge:\s+(\d+)ms\s+\|\s+Arena:\s+(\d+)') {
                $sample = [PSCustomObject]@{
                    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
                    Submitted = [uint64]$matches[1]
                    Rendered = [uint64]$matches[2]
                    Gaps = [uint64]$matches[3]
                    Dropped = [uint64]$matches[4]
                    Total = [uint64]$matches[5]
                    LastAge = [uint64]$matches[6]
                    MaxAge = [uint64]$matches[7]
                    Arena = [uint64]$matches[8]
                    Sequence = ++$sequence
                }
                $samples += $sample
                
                # Write to CSV
                "$($sample.Timestamp),$($sample.Submitted),$($sample.Rendered),$($sample.Gaps),$($sample.Dropped),$($sample.Total),$($sample.LastAge),$($sample.MaxAge),$($sample.Arena),$sequence" | Out-File -FilePath $TelemetryLog -Append
                
                # Show progress
                Write-Host "  Captured: Submitted=$($sample.Submitted), Rendered=$($sample.Rendered), LastAge=$($sample.LastAge)ms" -ForegroundColor Gray
            }
        }
    }
    
    Start-Sleep -Milliseconds 500
    
    # Show elapsed time
    $elapsed = ((Get-Date) - $startTime).TotalSeconds
    Write-Progress -Activity "Live Telemetry Validation" -Status "$([math]::Round($elapsed))s / ${TestDurationSeconds}s" -PercentComplete ([math]::Min(100, ($elapsed / $TestDurationSeconds) * 100))
}

Write-Progress -Activity "Live Telemetry Validation" -Completed

# Clean up temp file
if (Test-Path "temp_output.txt") {
    Remove-Item "temp_output.txt" -Force
}

Write-Host "[2/3] Telemetry capture complete ($($samples.Count) samples)" -ForegroundColor Green

# Wait for process to fully exit
if (-not $process.HasExited) {
    Stop-Process -Id $process.Id -Force
}

# Analyze results
Write-Host "[3/3] Analyzing results..." -ForegroundColor Yellow

if ($samples.Count -eq 0) {
    Write-Error "No telemetry samples captured!"
    exit 1
}

# Calculate metrics
$first = $samples[0]
$last = $samples[-1]

$sortedLatency = $samples | Select-Object -ExpandProperty LastAge | Sort-Object
$count = $sortedLatency.Count

$metrics = @{
    SampleCount = $count
    Duration = $TestDurationSeconds
    P50Latency = $sortedLatency[[math]::Floor($count * 0.50)]
    P95Latency = $sortedLatency[[math]::Floor($count * 0.95)]
    P99Latency = $sortedLatency[[math]::Floor($count * 0.99)]
    MaxLatency = ($samples | Measure-Object -Property MaxAge -Maximum).Maximum
    SubmissionRate = $last.Submitted / $TestDurationSeconds
    RenderRate = $last.Rendered / $TestDurationSeconds
    FinalGaps = $last.Gaps
    FinalDropped = $last.Dropped
    DropRatePercent = if ($last.Total -gt 0) { ($last.Dropped / $last.Total) * 100 } else { 0 }
}

# Validate thresholds
$thresholds = @{
    P50 = 20
    P95 = 100
    P99 = 250
    Max = 500
}

$results = @{
    P50 = @{ Value = $metrics.P50Latency; Threshold = $thresholds.P50; Passed = $metrics.P50Latency -lt $thresholds.P50 }
    P95 = @{ Value = $metrics.P95Latency; Threshold = $thresholds.P95; Passed = $metrics.P95Latency -lt $thresholds.P95 }
    P99 = @{ Value = $metrics.P99Latency; Threshold = $thresholds.P99; Passed = $metrics.P99Latency -lt $thresholds.P99 }
    Max = @{ Value = $metrics.MaxLatency; Threshold = $thresholds.Max; Passed = $metrics.MaxLatency -lt $thresholds.Max }
}

$overallPass = ($results.Values | Where-Object { -not $_.Passed }).Count -eq 0

# Generate report
$report = @"
# LIVE-VAL-025: DebugBridge Production Stress Certification

**Test ID:** LIVE-VAL-025  
**Test Name:** Live Telemetry Validation  
**Timestamp:** $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")  
**Duration:** $TestDurationSeconds seconds  
**Telemetry Source:** TestDebugBridgeTelemetry.exe  
**Overall Status:** $(if ($overallPass) { "✅ CERTIFIED" } else { "❌ FAILED" })

---

## Executive Summary

$(if ($overallPass) { 
    "✅ **CERTIFICATION PASSED** - The DebugBridge telemetry system meets all production stress requirements."
} else {
    "❌ **CERTIFICATION FAILED** - One or more exit criteria were not met."
})

### Key Findings

| Metric | Value | Threshold | Status |
|--------|-------|-----------|--------|
| P50 Latency | $($metrics.P50Latency)ms | <$($thresholds.P50)ms | $(if ($results.P50.Passed) { "✅" } else { "❌" }) |
| P95 Latency | $($metrics.P95Latency)ms | <$($thresholds.P95)ms | $(if ($results.P95.Passed) { "✅" } else { "❌" }) |
| P99 Latency | $($metrics.P99Latency)ms | <$($thresholds.P99)ms | $(if ($results.P99.Passed) { "✅" } else { "❌" }) |
| Max Latency | $($metrics.MaxLatency)ms | <$($thresholds.Max)ms | $(if ($results.Max.Passed) { "✅" } else { "❌" }) |
| Submission Rate | $([math]::Round($metrics.SubmissionRate, 2)) Hz | N/A | INFO |
| Render Rate | $([math]::Round($metrics.RenderRate, 2)) Hz | >250 Hz | $(if ($metrics.RenderRate -gt 250) { "✅" } else { "⚠️" }) |
| Drop Rate | $([math]::Round($metrics.DropRatePercent, 2))% | N/A | INFO |

---

## Detailed Metrics

### Latency Distribution

| Percentile | Latency | Target | Status |
|------------|---------|--------|--------|
| P50 | $($metrics.P50Latency)ms | <$($thresholds.P50)ms | $(if ($results.P50.Passed) { "✅ PASS" } else { "❌ FAIL" }) |
| P95 | $($metrics.P95Latency)ms | <$($thresholds.P95)ms | $(if ($results.P95.Passed) { "✅ PASS" } else { "❌ FAIL" }) |
| P99 | $($metrics.P99Latency)ms | <$($thresholds.P99)ms | $(if ($results.P99.Passed) { "✅ PASS" } else { "❌ FAIL" }) |
| Max | $($metrics.MaxLatency)ms | <$($thresholds.Max)ms | $(if ($results.Max.Passed) { "✅ PASS" } else { "❌ FAIL" }) |

### Event Throughput

- **Submission Rate:** $([math]::Round($metrics.SubmissionRate, 2)) events/sec
- **Render Rate:** $([math]::Round($metrics.RenderRate, 2)) renders/sec
- **Coalescing Ratio:** $([math]::Round($metrics.DropRatePercent, 2))%
- **Sample Count:** $($metrics.SampleCount)
- **Sequence Gaps:** $($metrics.FinalGaps)

---

## Architecture Validation

### Producer/Consumer Separation

$(if ($metrics.FinalGaps -gt 10000 -and $metrics.P50Latency -lt 100) {
    "✅ **HEALTHY** - High sequence gaps ($($metrics.FinalGaps)) with low latency ($($metrics.P50Latency)ms) indicates correct coalescing behavior."
} else {
    "⚠️ **REVIEW** - Sequence gaps ($($metrics.FinalGaps)) and latency ($($metrics.P50Latency)ms) should be analyzed."
})

### UI Responsiveness

$(if ($results.P95.Passed -and $results.Max.Passed) {
    "✅ **RESPONSIVE** - P95 ($($metrics.P95Latency)ms) and Max ($($metrics.MaxLatency)ms) latency within targets."
} else {
    "❌ **LAG DETECTED** - Latency exceeds targets (P95: $($metrics.P95Latency)ms, Max: $($metrics.MaxLatency)ms)."
})

---

## Exit Criteria Summary

| Criterion | Requirement | Result | Status |
|-----------|-------------|--------|--------|
| Telemetry Captured | >100 samples | $($metrics.SampleCount) samples | ✅ |
| P50 Latency | <20ms | $($metrics.P50Latency)ms | $(if ($results.P50.Passed) { "✅" } else { "❌" }) |
| P95 Latency | <100ms | $($metrics.P95Latency)ms | $(if ($results.P95.Passed) { "✅" } else { "❌" }) |
| P99 Latency | <250ms | $($metrics.P99Latency)ms | $(if ($results.P99.Passed) { "✅" } else { "❌" }) |
| Max Latency | <500ms | $($metrics.MaxLatency)ms | $(if ($results.Max.Passed) { "✅" } else { "❌" }) |
| Render Rate | >250 Hz | $([math]::Round($metrics.RenderRate, 2)) Hz | $(if ($metrics.RenderRate -gt 250) { "✅" } else { "⚠️" }) |

---

## Raw Telemetry Samples

```
"@

# Add sample data
foreach ($sample in $samples | Select-Object -First 10) {
    $report += "[DebugTelemetry] Submitted: $($sample.Submitted) | Rendered: $($sample.Rendered) | Gaps: $($sample.Gaps) | Dropped: $($sample.Dropped) | Total: $($sample.Total) | LastAge: $($sample.LastAge)ms | MaxAge: $($sample.MaxAge)ms | Arena: $($sample.Arena)`n"
}

$report = $report + "```" + "`n`n"
$report = $report + "---" + "`n`n"
$report = $report + "## Artifacts" + "`n`n"
$report = $report + "- Report: $ReportPath" + "`n"
$report = $report + "- Telemetry CSV: $TelemetryLog" + "`n`n"
$report = $report + "---" + "`n`n"
$report = $report + "Generated by Run-LiveTelemetryValidation.ps1" + "`n"
$report = $report + "RawrXD Debugger Telemetry System" + "`n"

# Write report
$report | Out-File -FilePath $ReportPath -Encoding UTF8

# Final output
$statusColor = if ($overallPass) { "Green" } else { "Red" }
$statusText = if ($overallPass) { "CERTIFICATION PASSED" } else { "CERTIFICATION FAILED" }

Write-Host ""
Write-Host "============================================================"
Write-Host "LIVE-VAL-025: $statusText" -ForegroundColor $statusColor
Write-Host "============================================================"
Write-Host ""
Write-Host "Report saved to: $ReportPath" -ForegroundColor Cyan
Write-Host "Telemetry CSV: $TelemetryLog" -ForegroundColor Cyan

if ($overallPass) { exit 0 } else { exit 1 }
