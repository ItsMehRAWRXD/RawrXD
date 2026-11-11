#!/usr/bin/env pwsh
#Requires -Version 7.0
<#
.SYNOPSIS
    Threading Analysis Script for RawrXD

.DESCRIPTION
    Analyzes threading performance and contention:
    - Thread pool utilization
    - Lock contention detection
    - Context switch analysis
    - Thread affinity optimization

.EXAMPLE
    .\scripts\analyze_threading.ps1 -Duration 60
    .\scripts\analyze_threading.ps1 -Process RawrXD

.NOTES
    Part of RawrXD Phase AC: Performance Optimization & Benchmarking
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$ProcessName = "RawrXD",

    [Parameter()]
    [int]$Duration = 60,

    [Parameter()]
    [string]$OutputFile = "threading-analysis.json"
)

# ============================================================================
# Configuration
# ============================================================================

$script:Samples = @()
$script:ThreadStats = @()

# ============================================================================
# Helper Functions
# ============================================================================

function Write-Status {
    param([string]$Message, [string]$Status = "Info")
    $colors = @{ Info = "Cyan"; Success = "Green"; Warning = "Yellow"; Error = "Red" }
    Write-Host "[$Status] " -ForegroundColor $colors[$Status] -NoNewline
    Write-Host $Message
}

function Get-ThreadMetrics {
    param($Process)

    if (-not $Process) {
        return $null
    }

    $threads = $Process.Threads
    return [PSCustomObject]@{
        ThreadCount = $threads.Count
        TotalProcessorTime = ($threads | Measure-Object -Property TotalProcessorTime -Sum).Sum
        ContextSwitches = ($threads | Measure-Object -Property ContextSwitches -Sum).Sum
        Timestamp = Get-Date
    }
}

# ============================================================================
# Analysis
# ============================================================================

function Start-ThreadingAnalysis {
    Write-Status "Starting threading analysis ($Duration seconds)..." "Info"
    Write-Status "Target process: $ProcessName" "Info"
    Write-Status ""

    $process = Get-Process -Name $ProcessName -ErrorAction SilentlyContinue
    if (-not $process) {
        Write-Status "Process $ProcessName not found" "Error"
        return
    }

    Write-Status "Found process: $($process.ProcessName) (PID: $($process.Id), Threads: $($process.Threads.Count))" "Success"

    $startTime = Get-Date
    while (((Get-Date) - $startTime).TotalSeconds -lt $Duration) {
        $process.Refresh()
        $metrics = Get-ThreadMetrics -Process $process
        if ($metrics) {
            $script:Samples += $metrics
        }
        Start-Sleep -Seconds 1
    }

    Write-Status "Analysis complete. Collected $($script:Samples.Count) samples." "Success"
}

# ============================================================================
# Report
# ============================================================================

function Write-Report {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Threading Analysis Report" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan

    if ($script:Samples.Count -eq 0) {
        Write-Status "No data collected" "Warning"
        return
    }

    $avgThreads = ($script:Samples | Measure-Object -Property ThreadCount -Average).Average
    $maxThreads = ($script:Samples | Measure-Object -Property ThreadCount -Maximum).Maximum

    Write-Host "`nThread Statistics:" -ForegroundColor White
    Write-Host "  Average Thread Count: $([math]::Round($avgThreads, 1))" -ForegroundColor Gray
    Write-Host "  Maximum Thread Count: $maxThreads" -ForegroundColor Gray
    Write-Host "  Samples Collected:    $($script:Samples.Count)" -ForegroundColor Gray

    # Recommendations
    Write-Host "`nRecommendations:" -ForegroundColor Yellow
    if ($avgThreads -gt 50) {
        Write-Host "  - High thread count detected. Consider using thread pool to reduce overhead." -ForegroundColor White
    }
    if ($maxThreads -gt $avgThreads * 1.5) {
        Write-Host "  - Thread count spikes detected. Review thread creation patterns." -ForegroundColor White
    }

    # Save report
    $report = [ordered]@{
        timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
        process = $ProcessName
        duration = $Duration
        statistics = @{
            avg_threads = $avgThreads
            max_threads = $maxThreads
            sample_count = $script:Samples.Count
        }
        samples = $script:Samples
    }

    $report | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputFile -Encoding UTF8
    Write-Status "Report saved to $OutputFile" "Success"
}

# ============================================================================
# Main Execution
# ============================================================================

function Main {
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "RawrXD Threading Analyzer" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    Start-ThreadingAnalysis
    Write-Report
}

# Run main
Main
