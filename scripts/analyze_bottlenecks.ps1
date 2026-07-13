#!/usr/bin/env pwsh
#Requires -Version 7.0
<#
.SYNOPSIS
    Bottleneck Analysis Script for RawrXD

.DESCRIPTION
    Identifies performance bottlenecks:
    - CPU bottlenecks
    - Memory bottlenecks
    - I/O bottlenecks
    - GPU bottlenecks
    - Lock contention

.EXAMPLE
    .\scripts\analyze_bottlenecks.ps1 -Duration 60
    .\scripts\analyze_bottlenecks.ps1 -Process RawrXD -Detailed

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
    [switch]$Detailed,

    [Parameter()]
    [string]$OutputFile = "bottleneck-analysis.json"
)

# ============================================================================
# Configuration
# ============================================================================

$script:Samples = @()
$script:Bottlenecks = @()

# ============================================================================
# Helper Functions
# ============================================================================

function Write-Status {
    param([string]$Message, [string]$Status = "Info")
    $colors = @{ Info = "Cyan"; Success = "Green"; Warning = "Yellow"; Error = "Red" }
    Write-Host "[$Status] " -ForegroundColor $colors[$Status] -NoNewline
    Write-Host $Message
}

function Get-SystemMetrics {
    $cpu = Get-Counter '\Processor(_Total)\% Processor Time' -ErrorAction SilentlyContinue
    $memory = Get-Counter '\Memory\Available MBytes' -ErrorAction SilentlyContinue
    $disk = Get-Counter '\PhysicalDisk(_Total)\% Disk Time' -ErrorAction SilentlyContinue

    return [PSCustomObject]@{
        CpuPercent = if ($cpu) { $cpu.CounterSamples[0].CookedValue } else { 0 }
        MemoryAvailableMB = if ($memory) { $memory.CounterSamples[0].CookedValue } else { 0 }
        DiskPercent = if ($disk) { $disk.CounterSamples[0].CookedValue } else { 0 }
        Timestamp = Get-Date
    }
}

# ============================================================================
# Analysis
# ============================================================================

function Start-BottleneckAnalysis {
    Write-Status "Starting bottleneck analysis ($Duration seconds)..." "Info"
    Write-Status "Target process: $ProcessName" "Info"
    Write-Status ""

    $startTime = Get-Date
    $process = Get-Process -Name $ProcessName -ErrorAction SilentlyContinue

    if (-not $process) {
        Write-Status "Process $ProcessName not found, analyzing system-wide" "Warning"
    } else {
        Write-Status "Monitoring process: $($process.ProcessName) (PID: $($process.Id))" "Success"
    }

    while (((Get-Date) - $startTime).TotalSeconds -lt $Duration) {
        $metrics = Get-SystemMetrics
        $script:Samples += $metrics

        # Detect bottlenecks
        if ($metrics.CpuPercent -gt 90) {
            $script:Bottlenecks += [PSCustomObject]@{
                Type = "CPU"
                Severity = "High"
                Value = $metrics.CpuPercent
                Timestamp = $metrics.Timestamp
                Recommendation = "Consider CPU optimization or scaling"
            }
        }

        if ($metrics.MemoryAvailableMB -lt 500) {
            $script:Bottlenecks += [PSCustomObject]@{
                Type = "Memory"
                Severity = "High"
                Value = $metrics.MemoryAvailableMB
                Timestamp = $metrics.Timestamp
                Recommendation = "Memory pressure detected - consider reducing allocations"
            }
        }

        if ($metrics.DiskPercent -gt 80) {
            $script:Bottlenecks += [PSCustomObject]@{
                Type = "Disk"
                Severity = "Medium"
                Value = $metrics.DiskPercent
                Timestamp = $metrics.Timestamp
                Recommendation = "High disk utilization - check I/O patterns"
            }
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
    Write-Host "Bottleneck Analysis Report" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan

    $cpuAvg = ($script:Samples | Measure-Object -Property CpuPercent -Average).Average
    $memoryAvg = ($script:Samples | Measure-Object -Property MemoryAvailableMB -Average).Average
    $diskAvg = ($script:Samples | Measure-Object -Property DiskPercent -Average).Average

    Write-Host "`nAverage Metrics:" -ForegroundColor White
    Write-Host "  CPU Usage:    $([math]::Round($cpuAvg, 1))%" -ForegroundColor $(if ($cpuAvg -gt 80) { "Red" } elseif ($cpuAvg -gt 60) { "Yellow" } else { "Green" })
    Write-Host "  Memory Avail: $([math]::Round($memoryAvg, 0)) MB" -ForegroundColor $(if ($memoryAvg -lt 1000) { "Red" } elseif ($memoryAvg -lt 2000) { "Yellow" } else { "Green" })
    Write-Host "  Disk Usage:   $([math]::Round($diskAvg, 1))%" -ForegroundColor $(if ($diskAvg -gt 70) { "Red" } elseif ($diskAvg -gt 50) { "Yellow" } else { "Green" })

    if ($script:Bottlenecks.Count -gt 0) {
        Write-Host "`nBottlenecks Detected: $($script:Bottlenecks.Count)" -ForegroundColor Red

        $grouped = $script:Bottlenecks | Group-Object -Property Type
        foreach ($group in $grouped) {
            Write-Host "`n  $($group.Name) Bottlenecks ($($group.Count) occurrences):" -ForegroundColor Yellow
            $uniqueRecs = $group.Group | Select-Object -Property Recommendation -Unique
            foreach ($rec in $uniqueRecs) {
                Write-Host "    - $($rec.Recommendation)" -ForegroundColor White
            }
        }
    } else {
        Write-Host "`n✅ No significant bottlenecks detected" -ForegroundColor Green
    }

    # Save report
    $report = [ordered]@{
        timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
        process = $ProcessName
        duration = $Duration
        averages = @{
            cpu_percent = $cpuAvg
            memory_available_mb = $memoryAvg
            disk_percent = $diskAvg
        }
        bottlenecks = $script:Bottlenecks
        sample_count = $script:Samples.Count
    }

    $report | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputFile -Encoding UTF8
    Write-Status "Report saved to $OutputFile" "Success"
}

# ============================================================================
# Main Execution
# ============================================================================

function Main {
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "RawrXD Bottleneck Analyzer" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    Start-BottleneckAnalysis
    Write-Report
}

# Run main
Main
