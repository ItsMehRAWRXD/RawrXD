#!/usr/bin/env pwsh
#Requires -Version 7.0
<#
.SYNOPSIS
    Resource Monitor for RawrXD

.DESCRIPTION
    Real-time resource monitoring:
    - CPU usage tracking
    - Memory consumption
    - Disk I/O monitoring
    - Network utilization
    - Alert thresholds

.EXAMPLE
    .\scripts\monitor_resources.ps1 -Duration 300
    .\scripts\monitor_resources.ps1 -AlertThreshold 80

.NOTES
    Part of RawrXD Phase AC: Performance Optimization & Benchmarking
#>

[CmdletBinding()]
param(
    [Parameter()]
    [int]$Duration = 0,  # 0 = indefinite

    [Parameter()]
    [int]$Interval = 5,  # seconds

    [Parameter()]
    [int]$AlertThreshold = 80,

    [Parameter()]
    [string]$LogFile = "resource-monitor.log",

    [Parameter()]
    [switch]$ShowUI
)

# ============================================================================
# Configuration
# ============================================================================

$script:Running = $true
$script:Samples = @()

# ============================================================================
# Helper Functions
# ============================================================================

function Write-Status {
    param([string]$Message, [string]$Status = "Info")
    $colors = @{ Info = "Cyan"; Success = "Green"; Warning = "Yellow"; Error = "Red" }
    Write-Host "[$Status] " -ForegroundColor $colors[$Status] -NoNewline
    Write-Host $Message
}

function Get-ResourceMetrics {
    $cpu = Get-Counter '\Processor(_Total)\% Processor Time' -ErrorAction SilentlyContinue
    $memory = Get-Counter '\Memory\% Committed Bytes In Use' -ErrorAction SilentlyContinue
    $disk = Get-Counter '\PhysicalDisk(_Total)\% Disk Time' -ErrorAction SilentlyContinue

    return [PSCustomObject]@{
        Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
        CpuPercent = [math]::Round($cpu.CounterSamples[0].CookedValue, 2)
        MemoryPercent = [math]::Round($memory.CounterSamples[0].CookedValue, 2)
        DiskPercent = [math]::Round($disk.CounterSamples[0].CookedValue, 2)
    }
}

function Show-ResourceUI {
    param($Metrics)

    Clear-Host
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "RawrXD Resource Monitor" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Timestamp: $($Metrics.Timestamp)" -ForegroundColor Gray
    Write-Host ""

    # CPU
    $cpuColor = if ($Metrics.CpuPercent -gt $AlertThreshold) { "Red" } elseif ($Metrics.CpuPercent -gt 60) { "Yellow" } else { "Green" }
    Write-Host "CPU:    $($Metrics.CpuPercent)%" -ForegroundColor $cpuColor
    Write-Host ("█" * [math]::Min(50, [int]($Metrics.CpuPercent / 2))) -ForegroundColor $cpuColor
    Write-Host ""

    # Memory
    $memColor = if ($Metrics.MemoryPercent -gt $AlertThreshold) { "Red" } elseif ($Metrics.MemoryPercent -gt 60) { "Yellow" } else { "Green" }
    Write-Host "Memory: $($Metrics.MemoryPercent)%" -ForegroundColor $memColor
    Write-Host ("█" * [math]::Min(50, [int]($Metrics.MemoryPercent / 2))) -ForegroundColor $memColor
    Write-Host ""

    # Disk
    $diskColor = if ($Metrics.DiskPercent -gt $AlertThreshold) { "Red" } elseif ($Metrics.DiskPercent -gt 60) { "Yellow" } else { "Green" }
    Write-Host "Disk:   $($Metrics.DiskPercent)%" -ForegroundColor $diskColor
    Write-Host ("█" * [math]::Min(50, [int]($Metrics.DiskPercent / 2))) -ForegroundColor $diskColor
    Write-Host ""

    Write-Host "Press Ctrl+C to stop monitoring" -ForegroundColor DarkGray
}

# ============================================================================
# Monitoring
# ============================================================================

function Start-ResourceMonitoring {
    Write-Status "Starting resource monitoring..." "Info"
    Write-Status "Interval: $Interval seconds" "Info"
    if ($Duration -gt 0) {
        Write-Status "Duration: $Duration seconds" "Info"
    } else {
        Write-Status "Duration: Indefinite (press Ctrl+C to stop)" "Info"
    }
    Write-Status "Alert threshold: $AlertThreshold%" "Info"
    Write-Status ""

    $startTime = Get-Date

    while ($script:Running) {
        $metrics = Get-ResourceMetrics
        $script:Samples += $metrics

        # Log to file
        "$($metrics.Timestamp), $($metrics.CpuPercent), $($metrics.MemoryPercent), $($metrics.DiskPercent)" | Out-File -FilePath $LogFile -Append

        # Check alerts
        if ($metrics.CpuPercent -gt $AlertThreshold) {
            Write-Status "ALERT: CPU usage at $($metrics.CpuPercent)%" "Warning"
        }
        if ($metrics.MemoryPercent -gt $AlertThreshold) {
            Write-Status "ALERT: Memory usage at $($metrics.MemoryPercent)%" "Warning"
        }

        # Display
        if ($ShowUI) {
            Show-ResourceUI -Metrics $metrics
        } else {
            Write-Status "CPU: $($metrics.CpuPercent)% | Memory: $($metrics.MemoryPercent)% | Disk: $($metrics.DiskPercent)%" "Info"
        }

        # Check duration
        if ($Duration -gt 0 -and ((Get-Date) - $startTime).TotalSeconds -ge $Duration) {
            $script:Running = $false
        }

        Start-Sleep -Seconds $Interval
    }
}

# ============================================================================
# Main Execution
# ============================================================================

function Main {
    # Handle Ctrl+C
    $null = Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action {
        $script:Running = $false
    }

    Start-ResourceMonitoring

    Write-Status "Monitoring complete. Samples collected: $($script:Samples.Count)" "Success"
    Write-Status "Log saved to: $LogFile" "Success"
}

# Run main
Main
