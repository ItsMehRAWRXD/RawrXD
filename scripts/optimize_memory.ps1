#!/usr/bin/env pwsh
#Requires -Version 7.0
<#
.SYNOPSIS
    Memory Optimization Script for RawrXD

.DESCRIPTION
    Analyzes and optimizes memory usage:
    - Memory leak detection
    - Heap analysis
    - Memory pool tuning
    - Cache optimization recommendations

.EXAMPLE
    .\scripts\optimize_memory.ps1 -Analyze
    .\scripts\optimize_memory.ps1 -Tune -Config config.json

.NOTES
    Part of RawrXD Phase AC: Performance Optimization & Benchmarking
#>

[CmdletBinding()]
param(
    [Parameter()]
    [switch]$Analyze,

    [Parameter()]
    [switch]$Tune,

    [Parameter()]
    [string]$ConfigPath = "config/memory.json",

    [Parameter()]
    [string]$OutputFile = "memory-optimization.json",

    [Parameter()]
    [int]$SampleDuration = 60
)

# ============================================================================
# Configuration
# ============================================================================

$Config = @{
    MaxWorkingSetMB = 4096
    TargetWorkingSetMB = 2048
    PoolBlockSize = 64KB
    CacheLineSize = 64
}

$script:AnalysisResults = @{
    PeakWorkingSet = 0
    AverageWorkingSet = 0
    LeakDetected = $false
    Recommendations = @()
}

# ============================================================================
# Helper Functions
# ============================================================================

function Write-Status {
    param([string]$Message, [string]$Status = "Info")
    $colors = @{ Info = "Cyan"; Success = "Green"; Warning = "Yellow"; Error = "Red" }
    Write-Host "[$Status] " -ForegroundColor $colors[$Status] -NoNewline
    Write-Host $Message
}

function Get-MemoryStats {
    $proc = Get-Process -Id $PID -ErrorAction SilentlyContinue
    if ($proc) {
        return [PSCustomObject]@{
            WorkingSetMB = [math]::Round($proc.WorkingSet64 / 1MB, 2)
            PrivateMB = [math]::Round($proc.PrivateMemorySize64 / 1MB, 2)
            VirtualMB = [math]::Round($proc.VirtualMemorySize64 / 1MB, 2)
            PagedMB = [math]::Round($proc.PagedMemorySize64 / 1MB, 2)
            Timestamp = Get-Date
        }
    }
    return $null
}

# ============================================================================
# Analysis
# ============================================================================

function Start-MemoryAnalysis {
    Write-Status "Starting memory analysis ($SampleDuration seconds)..." "Info"

    $samples = @()
    $startTime = Get-Date

    while (((Get-Date) - $startTime).TotalSeconds -lt $SampleDuration) {
        $stats = Get-MemoryStats
        if ($stats) {
            $samples += $stats
        }
        Start-Sleep -Seconds 1
    }

    if ($samples.Count -eq 0) {
        Write-Status "No samples collected" "Error"
        return
    }

    $workingSets = $samples | Select-Object -ExpandProperty WorkingSetMB
    $script:AnalysisResults.PeakWorkingSet = ($workingSets | Measure-Object -Maximum).Maximum
    $script:AnalysisResults.AverageWorkingSet = ($workingSets | Measure-Object -Average).Average

    # Detect potential memory leak
    $firstHalf = $workingSets[0..[int]($workingSets.Count / 2)] | Measure-Object -Average
    $secondHalf = $workingSets[[int]($workingSets.Count / 2)..($workingSets.Count - 1)] | Measure-Object -Average

    if ($secondHalf.Average -gt $firstHalf.Average * 1.2) {
        $script:AnalysisResults.LeakDetected = $true
        $script:AnalysisResults.Recommendations += "Potential memory leak detected: Working set increased by $([math]::Round((($secondHalf.Average - $firstHalf.Average) / $firstHalf.Average) * 100, 1))%"
    }

    # Generate recommendations
    if ($script:AnalysisResults.PeakWorkingSet -gt $Config.MaxWorkingSetMB) {
        $script:AnalysisResults.Recommendations += "Peak working set ($($script:AnalysisResults.PeakWorkingSet) MB) exceeds maximum threshold ($($Config.MaxWorkingSetMB) MB)"
        $script:AnalysisResults.Recommendations += "Consider enabling memory-mapped file I/O for model weights"
        $script:AnalysisResults.Recommendations += "Reduce batch size or context length"
    }

    if ($script:AnalysisResults.AverageWorkingSet -gt $Config.TargetWorkingSetMB) {
        $script:AnalysisResults.Recommendations += "Average working set ($($script:AnalysisResults.AverageWorkingSet) MB) exceeds target ($($Config.TargetWorkingSetMB) MB)"
    }

    $script:AnalysisResults.Samples = $samples
}

# ============================================================================
# Tuning
# ============================================================================

function Invoke-MemoryTuning {
    Write-Status "Applying memory optimizations..." "Info"

    $optimizations = @()

    # Calculate optimal pool sizes
    $availableMemory = (Get-CimInstance -ClassName Win32_ComputerSystem).TotalPhysicalMemory / 1MB
    $recommendedPoolSize = [math]::Min(512, [math]::Floor($availableMemory / 8))

    $optimizations += [PSCustomObject]@{
        Setting = "memory_pool_size"
        Current = "Default"
        Recommended = "$recommendedPoolSize MB"
        Reason = "Based on available system memory"
    }

    $optimizations += [PSCustomObject]@{
        Setting = "cache_alignment"
        Current = "Default"
        Recommended = "$($Config.CacheLineSize) bytes"
        Reason = "CPU cache line optimization"
    }

    $optimizations += [PSCustomObject]@{
        Setting = "mmap_weights"
        Current = "Off"
        Recommended = "On"
        Reason = "Reduce resident memory for large models"
    }

    Write-Host "`nRecommended Optimizations:" -ForegroundColor Cyan
    foreach ($opt in $optimizations) {
        Write-Host "  $($opt.Setting):" -ForegroundColor White
        Write-Host "    Current:     $($opt.Current)" -ForegroundColor Gray
        Write-Host "    Recommended: $($opt.Recommended)" -ForegroundColor Green
        Write-Host "    Reason:      $($opt.Reason)" -ForegroundColor DarkGray
    }

    return $optimizations
}

# ============================================================================
# Report
# ============================================================================

function Write-Report {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Memory Optimization Report" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan

    Write-Host "`nAnalysis Results:" -ForegroundColor White
    Write-Host "  Peak Working Set:    $($script:AnalysisResults.PeakWorkingSet) MB" -ForegroundColor Gray
    Write-Host "  Average Working Set: $($script:AnalysisResults.AverageWorkingSet) MB" -ForegroundColor Gray
    Write-Host "  Leak Detected:       $($script:AnalysisResults.LeakDetected)" -ForegroundColor $(if ($script:AnalysisResults.LeakDetected) { "Red" } else { "Green" })

    if ($script:AnalysisResults.Recommendations.Count -gt 0) {
        Write-Host "`nRecommendations:" -ForegroundColor Yellow
        foreach ($rec in $script:AnalysisResults.Recommendations) {
            Write-Host "  - $rec" -ForegroundColor White
        }
    }

    # Save report
    $script:AnalysisResults | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputFile -Encoding UTF8
    Write-Status "Report saved to $OutputFile" "Success"
}

# ============================================================================
# Main Execution
# ============================================================================

function Main {
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "RawrXD Memory Optimizer" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    if ($Analyze) {
        Start-MemoryAnalysis
    }

    if ($Tune) {
        Invoke-MemoryTuning
    }

    if (-not $Analyze -and -not $Tune) {
        Write-Status "No action specified. Use -Analyze or -Tune" "Warning"
        return
    }

    Write-Report
}

# Run main
Main
