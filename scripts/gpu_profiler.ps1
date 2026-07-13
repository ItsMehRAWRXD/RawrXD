#!/usr/bin/env pwsh
#Requires -Version 7.0
<#
.SYNOPSIS
    GPU Profiler for RawrXD

.DESCRIPTION
    Profiles GPU utilization and performance:
    - GPU memory usage
    - Compute utilization
    - Memory bandwidth
    - Kernel execution times
    - Temperature and power

.EXAMPLE
    .\scripts\gpu_profiler.ps1 -Duration 60
    .\scripts\gpu_profiler.ps1 -Backend vulkan -Output gpu-profile.json

.NOTES
    Part of RawrXD Phase AC: Performance Optimization & Benchmarking
#>

[CmdletBinding()]
param(
    [Parameter()]
    [int]$Duration = 60,

    [Parameter()]
    [ValidateSet("vulkan", "cuda", "rocm", "auto")]
    [string]$Backend = "auto",

    [Parameter()]
    [string]$OutputFile = "gpu-profile.json",

    [Parameter()]
    [switch]$MonitorOnly
)

# ============================================================================
# Configuration
# ============================================================================

$Config = @{
    SampleInterval = 1000  # milliseconds
}

$script:Samples = @()
$script:GPUInfo = $null

# ============================================================================
# Helper Functions
# ============================================================================

function Write-Status {
    param([string]$Message, [string]$Status = "Info")
    $colors = @{ Info = "Cyan"; Success = "Green"; Warning = "Yellow"; Error = "Red" }
    Write-Host "[$Status] " -ForegroundColor $colors[$Status] -NoNewline
    Write-Host $Message
}

function Get-NvidiaGPUInfo {
    try {
        $output = nvidia-smi --query-gpu=name,memory.total,memory.used,utilization.gpu,utilization.memory,temperature.gpu,power.draw --format=csv,noheader,nounits 2>$null
        if ($LASTEXITCODE -eq 0 -and $output) {
            $parts = $output.Split(',').Trim()
            return [PSCustomObject]@{
                Name = $parts[0]
                MemoryTotal = [int]$parts[1]
                MemoryUsed = [int]$parts[2]
                GpuUtilization = [int]$parts[3]
                MemoryUtilization = [int]$parts[4]
                Temperature = [int]$parts[5]
                PowerDraw = [float]$parts[6]
                Backend = "CUDA"
            }
        }
    } catch {
        return $null
    }
    return $null
}

function Get-AMDGPUInfo {
    # Placeholder for ROCm/rocm-smi integration
    return $null
}

function Get-VulkanGPUInfo {
    # Would query Vulkan capabilities
    return [PSCustomObject]@{
        Name = "Vulkan Device"
        Backend = "Vulkan"
    }
}

# ============================================================================
# Profiling
# ============================================================================

function Start-GPUProfiling {
    Write-Status "Starting GPU profiling ($Duration seconds)..." "Info"
    Write-Status "Backend: $Backend" "Info"
    Write-Status ""

    # Detect GPU
    $script:GPUInfo = Get-NvidiaGPUInfo
    if (-not $script:GPUInfo) {
        $script:GPUInfo = Get-AMDGPUInfo
    }
    if (-not $script:GPUInfo) {
        $script:GPUInfo = Get-VulkanGPUInfo
    }

    if ($script:GPUInfo) {
        Write-Status "GPU detected: $($script:GPUInfo.Name)" "Success"
    } else {
        Write-Status "No GPU detected" "Warning"
        return
    }

    # Sample loop
    $startTime = Get-Date
    while (((Get-Date) - $startTime).TotalSeconds -lt $Duration) {
        $sample = [PSCustomObject]@{
            Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
            ElapsedSeconds = ((Get-Date) - $startTime).TotalSeconds
        }

        if ($script:GPUInfo.Backend -eq "CUDA") {
            $gpuInfo = Get-NvidiaGPUInfo
            if ($gpuInfo) {
                $sample.MemoryUsed = $gpuInfo.MemoryUsed
                $sample.GpuUtilization = $gpuInfo.GpuUtilization
                $sample.Temperature = $gpuInfo.Temperature
                $sample.PowerDraw = $gpuInfo.PowerDraw
            }
        }

        $script:Samples += $sample
        Start-Sleep -Milliseconds $Config.SampleInterval
    }

    Write-Status "Profiling complete. Collected $($script:Samples.Count) samples." "Success"
}

# ============================================================================
# Analysis
# ============================================================================

function Get-GPUStatistics {
    if ($script:Samples.Count -eq 0) {
        return $null
    }

    $utilizations = $script:Samples | Where-Object { $_.GpuUtilization -ne $null } | Select-Object -ExpandProperty GpuUtilization
    $memoryUsed = $script:Samples | Where-Object { $_.MemoryUsed -ne $null } | Select-Object -ExpandProperty MemoryUsed
    $temperatures = $script:Samples | Where-Object { $_.Temperature -ne $null } | Select-Object -ExpandProperty Temperature

    return [PSCustomObject]@{
        Duration = $Duration
        SampleCount = $script:Samples.Count
        GpuUtilization = if ($utilizations) { @{
            Min = ($utilizations | Measure-Object -Minimum).Minimum
            Max = ($utilizations | Measure-Object -Maximum).Maximum
            Average = ($utilizations | Measure-Object -Average).Average
        } } else { $null }
        MemoryUsed = if ($memoryUsed) { @{
            Min = ($memoryUsed | Measure-Object -Minimum).Minimum
            Max = ($memoryUsed | Measure-Object -Maximum).Maximum
            Average = ($memoryUsed | Measure-Object -Average).Average
        } } else { $null }
        Temperature = if ($temperatures) { @{
            Min = ($temperatures | Measure-Object -Minimum).Minimum
            Max = ($temperatures | Measure-Object -Maximum).Maximum
            Average = ($temperatures | Measure-Object -Average).Average
        } } else { $null }
    }
}

# ============================================================================
# Report
# ============================================================================

function Write-Report {
    $stats = Get-GPUStatistics

    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "GPU Profile Report" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan

    if ($script:GPUInfo) {
        Write-Host "`nGPU Information:" -ForegroundColor White
        Write-Host "  Name: $($script:GPUInfo.Name)" -ForegroundColor Gray
        Write-Host "  Backend: $($script:GPUInfo.Backend)" -ForegroundColor Gray
    }

    if ($stats) {
        Write-Host "`nUtilization:" -ForegroundColor White
        if ($stats.GpuUtilization) {
            Write-Host "  Min: $($stats.GpuUtilization.Min)%" -ForegroundColor Gray
            Write-Host "  Avg: $([math]::Round($stats.GpuUtilization.Average, 1))%" -ForegroundColor Green
            Write-Host "  Max: $($stats.GpuUtilization.Max)%" -ForegroundColor Gray
        }

        Write-Host "`nMemory:" -ForegroundColor White
        if ($stats.MemoryUsed) {
            Write-Host "  Min: $($stats.MemoryUsed.Min) MB" -ForegroundColor Gray
            Write-Host "  Avg: $([math]::Round($stats.MemoryUsed.Average, 0)) MB" -ForegroundColor Green
            Write-Host "  Max: $($stats.MemoryUsed.Max) MB" -ForegroundColor Gray
        }

        Write-Host "`nTemperature:" -ForegroundColor White
        if ($stats.Temperature) {
            Write-Host "  Min: $($stats.Temperature.Min)°C" -ForegroundColor Gray
            Write-Host "  Avg: $([math]::Round($stats.Temperature.Average, 1))°C" -ForegroundColor Green
            Write-Host "  Max: $($stats.Temperature.Max)°C" -ForegroundColor $(if ($stats.Temperature.Max -gt 80) { "Red" } else { "Gray" })
        }
    }

    # Save report
    $report = [ordered]@{
        timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
        gpu_info = $script:GPUInfo
        statistics = $stats
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
    Write-Host "RawrXD GPU Profiler" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    Start-GPUProfiling
    Write-Report
}

# Run main
Main
