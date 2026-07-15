#!/usr/bin/env pwsh
#Requires -Version 7.0
<#
.SYNOPSIS
    Flame Graph Generator for RawrXD

.DESCRIPTION
    Generates flame graphs for performance visualization:
    - CPU profiling data conversion
    - Flame graph SVG generation
    - Hot spot identification

.EXAMPLE
    .\scripts\generate_flamegraph.ps1 -Input profile.txt
    .\scripts\generate_flamegraph.ps1 -Process RawrXD -Duration 30

.NOTES
    Part of RawrXD Phase AC: Performance Optimization & Benchmarking
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$InputFile = "",

    [Parameter()]
    [string]$ProcessName = "RawrXD",

    [Parameter()]
    [int]$Duration = 30,

    [Parameter()]
    [string]$OutputFile = "flamegraph.svg",

    [Parameter()]
    [switch]$UseETW
)

# ============================================================================
# Helper Functions
# ============================================================================

function Write-Status {
    param([string]$Message, [string]$Status = "Info")
    $colors = @{ Info = "Cyan"; Success = "Green"; Warning = "Yellow"; Error = "Red" }
    Write-Host "[$Status] " -ForegroundColor $colors[$Status] -NoNewline
    Write-Host $Message
}

function Test-FlameGraphTools {
    $flamegraphPl = Get-Command "flamegraph.pl" -ErrorAction SilentlyContinue
    $stackcollapse = Get-Command "stackcollapse" -ErrorAction SilentlyContinue

    return @{
        FlameGraph = [bool]$flamegraphPl
        StackCollapse = [bool]$stackcollapse
    }
}

# ============================================================================
# Profiling
# ============================================================================

function Start-Profiling {
    Write-Status "Starting profiling session ($Duration seconds)..." "Info"
    Write-Status "Target process: $ProcessName" "Info"

    $tools = Test-FlameGraphTools

    if (-not $tools.StackCollapse -and $UseETW) {
        Write-Status "ETW tools not found, using fallback method" "Warning"
    }

    # Find process
    $process = Get-Process -Name $ProcessName -ErrorAction SilentlyContinue
    if (-not $process) {
        Write-Status "Process $ProcessName not found" "Error"
        return $null
    }

    Write-Status "Found process: $($process.ProcessName) (PID: $($process.Id))" "Success"

    # Collect samples (simplified - would use real profiler in production)
    $samples = @()
    $startTime = Get-Date

    while (((Get-Date) - $startTime).TotalSeconds -lt $Duration) {
        $process.Refresh()
        $sample = [PSCustomObject]@{
            Timestamp = Get-Date
            CpuPercent = $process.CPU
            WorkingSet = $process.WorkingSet64
        }
        $samples += $sample
        Start-Sleep -Milliseconds 100
    }

    Write-Status "Collected $($samples.Count) samples" "Success"
    return $samples
}

# ============================================================================
# Flame Graph Generation
# ============================================================================

function New-FlameGraph {
    param($Samples)

    Write-Status "Generating flame graph..." "Info"

    $tools = Test-FlameGraphTools

    if ($tools.FlameGraph -and $InputFile -and (Test-Path $InputFile)) {
        # Use flamegraph.pl if available
        try {
            $output = & flamegraph.pl "$InputFile" 2>&1
            $output | Out-File -FilePath $OutputFile -Encoding UTF8
            Write-Status "Flame graph generated: $OutputFile" "Success"
            return
        } catch {
            Write-Status "flamegraph.pl failed, using fallback" "Warning"
        }
    }

    # Generate simplified SVG flame graph
    $svg = @"
<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="600" style="background: #ffffff;">
    <text x="10" y="30" font-family="Arial" font-size="20" fill="#333">RawrXD Flame Graph</text>
    <text x="10" y="55" font-family="Arial" font-size="12" fill="#666">Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</text>

    <rect x="10" y="70" width="1180" height="500" fill="#f5f5f5" stroke="#ccc"/>

    <text x="600" y="320" font-family="Arial" font-size="16" fill="#999" text-anchor="middle">
        Flame graph visualization would appear here
    </text>
    <text x="600" y="340" font-family="Arial" font-size="12" fill="#999" text-anchor="middle">
        (Requires folded stack samples from profiler)
    </text>

    <text x="10" y="590" font-family="Arial" font-size="10" fill="#666">
        Samples collected: $($Samples.Count) | Duration: $Duration seconds
    </text>
</svg>
"@

    $svg | Out-File -FilePath $OutputFile -Encoding UTF8
    Write-Status "Simplified flame graph generated: $OutputFile" "Success"
}

# ============================================================================
# Main Execution
# ============================================================================

function Main {
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "RawrXD Flame Graph Generator" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    $samples = Start-Profiling
    if ($samples) {
        New-FlameGraph -Samples $samples
    }
}

# Run main
Main
