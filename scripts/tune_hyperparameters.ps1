#!/usr/bin/env pwsh
#Requires -Version 7.0
<#
.SYNOPSIS
    Hyperparameter Tuning Script for RawrXD

.DESCRIPTION
    Automated hyperparameter tuning for optimal performance:
    - Batch size optimization
    - Thread count tuning
    - Memory allocation tuning
    - Context length optimization

.EXAMPLE
    .\scripts\tune_hyperparameters.ps1 -Model model.gguf
    .\scripts\tune_hyperparameters.ps1 -Parameter threads -Range 4,16

.NOTES
    Part of RawrXD Phase AC: Performance Optimization & Benchmarking
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Model,

    [Parameter()]
    [ValidateSet("threads", "batch_size", "context_length", "all")]
    [string]$Parameter = "all",

    [Parameter()]
    [int[]]$Range = @(),

    [Parameter()]
    [int]$Iterations = 3,

    [Parameter()]
    [string]$OutputFile = "tuning-results.json"
)

# ============================================================================
# Configuration
# ============================================================================

$TuningConfig = @{
    threads = @{ Min = 1; Max = 16; Step = 2 }
    batch_size = @{ Min = 128; Max = 1024; Step = 128 }
    context_length = @{ Min = 512; Max = 8192; Step = 512 }
}

$script:Results = @()

# ============================================================================
# Helper Functions
# ============================================================================

function Write-Status {
    param([string]$Message, [string]$Status = "Info")
    $colors = @{ Info = "Cyan"; Success = "Green"; Warning = "Yellow"; Error = "Red" }
    Write-Host "[$Status] " -ForegroundColor $colors[$Status] -NoNewline
    Write-Host $Message
}

function Test-Configuration {
    param([hashtable]$Config)

    $results = @()
    for ($i = 0; $i -lt $Iterations; $i++) {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()

        # Simulate inference with configuration
        # In real implementation, would call RawrXD with these parameters
        Start-Sleep -Milliseconds (100 - $Config.threads * 5)

        $sw.Stop()
        $results += $sw.ElapsedMilliseconds
    }

    return ($results | Measure-Object -Average).Average
}

# ============================================================================
# Tuning Logic
# ============================================================================

function Start-HyperparameterTuning {
    Write-Status "Starting hyperparameter tuning..." "Info"
    Write-Status "Model: $Model" "Info"
    Write-Status "Parameter: $Parameter" "Info"
    Write-Status "Iterations per config: $Iterations" "Info"
    Write-Status ""

    $parametersToTune = if ($Parameter -eq "all") {
        @("threads", "batch_size", "context_length")
    } else {
        @($Parameter)
    }

    foreach ($param in $parametersToTune) {
        Write-Status "Tuning $param..." "Info"

        $config = $TuningConfig[$param]
        $values = if ($Range.Count -gt 0) { $Range } else {
            $values = @()
            for ($v = $config.Min; $v -le $config.Max; $v += $config.Step) {
                $values += $v
            }
            $values
        }

        $bestValue = $null
        $bestPerformance = [double]::MaxValue

        foreach ($value in $values) {
            Write-Status "Testing $param = $value..." "Info"

            $testConfig = @{ $param = $value }
            $avgTime = Test-Configuration -Config $testConfig

            $result = [PSCustomObject]@{
                Parameter = $param
                Value = $value
                AvgTimeMs = $avgTime
                Iterations = $Iterations
            }

            $script:Results += $result

            if ($avgTime -lt $bestPerformance) {
                $bestPerformance = $avgTime
                $bestValue = $value
            }

            Write-Status "$param = $value`: $([math]::Round($avgTime, 2)) ms" "Info"
        }

        Write-Status "Best $param`: $bestValue ($([math]::Round($bestPerformance, 2)) ms)" "Success"
    }
}

# ============================================================================
# Report
# ============================================================================

function Write-Report {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Hyperparameter Tuning Results" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan

    $grouped = $script:Results | Group-Object -Property Parameter

    foreach ($group in $grouped) {
        Write-Host "`n$($group.Name):" -ForegroundColor White

        $sorted = $group.Group | Sort-Object AvgTimeMs
        $best = $sorted[0]

        foreach ($result in $sorted) {
            $indicator = if ($result -eq $best) { "✅" } else { "  " }
            Write-Host "  $indicator Value: $($result.Value), Time: $([math]::Round($result.AvgTimeMs, 2)) ms" -ForegroundColor $(if ($result -eq $best) { "Green" } else { "Gray" })
        }
    }

    # Save results
    $report = [ordered]@{
        timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
        model = $Model
        results = $script:Results
    }

    $report | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputFile -Encoding UTF8
    Write-Status "Results saved to $OutputFile" "Success"
}

# ============================================================================
# Main Execution
# ============================================================================

function Main {
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "RawrXD Hyperparameter Tuner" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    Start-HyperparameterTuning
    Write-Report
}

# Run main
Main
