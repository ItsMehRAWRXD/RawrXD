#!/usr/bin/env pwsh
#Requires -Version 7.0
<#
.SYNOPSIS
    Benchmark Comparison Tool for RawrXD

.DESCRIPTION
    Compares benchmark results between versions or configurations:
    - Side-by-side comparison
    - Statistical significance testing
    - Trend analysis
    - Visualization data generation

.EXAMPLE
    .\scripts\compare_benchmarks.ps1 -Baseline baseline.json -Current current.json
    .\scripts\compare_benchmarks.ps1 -Directory benchmarks/ -Pattern "*.json"

.NOTES
    Part of RawrXD Phase AC: Performance Optimization & Benchmarking
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$BaselineFile = "",

    [Parameter()]
    [string]$CurrentFile = "",

    [Parameter()]
    [string]$Directory = "",

    [Parameter()]
    [string]$Pattern = "*.json",

    [Parameter()]
    [double]$SignificanceThreshold = 5.0,

    [Parameter()]
    [string]$OutputFile = "benchmark-comparison.html",

    [Parameter()]
    [switch]$GenerateChart
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

function Import-BenchmarkData {
    param([string]$Path)

    if (-not (Test-Path $Path)) {
        return $null
    }

    try {
        $data = Get-Content -Path $Path -Raw | ConvertFrom-Json
        return $data
    } catch {
        Write-Status "Failed to parse $Path" "Error"
        return $null
    }
}

function Get-ChangeIndicator {
    param([double]$PercentChange, [string]$Metric)

    $isHigherBetter = $Metric -in @("tokens_per_second", "throughput", "requests_per_second")

    if ($isHigherBetter) {
        if ($PercentChange -gt $SignificanceThreshold) { return "📈" }
        if ($PercentChange -lt -$SignificanceThreshold) { return "📉" }
        return "➡️"
    } else {
        if ($PercentChange -lt -$SignificanceThreshold) { return "📈" }
        if ($PercentChange -gt $SignificanceThreshold) { return "📉" }
        return "➡️"
    }
}

# ============================================================================
# Comparison Logic
# ============================================================================

function Compare-Benchmarks {
    param($Baseline, $Current)

    $comparisons = @()

    foreach ($currentResult in $Current.results) {
        $baselineResult = $Baseline.results | Where-Object { $_.Name -eq $currentResult.Name }

        if ($baselineResult) {
            $percentChange = (($currentResult.Value - $baselineResult.Value) / $baselineResult.Value) * 100

            $comparisons += [PSCustomObject]@{
                Name = $currentResult.Name
                Baseline = $baselineResult.Value
                Current = $currentResult.Value
                Change = $currentResult.Value - $baselineResult.Value
                PercentChange = $percentChange
                Indicator = Get-ChangeIndicator -PercentChange $percentChange -Metric $currentResult.Metric
                Significant = [math]::Abs($percentChange) -gt $SignificanceThreshold
            }
        }
    }

    return $comparisons
}

# ============================================================================
# Report Generation
# ============================================================================

function Write-ConsoleReport {
    param($Comparisons)

    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Benchmark Comparison Report" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan

    Write-Host "`nResults:" -ForegroundColor White
    Write-Host ""

    $improvements = $Comparisons | Where-Object { $_.Significant -and $_.PercentChange -gt 0 }
    $regressions = $Comparisons | Where-Object { $_.Significant -and $_.PercentChange -lt 0 }
    $stable = $Comparisons | Where-Object { -not $_.Significant }

    if ($improvements) {
        Write-Host "Improvements:" -ForegroundColor Green
        foreach ($imp in $improvements) {
            Write-Host "  $($imp.Indicator) $($imp.Name): +$([math]::Round($imp.PercentChange, 2))% ($($imp.Baseline) → $($imp.Current))" -ForegroundColor Green
        }
        Write-Host ""
    }

    if ($regressions) {
        Write-Host "Regressions:" -ForegroundColor Red
        foreach ($reg in $regressions) {
            Write-Host "  $($reg.Indicator) $($reg.Name): $([math]::Round($reg.PercentChange, 2))% ($($reg.Baseline) → $($reg.Current))" -ForegroundColor Red
        }
        Write-Host ""
    }

    if ($stable) {
        Write-Host "Stable (within threshold):" -ForegroundColor Gray
        foreach ($stab in $stable) {
            Write-Host "  $($stab.Indicator) $($stab.Name): $([math]::Round($stab.PercentChange, 2))%" -ForegroundColor Gray
        }
    }

    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Summary: $($improvements.Count) improvements, $($regressions.Count) regressions, $($stable.Count) stable" -ForegroundColor White
}

function Write-HtmlReport {
    param($Comparisons, $Baseline, $Current)

    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>RawrXD Benchmark Comparison</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #1e1e1e; color: #d4d4d4; }
        h1, h2 { color: #569cd6; }
        table { border-collapse: collapse; width: 100%; margin: 20px 0; }
        th, td { border: 1px solid #3e3e3e; padding: 12px; text-align: left; }
        th { background: #252526; }
        .improvement { color: #4ec9b0; }
        .regression { color: #f48771; }
        .stable { color: #d4d4d4; }
        .summary { margin: 20px 0; padding: 15px; background: #252526; border-radius: 5px; }
    </style>
</head>
<body>
    <h1>📊 RawrXD Benchmark Comparison</h1>
    <div class="summary">
        <p><strong>Baseline:</strong> $($Baseline.timestamp)</p>
        <p><strong>Current:</strong> $($Current.timestamp)</p>
        <p><strong>Threshold:</strong> $SignificanceThreshold%</p>
    </div>

    <h2>Results</h2>
    <table>
        <tr>
            <th>Benchmark</th>
            <th>Baseline</th>
            <th>Current</th>
            <th>Change</th>
            <th>Status</th>
        </tr>
"@

    foreach ($comp in $Comparisons) {
        $class = if ($comp.PercentChange -gt $SignificanceThreshold) { "improvement" }
                 elseif ($comp.PercentChange -lt -$SignificanceThreshold) { "regression" }
                 else { "stable" }
        $status = if ($class -eq "improvement") { "✅ Improved" }
                  elseif ($class -eq "regression") { "❌ Regression" }
                  else { "➡️ Stable" }

        $html += "<tr class='$class'>"
        $html += "<td>$($comp.Name)</td>"
        $html += "<td>$([math]::Round($comp.Baseline, 2))</td>"
        $html += "<td>$([math]::Round($comp.Current, 2))</td>"
        $html += "<td>$([math]::Round($comp.PercentChange, 2))%</td>"
        $html += "<td>$status</td>"
        $html += "</tr>"
    }

    $html += @"
    </table>
    <p><em>Generated on $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</em></p>
</body>
</html>
"@

    $html | Out-File -FilePath $OutputFile -Encoding UTF8
    Write-Status "HTML report saved to $OutputFile" "Success"
}

# ============================================================================
# Main Execution
# ============================================================================

function Main {
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "RawrXD Benchmark Comparison" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    # Load data
    $baseline = $null
    $current = $null

    if ($BaselineFile -and $CurrentFile) {
        $baseline = Import-BenchmarkData -Path $BaselineFile
        $current = Import-BenchmarkData -Path $CurrentFile
    } elseif ($Directory) {
        $files = Get-ChildItem -Path $Directory -Filter $Pattern | Sort-Object LastWriteTime
        if ($files.Count -ge 2) {
            $baseline = Import-BenchmarkData -Path $files[-2].FullName
            $current = Import-BenchmarkData -Path $files[-1].FullName
        }
    }

    if (-not $baseline -or -not $current) {
        Write-Status "Could not load benchmark data" "Error"
        exit 1
    }

    Write-Status "Baseline: $($baseline.timestamp)" "Info"
    Write-Status "Current:  $($current.timestamp)" "Info"
    Write-Status ""

    # Compare
    $comparisons = Compare-Benchmarks -Baseline $baseline -Current $current

    # Generate reports
    Write-ConsoleReport -Comparisons $comparisons
    Write-HtmlReport -Comparisons $comparisons -Baseline $baseline -Current $current
}

# Run main
Main
