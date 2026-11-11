# RawrXD Performance Regression Detector
# Detects performance regressions by comparing benchmark results
# Version: 1.0.0
# Author: RawrXD DevOps Team

param(
    [Parameter()]
    [ValidateSet("Compare", "Baseline", "Trend", "Alert")]
    [string]$Action = "Compare",
    
    [Parameter()]
    [string]$BaselinePath = "benchmarks\baseline.json",
    
    [Parameter()]
    [string]$CurrentPath = "benchmarks\current.json",
    
    [Parameter()]
    [double]$Threshold = 10.0,
    
    [Parameter()]
    [string]$Metric = "tokens_per_second",
    
    [Parameter()]
    [string]$OutputPath = "regression-report.json",
    
    [Parameter()]
    [switch]$FailOnRegression
)

$ErrorActionPreference = "Stop"
$script:Version = "1.0.0"

function Write-Status { param([string]$Message) Write-Host "[INFO] $Message" -ForegroundColor Cyan }
function Write-Success { param([string]$Message) Write-Host "[OK] $Message" -ForegroundColor Green }
function Write-Warning { param([string]$Message) Write-Host "[WARN] $Message" -ForegroundColor Yellow }
function Write-Error { param([string]$Message) Write-Host "[ERROR] $Message" -ForegroundColor Red }

function Get-BenchmarkData {
    param([string]$Path)
    
    if (-not (Test-Path $Path)) {
        throw "Benchmark file not found: $Path"
    }
    
    return Get-Content $Path | ConvertFrom-Json
}

function Compare-Benchmarks {
    $baseline = Get-BenchmarkData -Path $BaselinePath
    $current = Get-BenchmarkData -Path $CurrentPath
    
    Write-Status "Comparing benchmarks..."
    Write-Status "Baseline: $BaselinePath"
    Write-Status "Current: $CurrentPath"
    Write-Status "Threshold: $Threshold%"
    Write-Host ""
    
    $regressions = @()
    $improvements = @()
    $unchanged = @()
    
    foreach ($test in $baseline.Tests) {
        $currentTest = $current.Tests | Where-Object { $_.Name -eq $test.Name }
        
        if (-not $currentTest) {
            Write-Warning "Test '$($test.Name)' not found in current results"
            continue
        }
        
        $baselineValue = $test.$Metric
        $currentValue = $currentTest.$Metric
        
        if ($baselineValue -eq 0) { continue }
        
        $change = (($currentValue - $baselineValue) / $baselineValue) * 100
        $absChange = [math]::Abs($change)
        
        $result = [PSCustomObject]@{
            TestName = $test.Name
            Baseline = $baselineValue
            Current = $currentValue
            Change = $change
            ChangePercent = [math]::Round($change, 2)
            Status = "unchanged"
        }
        
        if ($absChange -gt $Threshold) {
            if ($change -lt 0) {
                $result.Status = "regression"
                $regressions += $result
            } else {
                $result.Status = "improvement"
                $improvements += $result
            }
        } else {
            $unchanged += $result
        }
    }
    
    # Display results
    Write-Host "Performance Comparison Results" -ForegroundColor Cyan
    Write-Host "=============================" -ForegroundColor Cyan
    Write-Host ""
    
    if ($regressions.Count -gt 0) {
        Write-Host "⚠️  REGRESSIONS DETECTED ($($regressions.Count))" -ForegroundColor Red
        Write-Host ""
        Write-Host "Test Name                    Baseline    Current     Change"
        Write-Host "---------                    --------    -------     ------"
        
        foreach ($reg in $regressions) {
            Write-Host ($reg.TestName).PadRight(29) -NoNewline
            Write-Host $reg.Baseline.ToString().PadRight(12) -NoNewline
            Write-Host $reg.Current.ToString().PadRight(12) -NoNewline
            Write-Host "$($reg.ChangePercent)%" -ForegroundColor Red
        }
        Write-Host ""
    }
    
    if ($improvements.Count -gt 0) {
        Write-Host "✅ IMPROVEMENTS ($($improvements.Count))" -ForegroundColor Green
        Write-Host ""
        Write-Host "Test Name                    Baseline    Current     Change"
        Write-Host "---------                    --------    -------     ------"
        
        foreach ($imp in $improvements) {
            Write-Host ($imp.TestName).PadRight(29) -NoNewline
            Write-Host $imp.Baseline.ToString().PadRight(12) -NoNewline
            Write-Host $imp.Current.ToString().PadRight(12) -NoNewline
            Write-Host "+$($imp.ChangePercent)%" -ForegroundColor Green
        }
        Write-Host ""
    }
    
    Write-Host "Summary" -ForegroundColor Cyan
    Write-Host "-------"
    Write-Host "Total Tests: $($baseline.Tests.Count)"
    Write-Host "Regressions: $($regressions.Count)" -ForegroundColor $(if ($regressions.Count -gt 0) { "Red" } else { "Green" })
    Write-Host "Improvements: $($improvements.Count)" -ForegroundColor Green
    Write-Host "Unchanged: $($unchanged.Count)"
    Write-Host ""
    
    # Export report
    $report = @{
        GeneratedAt = (Get-Date).ToString("o")
        BaselinePath = $BaselinePath
        CurrentPath = $CurrentPath
        Threshold = $Threshold
        Metric = $Metric
        Summary = @{
            Total = $baseline.Tests.Count
            Regressions = $regressions.Count
            Improvements = $improvements.Count
            Unchanged = $unchanged.Count
        }
        Regressions = $regressions
        Improvements = $improvements
        Unchanged = $unchanged
    }
    
    $report | ConvertTo-Json -Depth 5 | Set-Content $OutputPath
    Write-Success "Report saved to: $OutputPath"
    
    if ($FailOnRegression -and $regressions.Count -gt 0) {
        exit 1
    }
}

function Set-Baseline {
    Write-Status "Setting new baseline from: $CurrentPath"
    
    if (-not (Test-Path $CurrentPath)) {
        throw "Current benchmark file not found: $CurrentPath"
    }
    
    Copy-Item $CurrentPath $BaselinePath -Force
    Write-Success "Baseline set from $CurrentPath to $BaselinePath"
}

function Show-Trend {
    Write-Status "Analyzing performance trends..."
    
    $benchmarkDir = Split-Path $BaselinePath -Parent
    $benchmarkFiles = Get-ChildItem -Path $benchmarkDir -Filter "benchmark-*.json" | 
        Sort-Object LastWriteTime -Descending | 
        Select-Object -First 10
    
    if ($benchmarkFiles.Count -lt 2) {
        Write-Warning "Not enough benchmark history for trend analysis"
        return
    }
    
    Write-Host "Performance Trend (Last $($benchmarkFiles.Count) runs)" -ForegroundColor Cyan
    Write-Host "======================================================" -ForegroundColor Cyan
    Write-Host ""
    
    # Simple trend visualization
    $metrics = @()
    foreach ($file in ($benchmarkFiles | Sort-Object LastWriteTime)) {
        $data = Get-Content $file.FullName | ConvertFrom-Json
        $avgMetric = ($data.Tests | Measure-Object -Property $Metric -Average).Average
        $metrics += [PSCustomObject]@{
            Date = $file.LastWriteTime
            Value = $avgMetric
        }
    }
    
    Write-Host "Date                $Metric"
    Write-Host "----                $("-" * $Metric.Length)"
    foreach ($m in $metrics) {
        Write-Host $m.Date.ToString("yyyy-MM-dd HH:mm").PadRight(20) -NoNewline
        Write-Host $m.Value
    }
    Write-Host ""
}

function Test-Alert {
    Write-Status "Checking for performance alerts..."
    
    if (-not (Test-Path $OutputPath)) {
        Write-Warning "No regression report found. Run Compare first."
        return
    }
    
    $report = Get-Content $OutputPath | ConvertFrom-Json
    
    if ($report.Summary.Regressions -gt 0) {
        Write-Error "ALERT: $($report.Summary.Regressions) performance regressions detected!"
        
        # Send notification (simulated)
        Write-Status "Would send alert notification here"
    } else {
        Write-Success "No performance alerts"
    }
}

# Main execution
try {
    switch ($Action) {
        "Compare" { Compare-Benchmarks }
        "Baseline" { Set-Baseline }
        "Trend" { Show-Trend }
        "Alert" { Test-Alert }
    }
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}
