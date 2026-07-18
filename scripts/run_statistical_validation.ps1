#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Gate D Statistical Validation - 1000-Run Performance Benchmark
.DESCRIPTION
    Runs 1000 iterations of kernel benchmarks to generate statistical evidence
    for Gate D sign-off. Captures speedup distributions and confidence intervals.
.PARAMETER Iterations
    Number of iterations to run (default: 1000)
.PARAMETER OutputDir
    Directory for evidence artifacts (default: evidence/gate_d)
#>

param(
    [int]$Iterations = 1000,
    [string]$OutputDir = "evidence/gate_d"
)

$ErrorActionPreference = "Stop"

# Create output directory
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
New-Item -ItemType Directory -Force -Path "$OutputDir/rmsnorm" | Out-Null
New-Item -ItemType Directory -Force -Path "$OutputDir/softmax" | Out-Null

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Gate D Statistical Validation" -ForegroundColor Cyan
Write-Host "Iterations: $Iterations" -ForegroundColor Cyan
Write-Host "Output: $OutputDir" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Test executable path
$TestExe = "build-ninja/tests/test_gate_d_intrinsics.exe"
if (-not (Test-Path $TestExe)) {
    Write-Error "Test executable not found: $TestExe"
    exit 1
}

# Arrays to store results
$rmsnormSpeedups = @()
$softmaxSpeedups = @()
$rmsnormErrors = @()
$softmaxErrors = @()

Write-Host "Running $Iterations iterations..." -ForegroundColor Yellow

for ($i = 1; $i -le $Iterations; $i++) {
    # Run test and capture output
    $output = & $TestExe 2>&1
    $outputString = $output | Out-String
    
    # Parse RMSNorm results - look for the specific line
    $rmsnormMatch = [regex]::Match($outputString, "RMSNorm.*Speedup:\s+([0-9.]+)x")
    if ($rmsnormMatch.Success) {
        $rmsnormSpeedups += [float]$rmsnormMatch.Groups[1].Value
    }
    $rmsnormErrorMatch = [regex]::Match($outputString, "RMSNorm.*Max error:\s+([0-9.eE+-]+)")
    if ($rmsnormErrorMatch.Success) {
        $rmsnormErrors += [float]$rmsnormErrorMatch.Groups[1].Value
    }
    
    # Parse Softmax results
    $softmaxMatch = [regex]::Match($outputString, "Softmax.*Speedup:\s+([0-9.]+)x")
    if ($softmaxMatch.Success) {
        $softmaxSpeedups += [float]$softmaxMatch.Groups[1].Value
    }
    $softmaxErrorMatch = [regex]::Match($outputString, "Softmax.*Max error:\s+([0-9.eE+-]+)")
    if ($softmaxErrorMatch.Success) {
        $softmaxErrors += [float]$softmaxErrorMatch.Groups[1].Value
    }
    
    # Progress indicator
    if ($i % 10 -eq 0) {
        Write-Host "  Completed $i/$Iterations iterations" -ForegroundColor Gray
    }
}

# Calculate statistics
function Get-Statistics($data) {
    if ($data.Count -eq 0) {
        return @{ Count = 0; Mean = 0; StdDev = 0; Min = 0; Max = 0; Median = 0; P5 = 0; P95 = 0 }
    }
    
    $sorted = @($data | Sort-Object)
    $n = $data.Count
    $mean = ($data | Measure-Object -Average).Average
    $variance = ($data | ForEach-Object { ($_ - $mean) * ($_ - $mean) } | Measure-Object -Average).Average
    $stdDev = [math]::Sqrt($variance)
    $min = ($data | Measure-Object -Minimum).Minimum
    $max = ($data | Measure-Object -Maximum).Maximum
    $median = $sorted[[int]($n / 2)]
    $p5 = $sorted[[int]($n * 0.05)]
    $p95 = $sorted[[int]($n * 0.95)]
    
    return @{
        Count = $n
        Mean = $mean
        StdDev = $stdDev
        Min = $min
        Max = $max
        Median = $median
        P5 = $p5
        P95 = $p95
    }
}

$rmsnormStats = Get-Statistics $rmsnormSpeedups
$softmaxStats = Get-Statistics $softmaxSpeedups

# Generate JSON report
$report = @{
    metadata = @{
        timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
        iterations = $Iterations
        platform = "Windows 11 x64"
        cpu = "AMD Ryzen (AVX2)"
    }
    rmsnorm = @{
        speedup = $rmsnormStats
        error = @{
            mean = ($rmsnormErrors | Measure-Object -Average).Average
            max = ($rmsnormErrors | Measure-Object -Maximum).Maximum
        }
        target = @{
            minSpeedup = 3.0
            maxError = 1e-5
        }
        pass = ($rmsnormStats.Mean -ge 3.0 -and ($rmsnormErrors | Measure-Object -Maximum).Maximum -le 1e-5)
    }
    softmax = @{
        speedup = $softmaxStats
        error = @{
            mean = ($softmaxErrors | Measure-Object -Average).Average
            max = ($softmaxErrors | Measure-Object -Maximum).Maximum
        }
        target = @{
            minSpeedup = 2.0
            maxError = 1e-3
        }
        pass = ($softmaxStats.Mean -ge 2.0 -and ($softmaxErrors | Measure-Object -Maximum).Maximum -le 1e-3)
    }
}

$reportJson = $report | ConvertTo-Json -Depth 10
$reportJson | Out-File "$OutputDir/statistical_report.json" -Encoding UTF8

# Generate CSV raw data
$rmsnormSpeedups -join "`n" | Out-File "$OutputDir/rmsnorm/speedups.csv" -Encoding UTF8
$rmsnormErrors -join "`n" | Out-File "$OutputDir/rmsnorm/errors.csv" -Encoding UTF8
$softmaxSpeedups -join "`n" | Out-File "$OutputDir/softmax/speedups.csv" -Encoding UTF8
$softmaxErrors -join "`n" | Out-File "$OutputDir/softmax/errors.csv" -Encoding UTF8

# Print summary
Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "Statistical Validation Complete" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "RMSNorm AVX2:" -ForegroundColor Cyan
Write-Host "  Mean Speedup: $($rmsnormStats.Mean.ToString('F2'))x" -ForegroundColor White
Write-Host "  95% CI: [$($rmsnormStats.P5.ToString('F2'))x, $($rmsnormStats.P95.ToString('F2'))x]" -ForegroundColor White
Write-Host "  Max Error: $(($rmsnormErrors | Measure-Object -Maximum).Maximum)" -ForegroundColor White
Write-Host "  Status: $(if ($report.rmsnorm.pass) { 'PASS' } else { 'FAIL' })" -ForegroundColor $(if ($report.rmsnorm.pass) { 'Green' } else { 'Red' })
Write-Host ""
Write-Host "Softmax AVX2:" -ForegroundColor Cyan
Write-Host "  Mean Speedup: $($softmaxStats.Mean.ToString('F2'))x" -ForegroundColor White
Write-Host "  95% CI: [$($softmaxStats.P5.ToString('F2'))x, $($softmaxStats.P95.ToString('F2'))x]" -ForegroundColor White
Write-Host "  Max Error: $(($softmaxErrors | Measure-Object -Maximum).Maximum)" -ForegroundColor White
Write-Host "  Status: $(if ($report.softmax.pass) { 'PASS' } else { 'FAIL' })" -ForegroundColor $(if ($report.softmax.pass) { 'Green' } else { 'Red' })
Write-Host ""
Write-Host "Artifacts saved to: $OutputDir" -ForegroundColor Yellow
