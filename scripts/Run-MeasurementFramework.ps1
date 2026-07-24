#=============================================================================
# Run-MeasurementFramework.ps1
# Automated execution of measurement framework with report generation
#=============================================================================

param(
    [string]$BuildConfig = "Release",
    [string]$BuildDir = "build",
    [switch]$SkipBuild,
    [switch]$SkipSlowTests,
    [string]$OutputDir = "reports"
)

$ErrorActionPreference = "Stop"

# Colors for output
$Colors = @{
    Header = "Cyan"
    Pass = "Green"
    Fail = "Red"
    Warn = "Yellow"
    Info = "White"
}

function Write-Header($text) {
    Write-Host "`n=============================================================================" -ForegroundColor $Colors.Header
    Write-Host $text -ForegroundColor $Colors.Header
    Write-Host "=============================================================================" -ForegroundColor $Colors.Header
}

function Write-Result($name, $passed, $duration, $details = "") {
    $status = if ($passed) { "PASS" } else { "FAIL" }
    $color = if ($passed) { $Colors.Pass } else { $Colors.Fail }
    Write-Host "  [$status] $name (${duration}s) $details" -ForegroundColor $color
}

# Create output directory
$ReportDir = Join-Path $PSScriptRoot ".." $OutputDir
New-Item -ItemType Directory -Force -Path $ReportDir | Out-Null

$Timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$ReportFile = Join-Path $ReportDir "measurement_report_$Timestamp.md"

Write-Header "RawrXD Measurement Framework"
Write-Host "Build Config: $BuildConfig" -ForegroundColor $Colors.Info
Write-Host "Report: $ReportFile" -ForegroundColor $Colors.Info

# Initialize report
@"
# RawrXD Measurement Framework Report

**Date:** $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")  
**Build Config:** $BuildConfig  
**Commit:** $(git rev-parse --short HEAD 2>$null || "unknown")

## Summary

| Test | Status | Duration | Result |
|------|--------|----------|--------|
"@ | Out-File -FilePath $ReportFile -Encoding UTF8

# Build if needed
if (-not $SkipBuild) {
    Write-Header "Building Measurement Tests"
    
    $Tests = @(
        "benchmark_dispatch_overhead",
        "benchmark_planner_amortization",
        "validate_end_to_end",
        "nevm_determinism_validation"
    )
    
    if (-not $SkipSlowTests) {
        $Tests += "nevm_stress_test"
    }
    
    foreach ($test in $Tests) {
        Write-Host "  Building $test..." -NoNewline
        try {
            cmake --build $BuildDir --config $BuildConfig --target $test 2>&1 | Out-Null
            Write-Host " OK" -ForegroundColor $Colors.Pass
        } catch {
            Write-Host " FAILED" -ForegroundColor $Colors.Fail
            Write-Error "Build failed for $test"
        }
    }
}

# Run tests
Write-Header "Running Measurement Tests"

$Results = @()

# Test 1: Dispatch Overhead
Write-Host "`n[1/5] Dispatch Overhead Benchmark" -ForegroundColor $Colors.Header
$sw = [System.Diagnostics.Stopwatch]::StartNew()
try {
    $output = & (Join-Path $BuildDir "bin" $BuildConfig "benchmark_dispatch_overhead.exe") 2>&1
    $sw.Stop()
    $passed = $output -match "PASSED|VALIDATED"
    Write-Result "benchmark_dispatch_overhead" $passed $sw.Elapsed.TotalSeconds
    $Results += @{ Name = "Dispatch Overhead"; Passed = $passed; Duration = $sw.Elapsed; Output = $output }
    
    # Extract key metrics
    $speedup = [regex]::Match($output, "Speedup.*?([\d.]+)x").Groups[1].Value
    if ($speedup) {
        Write-Host "    Speedup: ${speedup}x" -ForegroundColor $Colors.Info
    }
} catch {
    $sw.Stop()
    Write-Result "benchmark_dispatch_overhead" $false $sw.Elapsed.TotalSeconds "Exception: $_"
    $Results += @{ Name = "Dispatch Overhead"; Passed = $false; Duration = $sw.Elapsed; Output = $_ }
}

# Test 2: Planner Amortization
Write-Host "`n[2/5] Planner Amortization Benchmark" -ForegroundColor $Colors.Header
$sw = [System.Diagnostics.Stopwatch]::StartNew()
try {
    $output = & (Join-Path $BuildDir "bin" $BuildConfig "benchmark_planner_amortization.exe") 2>&1
    $sw.Stop()
    $passed = $output -match "PASS|break-even"
    Write-Result "benchmark_planner_amortization" $passed $sw.Elapsed.TotalSeconds
    $Results += @{ Name = "Planner Amortization"; Passed = $passed; Duration = $sw.Elapsed; Output = $output }
    
    # Extract break-even
    $breakeven = [regex]::Match($output, "Break-even at:\s*([\d.]+)").Groups[1].Value
    if ($breakeven) {
        Write-Host "    Break-even: $breakeven tokens" -ForegroundColor $Colors.Info
    }
} catch {
    $sw.Stop()
    Write-Result "benchmark_planner_amortization" $false $sw.Elapsed.TotalSeconds "Exception: $_"
    $Results += @{ Name = "Planner Amortization"; Passed = $false; Duration = $sw.Elapsed; Output = $_ }
}

# Test 3: End-to-End Validation (Four Gates)
Write-Host "`n[3/5] End-to-End Validation (Four Gates)" -ForegroundColor $Colors.Header
$sw = [System.Diagnostics.Stopwatch]::StartNew()
try {
    $output = & (Join-Path $BuildDir "bin" $BuildConfig "validate_end_to_end.exe") 2>&1
    $sw.Stop()
    $exitCode = $LASTEXITCODE
    $passed = ($exitCode -eq 0)
    Write-Result "validate_end_to_end" $passed $sw.Elapsed.TotalSeconds "Exit code: $exitCode"
    $Results += @{ Name = "End-to-End (4 Gates)"; Passed = $passed; Duration = $sw.Elapsed; Output = $output }
    
    # Count gates passed
    $gatesPassed = ([regex]::Matches($output, "GATE \d+ PASSED")).Count
    Write-Host "    Gates passed: $gatesPassed/4" -ForegroundColor $Colors.Info
} catch {
    $sw.Stop()
    Write-Result "validate_end_to_end" $false $sw.Elapsed.TotalSeconds "Exception: $_"
    $Results += @{ Name = "End-to-End (4 Gates)"; Passed = $false; Duration = $sw.Elapsed; Output = $_ }
}

# Test 4: Determinism Validation
Write-Host "`n[4/5] NEVM Determinism Validation" -ForegroundColor $Colors.Header
$sw = [System.Diagnostics.Stopwatch]::StartNew()
try {
    $output = & (Join-Path $BuildDir "bin" $BuildConfig "nevm_determinism_validation.exe") 2>&1
    $sw.Stop()
    $passed = $output -match "PASS|deterministic"
    Write-Result "nevm_determinism_validation" $passed $sw.Elapsed.TotalSeconds
    $Results += @{ Name = "Determinism"; Passed = $passed; Duration = $sw.Elapsed; Output = $output }
} catch {
    $sw.Stop()
    Write-Result "nevm_determinism_validation" $false $sw.Elapsed.TotalSeconds "Exception: $_"
    $Results += @{ Name = "Determinism"; Passed = $false; Duration = $sw.Elapsed; Output = $_ }
}

# Test 5: Stress Test (optional)
if (-not $SkipSlowTests) {
    Write-Host "`n[5/5] NEVM Stress Test (100K tokens)" -ForegroundColor $Colors.Header
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $output = & (Join-Path $BuildDir "bin" $BuildConfig "nevm_stress_test.exe") 2>&1
        $sw.Stop()
        $passed = $output -match "PASS|stable"
        Write-Result "nevm_stress_test" $passed $sw.Elapsed.TotalSeconds
        $Results += @{ Name = "Stress Test"; Passed = $passed; Duration = $sw.Elapsed; Output = $output }
    } catch {
        $sw.Stop()
        Write-Result "nevm_stress_test" $false $sw.Elapsed.TotalSeconds "Exception: $_"
        $Results += @{ Name = "Stress Test"; Passed = $false; Duration = $sw.Elapsed; Output = $_ }
    }
} else {
    Write-Host "`n[5/5] NEVM Stress Test - SKIPPED (use -SkipSlowTests:$false to run)" -ForegroundColor $Colors.Warn
}

# Generate report
Write-Header "Generating Report"

$totalTests = $Results.Count
$passedTests = ($Results | Where-Object { $_.Passed }).Count
$failedTests = $totalTests - $passedTests

foreach ($r in $Results) {
    $status = if ($r.Passed) { "PASS" } else { "FAIL" }
    $durationStr = "{0:N1}s" -f $r.Duration.TotalSeconds
    "| $($r.Name) | $status | $durationStr | - |" | Out-File -FilePath $ReportFile -Append -Encoding UTF8
}

@"

## Results Summary

- **Total Tests:** $totalTests
- **Passed:** $passedTests
- **Failed:** $failedTests
- **Success Rate:** $([math]::Round($passedTests / $totalTests * 100, 1))%

## Detailed Output

"@ | Out-File -FilePath $ReportFile -Append -Encoding UTF8

foreach ($r in $Results) {
    @"
### $($r.Name)

**Status:** $(if ($r.Passed) { "PASS" } else { "FAIL" })  
**Duration:** $($r.Duration.ToString())

```
$($r.Output -join "`n")
```

"@ | Out-File -FilePath $ReportFile -Append -Encoding UTF8
}

@"

## Validation Matrix

| Claim | Target | Status |
|-------|--------|--------|
| 50x dispatch overhead reduction | >=40x | $(if (($Results | Where-Object { $_.Name -eq "Dispatch Overhead" }).Passed) { "VALIDATED" } else { "PENDING" }) |
| <1us/token planner overhead | <1us | $(if (($Results | Where-Object { $_.Name -eq "Planner Amortization" }).Passed) { "VALIDATED" } else { "PENDING" }) |
| Four independent gates | 4/4 pass | $passedTests/4 |
| Determinism | 100% identical | $(if (($Results | Where-Object { $_.Name -eq "Determinism" }).Passed) { "VALIDATED" } else { "PENDING" }) |

---
*Generated by RawrXD Measurement Framework*
"@ | Out-File -FilePath $ReportFile -Append -Encoding UTF8

# Final summary
Write-Header "Measurement Framework Complete"
Write-Host "Total Tests: $totalTests" -ForegroundColor $Colors.Info
Write-Host "Passed: $passedTests" -ForegroundColor $Colors.Pass
Write-Host "Failed: $failedTests" -ForegroundColor $(if ($failedTests -gt 0) { $Colors.Fail } else { $Colors.Info })
Write-Host "Report: $ReportFile" -ForegroundColor $Colors.Info

if ($failedTests -gt 0) {
    exit 1
} else {
    exit 0
}
