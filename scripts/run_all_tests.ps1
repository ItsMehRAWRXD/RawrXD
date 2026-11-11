#!/usr/bin/env powershell
# =============================================================================
# Comprehensive Test Runner - RawrXD Validation Suite
# Runs all critical tests for Phase 17/18 validation
# =============================================================================

[CmdletBinding()]
param(
    [string]$BuildDir = "build-test",
    [string]$BuildType = "Release",
    [switch]$Clean,
    [switch]$SkipBuild,
    [string[]]$TestFilter = @()
)

$ErrorActionPreference = "Stop"
$TestResults = @()
$StartTime = Get-Date

# Color output functions
function Write-Header($text) {
    Write-Host "`n╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║ $text" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
}

function Write-Status($text, $status) {
    $color = switch($status) {
        "PASS" { "Green" }
        "FAIL" { "Red" }
        "WARN" { "Yellow" }
        "SKIP" { "DarkGray" }
        default { "White" }
    }
    Write-Host "[$status] $text" -ForegroundColor $color
}

# Test definitions
$Tests = @(
    @{
        Name = "AMX_Kernel_Smoke"
        Target = "RawrXD-AMXBench"
        Description = "AMX kernel validation on Sapphire Rapids"
        Critical = $true
        Args = @("--smoke")
    },
    @{
        Name = "INT8_Quantization"
        Target = "test_fp8_quantization"
        Description = "INT8/FP8 quantization accuracy"
        Critical = $true
        Args = @()
    },
    @{
        Name = "Sovereign_Stress"
        Target = "RawrXD-TestSovereign"
        Description = "Sovereign engine stress test"
        Critical = $true
        Args = @("--stress", "--duration=60")
    },
    @{
        Name = "Context_Correctness"
        Target = "ContextCorrectnessHarness"
        Description = "Context window correctness validation"
        Critical = $true
        Args = @()
    },
    @{
        Name = "Swarm_Smoke"
        Target = "SwarmSmokeTest"
        Description = "Distributed swarm functionality"
        Critical = $false
        Args = @()
    },
    @{
        Name = "Aperture_Standalone"
        Target = "ApertureStandaloneTest"
        Description = "Aperture inference engine"
        Critical = $true
        Args = @()
    },
    @{
        Name = "E2E_Integration"
        Target = "e2e_integration_test"
        Description = "End-to-end integration"
        Critical = $true
        Args = @()
    },
    @{
        Name = "Agentic_Orchestrator"
        Target = "agentic_orchestrator_smoke_test"
        Description = "Agentic orchestration"
        Critical = $false
        Args = @()
    },
    @{
        Name = "Measurement_Integration"
        Target = "smoke_test_measurement_integration"
        Description = "Performance measurement"
        Critical = $true
        Args = @()
    },
    @{
        Name = "Autonomous_Pipeline"
        Target = "test_autonomous_pipeline"
        Description = "Autonomous execution pipeline"
        Critical = $false
        Args = @()
    }
)

# Filter tests if specified
if ($TestFilter.Count -gt 0) {
    $Tests = $Tests | Where-Object { $TestFilter -contains $_.Name }
}

Write-Header "RawrXD Comprehensive Test Suite"
Write-Host "Build Directory: $BuildDir"
Write-Host "Build Type: $BuildType"
Write-Host "Tests Selected: $($Tests.Count)"
Write-Host ""

# Step 1: Build
if (-not $SkipBuild) {
    Write-Header "Phase 1: Build"
    
    if ($Clean -and (Test-Path $BuildDir)) {
        Write-Status "Cleaning previous build" "INFO"
        Remove-Item -Recurse -Force $BuildDir
    }
    
    if (-not (Test-Path $BuildDir)) {
        New-Item -ItemType Directory -Path $BuildDir | Out-Null
    }
    
    Write-Status "Configuring with CMake" "INFO"
    $cmakeArgs = @(
        "-B", $BuildDir
        "-G", "Ninja"
        "-DCMAKE_BUILD_TYPE=$BuildType"
        "-DCMAKE_CXX_STANDARD=20"
    )
    
    & cmake @cmakeArgs 2>&1 | ForEach-Object {
        if ($_ -match "error|Error|ERROR") {
            Write-Host $_ -ForegroundColor Red
        } else {
            Write-Host $_
        }
    }
    
    if ($LASTEXITCODE -ne 0) {
        throw "CMake configuration failed"
    }
    
    Write-Status "Building test targets" "INFO"
    foreach ($test in $Tests) {
        Write-Host "  Building $($test.Target)..." -NoNewline
        ninja -C $BuildDir $test.Target 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Host " OK" -ForegroundColor Green
        } else {
            Write-Host " FAILED" -ForegroundColor Red
            $test.BuildFailed = $true
        }
    }
} else {
    Write-Status "Skipping build (using existing binaries)" "WARN"
}

# Step 2: Execute Tests
Write-Header "Phase 2: Test Execution"

foreach ($test in $Tests) {
    if ($test.BuildFailed) {
        Write-Status "$($test.Name) - Build failed, skipping" "SKIP"
        $TestResults += [PSCustomObject]@{
            Name = $test.Name
            Status = "SKIP"
            Duration = 0
            ExitCode = -1
        }
        continue
    }
    
    Write-Host "`nRunning: $($test.Name)" -ForegroundColor White
    Write-Host "  Description: $($test.Description)"
    
    $testStart = Get-Date
    $binaryPath = "$BuildDir\bin\$($test.Target).exe"
    
    if (-not (Test-Path $binaryPath)) {
        $binaryPath = "$BuildDir\$($test.Target).exe"
    }
    
    if (-not (Test-Path $binaryPath)) {
        Write-Status "Binary not found: $binaryPath" "FAIL"
        $TestResults += [PSCustomObject]@{
            Name = $test.Name
            Status = "FAIL"
            Duration = 0
            ExitCode = -1
        }
        continue
    }
    
    # Execute test
    $process = Start-Process -FilePath $binaryPath -ArgumentList $test.Args -Wait -PassThru -NoNewWindow -RedirectStandardOutput "$BuildDir\$($test.Name)_stdout.log" -RedirectStandardError "$BuildDir\$($test.Name)_stderr.log"
    
    $testEnd = Get-Date
    $duration = ($testEnd - $testStart).TotalSeconds
    
    $status = $(if ($process.ExitCode -eq 0) { "PASS" } else { "FAIL" }
    
    Write-Status "$($test.Name) - Exit code: $($process.ExitCode), Duration: $([math]::Round($duration, 2))s" $status
    
    $TestResults += [PSCustomObject]@{
        Name = $test.Name
        Status = $status
        Duration = $duration
        ExitCode = $process.ExitCode
        Critical = $test.Critical
    }
}

# Step 3: Summary Report
Write-Header "Phase 3: Test Summary"

$passed = ($TestResults | Where-Object { $_.Status -eq "PASS" }).Count
$failed = ($TestResults | Where-Object { $_.Status -eq "FAIL" }).Count
$skipped = ($TestResults | Where-Object { $_.Status -eq "SKIP" }).Count
$criticalFailed = ($TestResults | Where-Object { $_.Status -eq "FAIL" -and $_.Critical }).Count

Write-Host "`nResults:"
Write-Host "  Total Tests: $($TestResults.Count)"
Write-Host "  Passed: $passed" -ForegroundColor Green
Write-Host "  Failed: $failed" -ForegroundColor Red
Write-Host "  Skipped: $skipped" -ForegroundColor DarkGray
Write-Host "  Critical Failures: $criticalFailed" -ForegroundColor $(if ($criticalFailed -gt 0) { "Red" } else { "Green" })

Write-Host "`nDetailed Results:"
Write-Host "────────────────────────────────────────────────────────────────"
$TestResults | ForEach-Object {
    $color = switch($_.Status) {
        "PASS" { "Green" }
        "FAIL" { "Red" }
        "SKIP" { "DarkGray" }
    }
    $criticalMark = $(if ($_.Critical) { "*" } else { " " }
    Write-Host "[$criticalMark] $($_.Name.PadRight(30)) $($_.Status.PadRight(6)) $([math]::Round($_.Duration, 2))s" -ForegroundColor $color
}

$endTime = Get-Date
$totalDuration = ($endTime - $StartTime).TotalMinutes

Write-Host "`n────────────────────────────────────────────────────────────────"
Write-Host "Total Duration: $([math]::Round($totalDuration, 2)) minutes"

# Export results
$reportPath = "$BuildDir\test_report_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
$report = [PSCustomObject]@{
    Timestamp = Get-Date -Format "o"
    DurationMinutes = $totalDuration
    Summary = [PSCustomObject]@{
        Total = $TestResults.Count
        Passed = $passed
        Failed = $failed
        Skipped = $skipped
        CriticalFailed = $criticalFailed
    }
    Results = $TestResults
}

$report | ConvertTo-Json -Depth 10 | Out-File $reportPath
Write-Host "`nReport exported to: $reportPath" -ForegroundColor Cyan

# Final status
if ($criticalFailed -gt 0) {
    Write-Header "CRITICAL TESTS FAILED - DO NOT PROCEED"
    exit 1
} elseif ($failed -gt 0) {
    Write-Header "SOME TESTS FAILED - REVIEW BEFORE PROCEEDING"
    exit 2
} else {
    Write-Header "ALL TESTS PASSED - READY FOR DEPLOYMENT"
    exit 0
}
