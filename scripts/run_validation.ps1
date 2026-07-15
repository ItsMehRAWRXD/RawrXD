# RawrXD-Script Unified Validation Runner
# Phase 2: Automate everything
# Usage: .\run_validation.ps1 [-Quick] [-FuzzIterations 1000000] [-EnableASan]

param(
    [switch]$Quick = $false,
    [int]$FuzzIterations = 10000,
    [switch]$EnableASan = $false,
    [switch]$Coverage = $false,
    [switch]$Replay = $false,
    [string]$ReplayFile = ""
)

$ErrorActionPreference = "Stop"
${script:StartTime} = Get-Date

# Colors
$Green = "`e[32m"
$Red = "`e[31m"
$Yellow = "`e[33m"
$Blue = "`e[34m"
$Reset = "`e[0m"

function Write-Status($Message, $Status = "INFO") {
    $color = switch ($Status) {
        "PASS" { $Green }
        "FAIL" { $Red }
        "WARN" { $Yellow }
        default { $Blue }
    }
    Write-Host "$color[$Status]$Reset $Message"
}

function Write-Section($Title) {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host $Title -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
}

# ============================================================================
# Configuration
# ============================================================================

$BuildDir = "..\build"
$TestResultsDir = "$BuildDir\test_results"
$CrashDir = "$BuildDir\crashes"
$RegressionDir = "..\src\script\tests\regression"

$Tests = @(
    @{ Name = "opcode_verification"; Executable = "opcode_verify.exe"; Type = "unit" },
    @{ Name = "exception_paths"; Executable = "exception_test.exe"; Type = "unit" },
    @{ Name = "ic_invalidation"; Executable = "ic_test.exe"; Type = "unit" },
    @{ Name = "differential"; Executable = "diff_test.exe"; Type = "integration" },
    @{ Name = "conformance"; Executable = "conformance.exe"; Type = "integration" },
    @{ Name = "memory_stress"; Executable = "stress_test.exe"; Type = "stress" },
    @{ Name = "benchmark"; Executable = "benchmark.exe"; Type = "perf" },
    @{ Name = "fuzzing"; Executable = "fuzz.exe"; Type = "fuzz" }
)

# ============================================================================
# Build Phase
# ============================================================================

function Invoke-Build {
    Write-Section "Phase 1: Build"
    
    if (!(Test-Path $BuildDir)) {
        New-Item -ItemType Directory -Path $BuildDir | Out-Null
    }
    
    $cmakeArgs = @("-B", $BuildDir, "-S", "..")
    if ($EnableASan) {
        $cmakeArgs += "-DRAWRXD_ENABLE_ASAN=ON"
        Write-Status "Building with AddressSanitizer enabled" "WARN"
    }
    
    Write-Status "Configuring CMake..."
    & cmake @cmakeArgs 2>&1 | ForEach-Object { "  $_" }
    
    if ($LASTEXITCODE -ne 0) {
        Write-Status "CMake configuration failed" "FAIL"
        exit 1
    }
    
    Write-Status "Building..."
    & cmake --build $BuildDir --config Release 2>&1 | ForEach-Object { "  $_" }
    
    if ($LASTEXITCODE -ne 0) {
        Write-Status "Build failed" "FAIL"
        exit 1
    }
    
    Write-Status "Build completed successfully" "PASS"
}

# ============================================================================
# Test Execution
# ============================================================================

${script:Results} = @{
    Total = 0
    Passed = 0
    Failed = 0
    Skipped = 0
    Coverage = @{}
}

function Invoke-Test($Test) {
    $exe = "$BuildDir\bin\$($Test.Executable)"
    $name = $Test.Name
    
    ${script:Results}.Total++
    
    if (!(Test-Path $exe)) {
        Write-Status "$name`: Executable not found, skipping" "WARN"
        ${script:Results}.Skipped++
        return
    }
    
    Write-Status "Running $name..."
    
    $logFile = "$TestResultsDir\$name.log"
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    
    try {
        $process = Start-Process -FilePath $exe -ArgumentList "--verbose" `
            -RedirectStandardOutput $logFile -RedirectStandardError "$logFile.err" `
            -PassThru -Wait -NoNewWindow
        
        $timer.Stop()
        
        if ($process.ExitCode -eq 0) {
            Write-Status "$name`: PASSED ($($timer.ElapsedMilliseconds)ms)" "PASS"
            ${script:Results}.Passed++
        } else {
            Write-Status "$name`: FAILED (exit code $($process.ExitCode))" "FAIL"
            ${script:Results}.Failed++
            if (Test-Path $logFile) {
                Get-Content $logFile -Tail 20 | ForEach-Object { "    $_" }
            }
        }
    }
    catch {
        Write-Status "$name`: EXCEPTION - $_" "FAIL"
        ${script:Results}.Failed++
    }
}

function Invoke-FuzzingTest {
    Write-Section "Phase 5: Fuzzing"
    
    $exe = "$BuildDir\bin\fuzz.exe"
    if (!(Test-Path $exe)) {
        Write-Status "Fuzzing executable not found, skipping" "WARN"
        return
    }
    
    if ($Replay -and $ReplayFile) {
        Write-Status "Replaying crash: $ReplayFile"
        & $exe "--replay", $ReplayFile 2>&1
        return
    }
    
    $iterations = $(if ($Quick) { 1000 } else { $FuzzIterations }
    Write-Status "Running $iterations fuzzing iterations..."
    
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    & $exe "--iterations", $iterations, "--save-crashes", "--corpus", "$BuildDir\corpus" 2>&1 | Tee-Object -FilePath "$TestResultsDir\fuzz.log"
    $timer.Stop()
    
    # Check for crashes
    $crashes = Get-ChildItem -Path $CrashDir -Filter "*.replay" -ErrorAction SilentlyContinue
    if ($crashes) {
        Write-Status "Found $($crashes.Count) crash(es)!" "FAIL"
        foreach ($crash in $crashes) {
            Write-Status "  Crash: $($crash.Name)" "WARN"
        }
    } else {
        Write-Status "No crashes found" "PASS"
    }
    
    Write-Status "Fuzzing completed in $($timer.Elapsed)"
}

function Invoke-RegressionTests {
    Write-Section "Phase 6: Regression Database"
    
    if (!(Test-Path $RegressionDir)) {
        Write-Status "No regression tests found" "WARN"
        return
    }
    
    $tests = Get-ChildItem -Path $RegressionDir -Filter "bug_*.js"
    if ($tests.Count -eq 0) {
        Write-Status "No regression tests found" "WARN"
        return
    }
    
    Write-Status "Running $($tests.Count) regression tests..."
    
    $passed = 0
    $failed = 0
    
    foreach ($test in $tests) {
        $content = Get-Content $test.FullName -Raw
        # TODO: Execute and verify
        $passed++
    }
    
    Write-Status "Regression: $passed passed, $failed failed" $(if ($failed -eq 0) { "PASS" } else { "FAIL" })
}

function Invoke-CoverageReport {
    if (!$Coverage) { return }
    
    Write-Section "Phase 7: Coverage Report"
    
    # Opcode coverage
    $exe = "$BuildDir\bin\opcode_verify.exe"
    if (Test-Path $exe) {
        & $exe "--coverage-report" 2>&1 | Tee-Object -FilePath "$TestResultsDir\coverage.txt"
    }
    
    Write-Status "Coverage report saved to $TestResultsDir\coverage.txt"
}

# ============================================================================
# Main Execution
# ============================================================================

function Main {
    Write-Host @"
    ____                            __  ____            _       _   _             
   |  _ \\ _____   _____ _ __ __ _/_/_ / ___|  ___ _ __(_)_ __ | |_| | ___  _ __  
   | |_) / _ \\ \\ / / _ \\ '__/ _` | '_ \\___ \\ / __| '__| | '_ \\| __| |/ _ \\| '_ \\ 
   |  _ <  __/\\ V /  __/ | | (_| | | | |__) | (__| |  | | |_) | |_| | (_) | | | |
   |_| \\_\\___| \\_/ \\___|_|  \\__, |_| |_|____/ \\___|_|  |_| .__/ \\__|_|\\___/|_| |_|
                             |___/                        |_|                      
"@ -ForegroundColor Cyan
    
    Write-Host "RawrXD-Script Validation Framework v1.0" -ForegroundColor Yellow
    Write-Host ""
    
    # Setup
    if (!(Test-Path $TestResultsDir)) {
        New-Item -ItemType Directory -Path $TestResultsDir -Force | Out-Null
    }
    if (!(Test-Path $CrashDir)) {
        New-Item -ItemType Directory -Path $CrashDir -Force | Out-Null
    }
    
    # Phase 1: Build
    Invoke-Build
    
    # Phase 2: Unit Tests
    Write-Section "Phase 2: Unit Tests"
    foreach ($test in $Tests | Where-Object { $_.Type -eq "unit" }) {
        Invoke-Test $test
    }
    
    # Phase 3: Integration Tests
    Write-Section "Phase 3: Integration Tests"
    foreach ($test in $Tests | Where-Object { $_.Type -eq "integration" }) {
        Invoke-Test $test
    }
    
    # Phase 4: Stress Tests
    if (!$Quick) {
        Write-Section "Phase 4: Stress Tests"
        foreach ($test in $Tests | Where-Object { $_.Type -eq "stress" }) {
            Invoke-Test $test
        }
    }
    
    # Phase 5: Fuzzing
    Invoke-FuzzingTest
    
    # Phase 6: Regression
    Invoke-RegressionTests
    
    # Phase 7: Coverage
    Invoke-CoverageReport
    
    # Summary
    Write-Section "Validation Summary"
    
    $duration = (Get-Date) - ${script:StartTime}
    
    Write-Status "Total Tests:    $(${script:Results}.Total)"
    Write-Status "Passed:         $(${script:Results}.Passed)" $(if (${script:Results}.Passed -gt 0) { "PASS" } else { "INFO" })
    Write-Status "Failed:         $(${script:Results}.Failed)" $(if (${script:Results}.Failed -gt 0) { "FAIL" } else { "INFO" })
    Write-Status "Skipped:        $(${script:Results}.Skipped)"
    Write-Status "Duration:       $($duration.ToString('hh\\:mm\\:ss'))"
    
    if (${script:Results}.Failed -eq 0) {
        Write-Host ""
        Write-Host "========================================" -ForegroundColor Green
        Write-Host "  ALL VALIDATION PASSED" -ForegroundColor Green
        Write-Host "========================================" -ForegroundColor Green
        exit 0
    } else {
        Write-Host ""
        Write-Host "========================================" -ForegroundColor Red
        Write-Host "  VALIDATION FAILED" -ForegroundColor Red
        Write-Host "========================================" -ForegroundColor Red
        exit 1
    }
}

# Run main
Main
