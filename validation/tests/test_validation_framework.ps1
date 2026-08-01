# RawrXD Validation Framework Test Suite
# Tests the validation components themselves

param(
    [string]$HarnessDir = "..\harness",
    [string]$OutputDir = "test_output",
    [switch]$Verbose
)

$ErrorActionPreference = "Stop"
$script:TestsPassed = 0
$script:TestsFailed = 0
$script:TestResults = @()

function Write-TestHeader($name) {
    Write-Host ""
    Write-Host "TEST: $name" -ForegroundColor Cyan
}

function Write-TestResult($name, $passed, $message) {
    $result = @{
        Name = $name
        Passed = $passed
        Message = $message
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
    $script:TestResults += $result
    
    if ($passed) {
        $script:TestsPassed++
        Write-Host "  ✓ PASS: $message" -ForegroundColor Green
    } else {
        $script:TestsFailed++
        Write-Host "  ✗ FAIL: $message" -ForegroundColor Red
    }
}

function Test-ExecutableExists {
    param($name, $path)
    
    Write-TestHeader "Executable Exists: $name"
    
    $exists = Test-Path $path
    Write-TestResult "ExecutableExists_$name" $exists "Path: $path"
    
    return $exists
}

function Test-ExecutableRuns {
    param($name, $path, $args)
    
    Write-TestHeader "Executable Runs: $name"
    
    try {
        $process = Start-Process -FilePath $path -ArgumentList $args `
            -Wait -PassThru -NoNewWindow -RedirectStandardOutput "test_out.txt" -RedirectStandardError "test_err.txt"
        
        $exitCode = $process.ExitCode
        $success = ($exitCode -eq 0) -or ($exitCode -eq 1)  # 1 is acceptable for some validators
        
        if ($Verbose) {
            Write-Host "  Exit code: $exitCode" -ForegroundColor Gray
            if (Test-Path "test_out.txt") {
                Write-Host "  Output: $(Get-Content "test_out.txt" -Raw)" -ForegroundColor Gray
            }
        }
        
        Write-TestResult "ExecutableRuns_$name" $success "Exit code: $exitCode"
        
        # Cleanup
        Remove-Item "test_out.txt" -ErrorAction SilentlyContinue
        Remove-Item "test_err.txt" -ErrorAction SilentlyContinue
        
        return $success
    } catch {
        Write-TestResult "ExecutableRuns_$name" $false "Exception: $_"
        return $false
    }
}

function Test-JSONOutput {
    param($name, $file)
    
    Write-TestHeader "JSON Output Valid: $name"
    
    if (-not (Test-Path $file)) {
        Write-TestResult "JSONOutput_$name" $false "File not found: $file"
        return $false
    }
    
    try {
        $content = Get-Content $file -Raw
        $json = $content | ConvertFrom-Json
        Write-TestResult "JSONOutput_$name" $true "Valid JSON with $($json.PSObject.Properties.Count) top-level properties"
        return $true
    } catch {
        Write-TestResult "JSONOutput_$name" $false "Invalid JSON: $_"
        return $false
    }
}

function Test-PerformanceTargets {
    param($file)
    
    Write-TestHeader "Performance Targets"
    
    if (-not (Test-Path $file)) {
        Write-TestResult "PerformanceTargets" $false "Benchmark results not found"
        return
    }
    
    $report = Get-Content $file | ConvertFrom-Json
    
    if ($report.performance) {
        $tps = $report.performance.avg_tps
        $latency = $report.performance.avg_latency_ms
        $ttft = $report.performance.avg_ttft_ms
        
        # TPS check
        $tpsPass = $tps -ge 100
        Write-TestResult "Performance_TPS" $tpsPass "TPS: $tps (target: >= 100)"
        
        # Latency check
        $latencyPass = $latency -lt 5000
        Write-TestResult "Performance_Latency" $latencyPass "Latency: $latency ms (target: < 5000)"
        
        # TTFT check
        $ttftPass = $ttft -lt 250
        Write-TestResult "Performance_TTFT" $ttftPass "TTFT: $ttft ms (target: < 250)"
    } else {
        Write-TestResult "PerformanceTargets" $false "No performance data in report"
    }
}

function Test-HardwareDetection {
    param($file)
    
    Write-TestHeader "Hardware Detection"
    
    if (-not (Test-Path $file)) {
        Write-TestResult "HardwareDetection" $false "Hardware report not found"
        return
    }
    
    $report = Get-Content $file | ConvertFrom-Json
    
    # Check GPU count
    $hasGpus = $report.gpu_count -gt 0
    Write-TestResult "Hardware_GPUsFound" $hasGpus "Found $($report.gpu_count) GPU(s)"
    
    # Check for target GPUs
    if ($report.gpus) {
        $r9700 = $report.gpus | Where-Object { $_.is_r9700 }
        $rx7800 = $report.gpus | Where-Object { $_.is_rx7800xt }
        
        Write-TestResult "Hardware_R9700" ($r9700 -ne $null) "R9700: $(if ($r9700) { 'Found' } else { 'Not found' })"
        Write-TestResult "Hardware_RX7800XT" ($rx7800 -ne $null) "RX 7800 XT: $(if ($rx7800) { 'Found' } else { 'Not found' })"
    }
}

# ============================================================================
# Main Test Execution
# ============================================================================

Write-Host "RawrXD Validation Framework Test Suite" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Harness Directory: $HarnessDir" -ForegroundColor Gray
Write-Host "Output Directory: $OutputDir" -ForegroundColor Gray
Write-Host ""

# Create output directory
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

# Test 1: Executables exist
Write-Host "PHASE 1: Executable Verification" -ForegroundColor Yellow
$exeTests = @(
    @{ Name = "ValidationHarness"; Path = "$HarnessDir\ValidationHarness.exe" },
    @{ Name = "HardwareValidator"; Path = "$HarnessDir\HardwareValidator.exe" },
    @{ Name = "RealInferenceBenchmark"; Path = "$HarnessDir\RealInferenceBenchmark.exe" },
    @{ Name = "TelemetryCollector"; Path = "$HarnessDir\TelemetryCollector.exe" }
)

foreach ($test in $exeTests) {
    Test-ExecutableExists -name $test.Name -path $test.Path
}

# Test 2: Hardware validation
Write-Host ""
Write-Host "PHASE 2: Hardware Validation" -ForegroundColor Yellow
$hardwareOutput = Join-Path $OutputDir "test_hardware.json"
if (Test-Path "$HarnessDir\HardwareValidator.exe") {
    Test-ExecutableRuns -name "HardwareValidator" -path "$HarnessDir\HardwareValidator.exe" -args $hardwareOutput
    Test-JSONOutput -name "HardwareReport" -file $hardwareOutput
    Test-HardwareDetection -file $hardwareOutput
}

# Test 3: Telemetry collection (short run)
Write-Host ""
Write-Host "PHASE 3: Telemetry Collection" -ForegroundColor Yellow
$telemetryOutput = Join-Path $OutputDir "test_telemetry.json"
if (Test-Path "$HarnessDir\TelemetryCollector.exe") {
    # Run for only 5 seconds for testing
    $process = Start-Process -FilePath "$HarnessDir\TelemetryCollector.exe" `
        -ArgumentList "--duration", "5", "--interval", "500", "--output", $telemetryOutput `
        -Wait -PassThru -NoNewWindow
    
    Test-JSONOutput -name "TelemetryReport" -file $telemetryOutput
}

# Test 4: Summary
Write-Host ""
Write-Host "======================================" -ForegroundColor Cyan
Write-Host "Test Summary" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan
Write-Host "Tests Passed: $script:TestsPassed" -ForegroundColor Green
Write-Host "Tests Failed: $script:TestsFailed" -ForegroundColor $(if ($script:TestsFailed -gt 0) { "Red" } else { "Green" })
Write-Host "Total Tests: $($script:TestsPassed + $script:TestsFailed)" -ForegroundColor White

# Export results
$resultsFile = Join-Path $OutputDir "test_results.json"
$script:TestResults | ConvertTo-Json -Depth 3 | Out-File $resultsFile
Write-Host ""
Write-Host "Test results exported to: $resultsFile" -ForegroundColor Gray

# Exit code
exit $script:TestsFailed
