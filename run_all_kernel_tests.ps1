# ============================================================================
# Run All Kernel Validation Tests
# ============================================================================

$ErrorActionPreference = "Stop"

# Colors
$Green = "Green"
$Red = "Red"
$Yellow = "Yellow"
$Cyan = "Cyan"

Write-Host ""
Write-Host "========================================" -ForegroundColor $Cyan
Write-Host "RawrXD Kernel Validation Suite" -ForegroundColor $Cyan
Write-Host "========================================" -ForegroundColor $Cyan
Write-Host ""

$TestsPassed = 0
$TestsFailed = 0

# Test 1: SiLU Activation
Write-Host "[1/5] Running SiLU Activation Test..." -ForegroundColor $Yellow
Set-Location d:\rawrxd-ci-bootstrap\tests\kernels
$Output = .\test_silu_activation.exe 2>&1
$ExitCode = $LASTEXITCODE

if ($ExitCode -eq 0) {
    Write-Host "  ✅ SiLU Activation: PASS" -ForegroundColor $Green
    $TestsPassed++
} else {
    Write-Host "  ❌ SiLU Activation: FAIL" -ForegroundColor $Red
    $TestsFailed++
}
Write-Host "      $Output" -ForegroundColor Gray

# Test 2: Softmax
Write-Host ""
Write-Host "[2/5] Running Softmax Test..." -ForegroundColor $Yellow
Set-Location d:\rawrxd-ci-bootstrap\tests\kernels
$Output = .\test_softmax.exe 2>&1
$ExitCode = $LASTEXITCODE

if ($ExitCode -eq 0) {
    Write-Host "  ✅ Softmax: PASS" -ForegroundColor $Green
    $TestsPassed++
} else {
    Write-Host "  ❌ Softmax: FAIL" -ForegroundColor $Red
    $TestsFailed++
}
Write-Host "      $Output" -ForegroundColor Gray

# Test 3: RMS Normalization
Write-Host ""
Write-Host "[3/5] Running RMS Normalization Test..." -ForegroundColor $Yellow
Set-Location d:\rawrxd-ci-bootstrap\tests\kernels
$Output = .\test_rms_norm.exe 2>&1
$ExitCode = $LASTEXITCODE

if ($ExitCode -eq 0) {
    Write-Host "  ✅ RMS Normalization: PASS" -ForegroundColor $Green
    $TestsPassed++
} else {
    Write-Host "  ❌ RMS Normalization: FAIL" -ForegroundColor $Red
    $TestsFailed++
}
Write-Host "      $Output" -ForegroundColor Gray

# Test 4: Q4_0 Dequantization
Write-Host ""
Write-Host "[4/5] Running Q4_0 Dequantization Test..." -ForegroundColor $Yellow
Set-Location d:\rawrxd-ci-bootstrap\src\validation

# Build if needed
if (-not (Test-Path "q4_0_simple_test.exe")) {
    Write-Host "      Building test..." -ForegroundColor Gray
    powershell -ExecutionPolicy Bypass -File build_and_run.ps1 > $null 2>&1
}

if (Test-Path "q4_0_simple_test.exe") {
    $Output = .\q4_0_simple_test.exe 2>&1
    $ExitCode = $LASTEXITCODE
    
    if ($ExitCode -eq 0) {
        Write-Host "  ✅ Q4_0 Dequantization: PASS" -ForegroundColor $Green
        $TestsPassed++
    } else {
        Write-Host "  ❌ Q4_0 Dequantization: FAIL" -ForegroundColor $Red
        $TestsFailed++
    }
} else {
    Write-Host "  ⚠️  Q4_0 Dequantization: Not built" -ForegroundColor $Yellow
    $TestsFailed++
}

# Test 5: Check Running GUI
Write-Host ""
Write-Host "[5/5] Checking RawrXD GUI Status..." -ForegroundColor $Yellow
$Process = Get-Process | Where-Object { $_.ProcessName -like "*RawrXD*" } | Select-Object -First 1

if ($Process) {
    Write-Host "  ✅ RawrXD GUI: Running (PID $($Process.Id))" -ForegroundColor $Green
    $TestsPassed++
} else {
    Write-Host "  ⚠️  RawrXD GUI: Not running" -ForegroundColor $Yellow
}

# Summary
Write-Host ""
Write-Host "========================================" -ForegroundColor $Cyan
Write-Host "Test Summary" -ForegroundColor $Cyan
Write-Host "========================================" -ForegroundColor $Cyan
Write-Host "Tests Passed: $TestsPassed" -ForegroundColor $Green
Write-Host "Tests Failed: $TestsFailed" -ForegroundColor $(if ($TestsFailed -gt 0) { $Red } else { $Green })
Write-Host ""

if ($TestsFailed -eq 0) {
    Write-Host "✅ ALL KERNELS VALIDATED" -ForegroundColor $Green
    Write-Host "Status: Ready for production" -ForegroundColor $Green
    exit 0
} else {
    Write-Host "❌ SOME TESTS FAILED" -ForegroundColor $Red
    exit 1
}
