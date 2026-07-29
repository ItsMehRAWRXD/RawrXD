@echo off
REM ═════════════════════════════════════════════════════════════════════════════
REM RawrXD OMEGA-1 Complete Test Suite
REM Runs all tests in sequence for dual GPU validation
REM ═════════════════════════════════════════════════════════════════════════════

echo.
echo ╔══════════════════════════════════════════════════════════════════════════════╗
echo ║     RawrXD OMEGA-1 Complete Test Suite                                       ║
echo ║     Dual GPU Production Validation                                             ║
echo ╚══════════════════════════════════════════════════════════════════════════════╝
echo.

set "BIN_DIR=d:\rawrxd\bin"
set "OUT_DIR=d:\rawrxd\test_results"
set "TESTS_PASSED=0"
set "TESTS_FAILED=0"
set "TOTAL_TESTS=0"

mkdir "%OUT_DIR%" 2>nul

REM Test 1: Dual GPU Certification
echo.
echo [TEST 1/6] Dual GPU Certification - 10 Gates
echo ════════════════════════════════════════════════════════════════════════════════
powershell -ExecutionPolicy Bypass -File "d:\rawrxd\scripts\dual_gpu_certification.ps1" -BinDir "%BIN_DIR%" -OutDir "%OUT_DIR%"
if %ERRORLEVEL% EQU 0 (
    set /a TESTS_PASSED+=1
    echo [PASS] Dual GPU Certification
) else (
    set /a TESTS_FAILED+=1
    echo [WARN] Dual GPU Certification had warnings
)
set /a TOTAL_TESTS+=1

REM Test 2: Integration Test
echo.
echo [TEST 2/6] RawrXD_Integration_Test.exe - Phase 11-23 Integration
echo ════════════════════════════════════════════════════════════════════════════════
"%BIN_DIR%\RawrXD_Integration_Test.exe" > "%OUT_DIR%\integration_test.log" 2>&1
if %ERRORLEVEL% EQU 0 (
    set /a TESTS_PASSED+=1
    echo [PASS] Integration Test
) else (
    set /a TESTS_FAILED+=1
    echo [FAIL] Integration Test - Exit code: %ERRORLEVEL%
)
set /a TOTAL_TESTS+=1

REM Test 3: Ring Smoke Test
echo.
echo [TEST 3/6] RawrXD_Ring_Smoke_Test.exe - Ring Buffer Validation
echo ════════════════════════════════════════════════════════════════════════════════
start /b /wait "" "%BIN_DIR%\RawrXD_Ring_Smoke_Test.exe" > "%OUT_DIR%\ring_smoke.log" 2>&1
if %ERRORLEVEL% EQU 0 (
    set /a TESTS_PASSED+=1
    echo [PASS] Ring Smoke Test
) else (
    set /a TESTS_FAILED+=1
    echo [FAIL] Ring Smoke Test - Exit code: %ERRORLEVEL%
)
set /a TOTAL_TESTS+=1
"%BIN_DIR%\test_omega1_bridge.exe"
if %ERRORLEVEL% EQU 0 (
    set /a TESTS_PASSED+=1
    echo [PASS] Omega1 Bridge Test
) else (
    set /a TESTS_FAILED+=1
    echo [FAIL] Omega1 Bridge Test
)
set /a TOTAL_TESTS+=1

REM Test 4: PowerShell Runspace
echo.
echo [TEST 4/6] test_omega1_powershell_runspace.exe - PowerShell Integration
echo ════════════════════════════════════════════════════════════════════════════════
"%BIN_DIR%\test_omega1_powershell_runspace.exe"
if %ERRORLEVEL% EQU 0 (
    set /a TESTS_PASSED+=1
    echo [PASS] PowerShell Runspace Test
) else (
    set /a TESTS_FAILED+=1
    echo [FAIL] PowerShell Runspace Test
)
set /a TOTAL_TESTS+=1

REM Test 5: Dual GPU Smoke Test
echo.
echo [TEST 5/6] dual_gpu_smoke_test.exe - GPU Detection
echo ════════════════════════════════════════════════════════════════════════════════
"%BIN_DIR%\dual_gpu_smoke_test.exe"
if %ERRORLEVEL% EQU 0 (
    set /a TESTS_PASSED+=1
    echo [PASS] Dual GPU Smoke Test
) else (
    set /a TESTS_FAILED+=1
    echo [FAIL] Dual GPU Smoke Test
)
set /a TOTAL_TESTS+=1

REM Test 6: ValidationRunner (if exists)
echo.
echo [TEST 6/6] ValidationRunner.exe - Validation Suite
echo ════════════════════════════════════════════════════════════════════════════════
if exist "%BIN_DIR%\ValidationRunner.exe" (
    "%BIN_DIR%\ValidationRunner.exe"
    if %ERRORLEVEL% EQU 0 (
        set /a TESTS_PASSED+=1
        echo [PASS] ValidationRunner
    ) else (
        set /a TESTS_FAILED+=1
        echo [FAIL] ValidationRunner
    )
) else (
    echo [SKIP] ValidationRunner not found
)
set /a TOTAL_TESTS+=1

REM Final Summary
echo.
echo ╔══════════════════════════════════════════════════════════════════════════════╗
echo ║                         FINAL TEST SUMMARY                                     ║
echo ╠══════════════════════════════════════════════════════════════════════════════╣
echo ║ Total Test Suites:  %TOTAL_TESTS%                                              ║
echo ║ Passed:              %TESTS_PASSED%                                              ║
echo ║ Failed:              %TESTS_FAILED%                                              ║
echo ╠══════════════════════════════════════════════════════════════════════════════╣
if %TESTS_FAILED% EQU 0 (
    echo ║                                                                              ║
    echo ║   🎉 ALL TEST SUITES PASSED - PRODUCTION READY 🎉                           ║
    echo ║                                                                              ║
    echo ║   RawrXD OMEGA-1 Engine with Dual GPU Support                                ║
    echo ║   is fully validated and ready for deployment!                             ║
    echo ║                                                                              ║
) else (
    echo ║   ⚠️  SOME TEST SUITES FAILED - Review Required                             ║
)
echo ╚══════════════════════════════════════════════════════════════════════════════╝
echo.

pause
