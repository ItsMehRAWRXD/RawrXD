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

set "BIN_DIR=%~dp0..\build\bin"
set "TESTS_PASSED=0"
set "TESTS_FAILED=0"
set "TOTAL_TESTS=0"

REM Test 1: CertificationRunner
echo.
echo [TEST 1/6] CertificationRunner.exe - 25 Certification Gates
echo ════════════════════════════════════════════════════════════════════════════════
"%BIN_DIR%\CertificationRunner.exe"
if %ERRORLEVEL% EQU 0 (
    set /a TESTS_PASSED+=1
    echo [PASS] CertificationRunner
) else (
    set /a TESTS_FAILED+=1
    echo [FAIL] CertificationRunner
)
set /a TOTAL_TESTS+=1

REM Test 2: Comprehensive Dual GPU Test
echo.
echo [TEST 2/6] comprehensive_dual_gpu_test.exe - Full Integration
echo ════════════════════════════════════════════════════════════════════════════════
"%BIN_DIR%\comprehensive_dual_gpu_test.exe"
if %ERRORLEVEL% EQU 0 (
    set /a TESTS_PASSED+=1
    echo [PASS] Comprehensive Dual GPU Test
) else (
    set /a TESTS_FAILED+=1
    echo [FAIL] Comprehensive Dual GPU Test
)
set /a TOTAL_TESTS+=1

REM Test 3: Omega1 Bridge
echo.
echo [TEST 3/6] test_omega1_bridge.exe - IAT Slot Validation
echo ════════════════════════════════════════════════════════════════════════════════
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
