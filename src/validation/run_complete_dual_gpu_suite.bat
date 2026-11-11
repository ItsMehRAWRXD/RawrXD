@echo off
chcp 65001 > nul
setlocal EnableDelayedExpansion

:: ============================================================================
:: RawrXD Complete Dual GPU Test Suite
:: ============================================================================
:: Runs all dual GPU tests including smoke tests, integration tests,
:: and real hardware validation
:: ============================================================================

echo =========================================
echo RawrXD Complete Dual GPU Test Suite
echo =========================================
echo.

set "SUITE_PASSED=0"
set "SUITE_FAILED=0"

:: Test 1: Python Smoke Tests
echo [1/4] Running Python Smoke Tests...
cd /d "%~dp0"
python smoke_dual_gpu.py
if %errorlevel% equ 0 (
    echo   [PASS] Python smoke tests
echo   [PASS] Python smoke tests
    set /a SUITE_PASSED+=1
) else (
    echo   [FAIL] Python smoke tests
    set /a SUITE_FAILED+=1
)

echo.

:: Test 2: Real Hardware Test (if compiled)
echo [2/4] Running Real Hardware Test...
if exist "test_real_dual_gpu.exe" (
    test_real_dual_gpu.exe
    if %errorlevel% equ 0 (
        echo   [PASS] Real hardware test
        set /a SUITE_PASSED+=1
    ) else (
        echo   [FAIL] Real hardware test
        set /a SUITE_FAILED+=1
    )
) else (
    echo   [SKIP] test_real_dual_gpu.exe not built
    echo   [INFO] Build with: cl /std:c++17 /O2 test_real_dual_gpu.cpp /Fe:test_real_dual_gpu.exe
)

echo.

:: Test 3: Integration Test (if compiled)
echo [3/4] Running Integration Tests...
if exist "DualGPUIntegrationTest.exe" (
    DualGPUIntegrationTest.exe
    if %errorlevel% equ 0 (
        echo   [PASS] Integration tests
        set /a SUITE_PASSED+=1
    ) else (
        echo   [FAIL] Integration tests
        set /a SUITE_FAILED+=1
    )
) else (
    echo   [SKIP] DualGPUIntegrationTest.exe not built
    echo   [INFO] Build with: cl /std:c++17 /O2 tests\DualGPUIntegrationTest.cpp /Fe:DualGPUIntegrationTest.exe
)

echo.

:: Test 4: VAL-071 Gate (if compiled)
echo [4/4] Running VAL-071 Dual GPU Gate...
if exist "val071_dual_gpu.exe" (
    val071_dual_gpu.exe
    if %errorlevel% equ 0 (
        echo   [PASS] VAL-071 gate
        set /a SUITE_PASSED+=1
    ) else (
        echo   [FAIL] VAL-071 gate
        set /a SUITE_FAILED+=1
    )
) else (
    echo   [SKIP] val071_dual_gpu.exe not built
    echo   [INFO] Build with: build_dual_gpu.bat
)

echo.
echo =========================================
echo Complete Suite Summary
echo =========================================
echo Tests Passed: %SUITE_PASSED%
echo Tests Failed: %SUITE_FAILED%
echo.

if %SUITE_FAILED% equ 0 (
    echo [SUCCESS] All dual GPU tests completed successfully!
    echo.
    echo Next steps:
    echo   1. Review evidence files
    echo   2. Merge to main: git checkout main ^&^& git merge session_7f014eb4
    echo   3. Tag release: git tag -a v1.0.0 -m "RawrXD v1.0.0"
    echo   4. Deploy to production
    exit /b 0
) else (
    echo [WARNING] %SUITE_FAILED% test(s) had issues
    echo Please review the output above for details.
    exit /b 1
)
