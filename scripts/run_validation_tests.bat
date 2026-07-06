@echo off
REM RawrXD-Script Validation Test Runner
REM Runs differential tests, IC invalidation tests, and conformance suite

setlocal EnableDelayedExpansion

echo ============================================
echo RawrXD-Script Validation Test Suite
echo ============================================
echo.

set "BUILD_DIR=%~dp0..\build"
set "TEST_RESULTS=%BUILD_DIR%\test_results"
set "RAWRXD_ROOT=%~dp0..\..\rawrxd"

if not exist "%TEST_RESULTS%" mkdir "%TEST_RESULTS%"

REM Check for test executables
set "DIFFERENTIAL_TEST=%BUILD_DIR%\bin\differential_test.exe"
set "IC_TEST=%BUILD_DIR%\bin\ic_invalidation_test.exe"
set "CONFORMANCE_TEST=%BUILD_DIR%\bin\conformance_test.exe"

set /a TOTAL_TESTS=0
set /a PASSED_TESTS=0
set /a FAILED_TESTS=0

echo [1/3] Running Differential Tests...
echo --------------------------------------------
if exist "%DIFFERENTIAL_TEST%" (
    "%DIFFERENTIAL_TEST%" > "%TEST_RESULTS%\differential.log" 2>&1
    if !ERRORLEVEL! equ 0 (
        echo [PASS] Differential tests completed
        set /a PASSED_TESTS+=1
    ) else (
        echo [FAIL] Differential tests failed (exit code: !ERRORLEVEL!)
        type "%TEST_RESULTS%\differential.log"
        set /a FAILED_TESTS+=1
    )
    set /a TOTAL_TESTS+=1
) else (
    echo [SKIP] Differential test executable not found: %DIFFERENTIAL_TEST%
    echo        Build with: cmake -DRAWRXD_BUILD_TESTS=ON ..
)

echo.
echo [2/3] Running IC Invalidation Tests...
echo --------------------------------------------
if exist "%IC_TEST%" (
    "%IC_TEST%" > "%TEST_RESULTS%\ic_invalidation.log" 2>&1
    if !ERRORLEVEL! equ 0 (
        echo [PASS] IC invalidation tests completed
        set /a PASSED_TESTS+=1
    ) else (
        echo [FAIL] IC invalidation tests failed (exit code: !ERRORLEVEL!)
        type "%TEST_RESULTS%\ic_invalidation.log"
        set /a FAILED_TESTS+=1
    )
    set /a TOTAL_TESTS+=1
) else (
    echo [SKIP] IC invalidation test executable not found: %IC_TEST%
    echo        Build with: cmake -DRAWRXD_BUILD_TESTS=ON ..
)

echo.
echo [3/3] Running Conformance Tests...
echo --------------------------------------------
if exist "%CONFORMANCE_TEST%" (
    "%CONFORMANCE_TEST%" > "%TEST_RESULTS%\conformance.log" 2>&1
    if !ERRORLEVEL! equ 0 (
        echo [PASS] Conformance tests completed
        set /a PASSED_TESTS+=1
    ) else (
        echo [FAIL] Conformance tests failed (exit code: !ERRORLEVEL!)
        type "%TEST_RESULTS%\conformance.log"
        set /a FAILED_TESTS+=1
    )
    set /a TOTAL_TESTS+=1
) else (
    echo [SKIP] Conformance test executable not found: %CONFORMANCE_TEST%
)

echo.
echo ============================================
echo Test Summary
echo ============================================
echo Total:  %TOTAL_TESTS%
echo Passed: %PASSED_TESTS%
echo Failed: %FAILED_TESTS%
echo.

if %FAILED_TESTS% gtr 0 (
    echo Validation FAILED
    exit /b 1
) else (
    echo Validation PASSED
    exit /b 0
)
