@echo off
setlocal EnableDelayedExpansion

:: RawrXD Stress Test Runner
:: Runs soak, fuzz, and memory stress tests

echo ============================================
echo RawrXD Stress Test Suite
echo ============================================
echo.

set "TEST_DIR=%~dp0"
set "VERBOSE=0"
set "QUICK=0"

:: Parse arguments
for %%a in (%*) do (
    if "%%a"=="--verbose" set VERBOSE=1
    if "%%a"=="--quick" set QUICK=1
    if "%%a"=="-v" set VERBOSE=1
    if "%%a"=="-q" set QUICK=1
)

set "TOTAL_TESTS=0"
set "PASSED_TESTS=0"
set "FAILED_TESTS=0"

echo Running stress tests...
echo.

:: Test 1: Fuzz Test (always run, it's fast)
echo [Fuzz Test - Edge Case Detection]
set /a TOTAL_TESTS+=1
if %VERBOSE%==1 (
    "%~dp0\test_fuzz.exe"
) else (
    "%~dp0\test_fuzz.exe" > nul 2>&1
)
if errorlevel 1 (
    echo   [FAIL] test_fuzz
    set /a FAILED_TESTS+=1
) else (
    echo   [PASS] test_fuzz - 10000 iterations, 0 crashes
    set /a PASSED_TESTS+=1
)
echo.

:: Test 2: Memory Profiler
echo [Memory Profiler - Leak Detection]
set /a TOTAL_TESTS+=1
if %VERBOSE%==1 (
    "%~dp0\test_memory.exe"
) else (
    "%~dp0\test_memory.exe" > nul 2>&1
)
if errorlevel 1 (
    echo   [FAIL] test_memory
    set /a FAILED_TESTS+=1
) else (
    echo   [PASS] test_memory - No leaks detected
    set /a PASSED_TESTS+=1
)
echo.

:: Test 3: Soak Test (skip if --quick)
if %QUICK%==0 (
    echo [Soak Test - Long Running Stability]
    set /a TOTAL_TESTS+=1
    echo   Running 5-minute soak test...
    echo   (Use --quick to skip)
    if %VERBOSE%==1 (
        "%~dp0\test_soak.exe"
    ) else (
        "%~dp0\test_soak.exe" > nul 2>&1
    )
    if errorlevel 1 (
        echo   [FAIL] test_soak
        set /a FAILED_TESTS+=1
    ) else (
        echo   [PASS] test_soak - 5 minutes, no failures
        set /a PASSED_TESTS+=1
    )
    echo.
) else (
    echo [Soak Test - SKIPPED (use --quick)]
    echo.
)

:: Summary
echo ============================================
echo Stress Test Summary
echo ============================================
echo Total Tests:  %TOTAL_TESTS%
echo Passed:       %PASSED_TESTS%
echo Failed:       %FAILED_TESTS%
echo.

if %FAILED_TESTS%==0 (
    echo [OK] All stress tests passed!
    echo.
    echo Stress Testing Complete:
    echo   ✓ Fuzz test: 10000 iterations, 0 crashes
    echo   ✓ Memory test: No leaks detected
    if %QUICK%==0 echo   ✓ Soak test: 5 minutes stable
    exit /b 0
) else (
    echo [FAIL] Some stress tests failed
    exit /b 1
)
