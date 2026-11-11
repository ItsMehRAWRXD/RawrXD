@echo off
REM ============================================================================
REM Run-MeasurementFramework.bat
REM Automated execution of measurement framework
REM ============================================================================

setlocal EnableDelayedExpansion

set "BUILD_CONFIG=Release"
set "BUILD_DIR=build"
set "OUTPUT_DIR=reports"

if "%~1"=="--help" goto :help
if "%~1"=="-h" goto :help

:parse_args
if "%~1"=="--debug" (
    set "BUILD_CONFIG=Debug"
    shift
    goto :parse_args
)
if "%~1"=="--skip-build" (
    set "SKIP_BUILD=1"
    shift
    goto :parse_args
)
if "%~1"=="--skip-slow" (
    set "SKIP_SLOW=1"
    shift
    goto :parse_args
)

REM ============================================================================
REM Header
REM ============================================================================
echo.
echo ==============================================================================
echo RawrXD Measurement Framework
echo ==============================================================================
echo Build Config: %BUILD_CONFIG%
echo.

REM ============================================================================
REM Create output directory
REM ============================================================================
if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"

for /f "tokens=2-4 delims=/ " %%a in ('date /t') do (set mydate=%%c-%%a-%%b)
for /f "tokens=1-2 delims=/:" %%a in ('time /t') do (set mytime=%%a-%%b)
set "REPORT_FILE=%OUTPUT_DIR%\measurement_report_%mydate%_%mytime%.md"

REM ============================================================================
REM Build
REM ============================================================================
if not defined SKIP_BUILD (
    echo [BUILD] Building measurement tests...
    
    call :build_test benchmark_dispatch_overhead
    call :build_test benchmark_planner_amortization
    call :build_test validate_end_to_end
    call :build_test nevm_determinism_validation
    
    if not defined SKIP_SLOW (
        call :build_test nevm_stress_test
    )
    
    echo.
)

REM ============================================================================
REM Run Tests
REM ============================================================================
echo [RUN] Starting measurement tests...
echo.

set "PASSED=0"
set "FAILED=0"

REM Test 1: Dispatch Overhead
call :run_test "benchmark_dispatch_overhead" "Dispatch Overhead"

REM Test 2: Planner Amortization
call :run_test "benchmark_planner_amortization" "Planner Amortization"

REM Test 3: End-to-End Validation
call :run_test "validate_end_to_end" "End-to-End (4 Gates)"

REM Test 4: Determinism
call :run_test "nevm_determinism_validation" "Determinism"

REM Test 5: Stress Test (optional)
if not defined SKIP_SLOW (
    call :run_test "nevm_stress_test" "Stress Test (100K tokens)"
) else (
    echo [SKIP] Stress Test (use --skip-slow to run)
)

REM ============================================================================
REM Summary
REM ============================================================================
echo.
echo ==============================================================================
echo Measurement Framework Complete
echo ==============================================================================
echo Total Tests: %TOTAL%
echo Passed: %PASSED%
echo Failed: %FAILED%
echo Report: %REPORT_FILE%
echo.

if %FAILED% GTR 0 (
    echo FAILED: %FAILED% test(s) failed
    exit /b 1
) else (
    echo SUCCESS: All tests passed
    exit /b 0
)

REM ============================================================================
REM Subroutines
REM ============================================================================

:build_test
set "TEST_NAME=%~1"
echo   Building %TEST_NAME%... 
cmake --build %BUILD_DIR% --config %BUILD_CONFIG% --target %TEST_NAME% >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo OK
) else (
    echo FAILED
    exit /b 1
)
goto :eof

:run_test
set "TEST_EXE=%~1"
set "TEST_DESC=%~2"
set /a "TOTAL+=1"

echo [%TOTAL%] Running %TEST_DESC%...

set "START_TIME=%TIME%"
"%BUILD_DIR%\bin\%BUILD_CONFIG%\%TEST_EXE%.exe" > "%OUTPUT_DIR%\%TEST_EXE%.log" 2>&1
set "EXIT_CODE=%ERRORLEVEL%"
set "END_TIME=%TIME%"

if %EXIT_CODE% EQU 0 (
    echo   [PASS] %TEST_DESC%
    set /a "PASSED+=1"
) else (
    echo   [FAIL] %TEST_DESC% (exit: %EXIT_CODE%)
    set /a "FAILED+=1"
)

goto :eof

:help
echo Usage: run-measurement-framework.bat [options]
echo.
echo Options:
echo   --debug         Use Debug configuration (default: Release)
echo   --skip-build    Skip building tests
echo   --skip-slow     Skip slow tests (stress test)
echo   -h, --help      Show this help
echo.
exit /b 0
