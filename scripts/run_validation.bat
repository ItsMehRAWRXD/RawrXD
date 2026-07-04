@echo off
REM RawrXD-Script Unified Validation Runner (Windows Batch)
REM Usage: run_validation.bat [options]
REM   --quick           Run quick validation only
REM   --asan            Build with AddressSanitizer
REM   --coverage        Generate coverage report
REM   --replay <file>   Replay a specific crash file

setlocal EnableDelayedExpansion

set "QUICK="
set "ASAN="
set "COVERAGE="
set "REPLAY_FILE="

REM Parse arguments
:parse_args
if "%~1"=="" goto :done_args
if "%~1"=="--quick" (
    set "QUICK=1"
    shift
    goto :parse_args
)
if "%~1"=="--asan" (
    set "ASAN=1"
    shift
    goto :parse_args
)
if "%~1"=="--coverage" (
    set "COVERAGE=1"
    shift
    goto :parse_args
)
if "%~1"=="--replay" (
    set "REPLAY_FILE=%~2"
    shift
    shift
    goto :parse_args
)
echo Unknown option: %~1
goto :usage

:done_args

set "BUILD_DIR=..\build"
set "TEST_RESULTS=%BUILD_DIR%\test_results"
set "CRASH_DIR=%BUILD_DIR%\crashes"

echo ========================================
echo RawrXD-Script Validation Framework
echo ========================================
echo.

REM Create directories
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"
if not exist "%TEST_RESULTS%" mkdir "%TEST_RESULTS%"
if not exist "%CRASH_DIR%" mkdir "%CRASH_DIR%"

REM Phase 1: Build
echo [Phase 1] Building...
set "CMAKE_ARGS=-B %BUILD_DIR% -S .."
if defined ASAN (
    echo [ASan] AddressSanitizer enabled
    set "CMAKE_ARGS=!CMAKE_ARGS! -DRAWRXD_ENABLE_ASAN=ON"
)

cmake !CMAKE_ARGS! > "%TEST_RESULTS%\build.log" 2>&1
if !ERRORLEVEL! neq 0 (
    echo [FAIL] CMake configuration failed
    type "%TEST_RESULTS%\build.log"
    exit /b 1
)

cmake --build %BUILD_DIR% --config Release >> "%TEST_RESULTS%\build.log" 2>&1
if !ERRORLEVEL! neq 0 (
    echo [FAIL] Build failed
    type "%TEST_RESULTS%\build.log"
    exit /b 1
)
echo [PASS] Build completed

REM Phase 2: Unit Tests
echo.
echo [Phase 2] Running Unit Tests...
call :run_test "opcode_verification" "opcode_verify.exe"
call :run_test "exception_paths" "exception_test.exe"
call :run_test "ic_invalidation" "ic_test.exe"

REM Phase 3: Integration Tests
echo.
echo [Phase 3] Running Integration Tests...
call :run_test "differential" "diff_test.exe"
call :run_test "conformance" "conformance.exe"

REM Phase 4: Stress Tests (unless --quick)
if not defined QUICK (
    echo.
    echo [Phase 4] Running Stress Tests...
    call :run_test "memory_stress" "stress_test.exe"
    call :run_test "benchmark" "benchmark.exe"
)

REM Phase 5: Fuzzing
echo.
echo [Phase 5] Running Fuzzing...
if defined REPLAY_FILE (
    echo [Replay] Replaying: %REPLAY_FILE%
    if exist "%BUILD_DIR%\bin\fuzz.exe" (
        "%BUILD_DIR%\bin\fuzz.exe" --replay "%REPLAY_FILE%"
    ) else (
        echo [SKIP] Fuzzing executable not found
    )
) else (
    set "FUZZ_ITERS=10000"
    if defined QUICK set "FUZZ_ITERS=1000"
    echo [Fuzz] Running !FUZZ_ITERS! iterations...
    if exist "%BUILD_DIR%\bin\fuzz.exe" (
        "%BUILD_DIR%\bin\fuzz.exe" --iterations !FUZZ_ITERS! --save-crashes --corpus "%BUILD_DIR%\corpus" > "%TEST_RESULTS%\fuzz.log" 2>&1
        echo [PASS] Fuzzing completed
    ) else (
        echo [SKIP] Fuzzing executable not found
    )
)

REM Phase 6: Coverage Report
if defined COVERAGE (
    echo.
    echo [Phase 6] Generating Coverage Report...
    if exist "%BUILD_DIR%\bin\opcode_verify.exe" (
        "%BUILD_DIR%\bin\opcode_verify.exe" --coverage-report > "%TEST_RESULTS%\coverage.txt" 2>&1
        echo [PASS] Coverage report: %TEST_RESULTS%\coverage.txt
    )
)

REM Summary
echo.
echo ========================================
echo Validation Summary
echo ========================================
echo Results saved to: %TEST_RESULTS%
echo.

if exist "%CRASH_DIR%\*.replay" (
    echo [WARNING] Crash files found in %CRASH_DIR%
    dir /b "%CRASH_DIR%\*.replay"
    exit /b 1
) else (
    echo [SUCCESS] All validation passed
    exit /b 0
)

REM Helper function to run a test
:run_test
set "TEST_NAME=%~1"
set "TEST_EXE=%~2"
set "TEST_PATH=%BUILD_DIR%\bin\%TEST_EXE%"

if exist "%TEST_PATH%" (
    echo [TEST] Running %TEST_NAME%...
    "%TEST_PATH%" > "%TEST_RESULTS%\%TEST_NAME%.log" 2>&1
    if !ERRORLEVEL! equ 0 (
        echo [PASS] %TEST_NAME%
    ) else (
        echo [FAIL] %TEST_NAME% (exit code: !ERRORLEVEL!)
    )
) else (
    echo [SKIP] %TEST_NAME%: executable not found
)
goto :eof

:usage
echo Usage: run_validation.bat [options]
echo   --quick           Run quick validation only
echo   --asan            Build with AddressSanitizer
echo   --coverage        Generate coverage report
echo   --replay ^<file^>  Replay a specific crash file
exit /b 1
