@echo off
REM =============================================================================
REM   RawrXD Test Runner - Batch 4 of 5
REM   Master test runner for all test suites
REM =============================================================================

setlocal EnableDelayedExpansion

set "RAWRXD_HOME=d:\rawrxd"
set "BUILD_DIR=%RAWRXD_HOME%\build"
set "TEST_DIR=%RAWRXD_HOME%\tests"
set "REPORT_DIR=%RAWRXD_HOME%\reports"

set "TEST_FILTER=%1"
if "!TEST_FILTER!"=="" set "TEST_FILTER=all"

set "TOTAL_TESTS=0"
set "PASSED_TESTS=0"
set "FAILED_TESTS=0"

if not exist "%REPORT_DIR%" mkdir "%REPORT_DIR%"

echo =============================================================================
echo   RawrXD Test Runner
echo   Filter: !TEST_FILTER!
echo   Time: %date% %time%
echo =============================================================================
echo.

if /i "!TEST_FILTER!"=="help" goto :help
if /i "!TEST_FILTER!"=="all" goto :run_all
if /i "!TEST_FILTER!"=="unit" goto :run_unit
if /i "!TEST_FILTER!"=="integration" goto :run_integration
if /i "!TEST_FILTER!"=="fuzz" goto :run_fuzz
if /i "!TEST_FILTER!"=="sanitizer" goto :run_sanitizer
if /i "!TEST_FILTER!"=="ci" goto :run_ci

echo Running specific test: !TEST_FILTER!
goto :run_specific

:help
echo Usage: run_tests [filter]
echo.
echo Filters:
echo   all          - Run all tests (default)
echo   unit         - Run unit tests only
echo   integration  - Run integration tests only
echo   fuzz         - Run fuzz tests only
echo   sanitizer    - Run sanitizer tests only
echo   ci           - Run CI test suite
echo   help         - Show this help
echo   [test_name]  - Run specific test by name
echo.
echo Examples:
echo   run_tests              - Run all tests
echo   run_tests unit         - Run only unit tests
echo   run_tests test_assembler - Run specific test
goto :end

:run_all
echo Running all test suites...
echo.
call :run_unit
call :run_integration
call :run_fuzz
call :run_sanitizer
goto :summary

:run_unit
echo =============================================================================
echo   UNIT TESTS
echo =============================================================================
echo.

if exist "%BUILD_DIR%\test_assembler.exe" (
    echo Running assembler unit tests...
    "%BUILD_DIR%\test_assembler.exe"
    if errorlevel 1 (
        echo     FAILED
        set /a FAILED_TESTS+=1
    ) else (
        echo     PASSED
        set /a PASSED_TESTS+=1
    )
    set /a TOTAL_TESTS+=1
    echo.
)

if exist "%BUILD_DIR%\test_linker.exe" (
    echo Running linker unit tests...
    "%BUILD_DIR%\test_linker.exe"
    if errorlevel 1 (
        echo     FAILED
        set /a FAILED_TESTS+=1
    ) else (
        echo     PASSED
        set /a PASSED_TESTS+=1
    )
    set /a TOTAL_TESTS+=1
    echo.
)

if /i "!TEST_FILTER!"=="unit" goto :summary
exit /b 0

:run_integration
echo =============================================================================
echo   INTEGRATION TESTS
echo =============================================================================
echo.

if exist "%BUILD_DIR%\test_pipeline.exe" (
    echo Running pipeline integration tests...
    "%BUILD_DIR%\test_pipeline.exe"
    if errorlevel 1 (
        echo     FAILED
        set /a FAILED_TESTS+=1
    ) else (
        echo     PASSED
        set /a PASSED_TESTS+=1
    )
    set /a TOTAL_TESTS+=1
    echo.
)

if /i "!TEST_FILTER!"=="integration" goto :summary
exit /b 0

:run_fuzz
echo =============================================================================
echo   FUZZ TESTS
echo =============================================================================
echo.

if exist "%BUILD_DIR%\fuzz_assembler.exe" (
    echo Running assembler fuzz tests...
    "%BUILD_DIR%\fuzz_assembler.exe"
    if errorlevel 1 (
        echo     FAILED
        set /a FAILED_TESTS+=1
    ) else (
        echo     PASSED
        set /a PASSED_TESTS+=1
    )
    set /a TOTAL_TESTS+=1
    echo.
)

if /i "!TEST_FILTER!"=="fuzz" goto :summary
exit /b 0

:run_sanitizer
echo =============================================================================
echo   SANITIZER TESTS
echo =============================================================================
echo.

if exist "%BUILD_DIR%\sanitizer_tests.exe" (
    echo Running sanitizer tests...
    "%BUILD_DIR%\sanitizer_tests.exe"
    if errorlevel 1 (
        echo     FAILED
        set /a FAILED_TESTS+=1
    ) else (
        echo     PASSED
        set /a PASSED_TESTS+=1
    )
    set /a TOTAL_TESTS+=1
    echo.
)

if /i "!TEST_FILTER!"=="sanitizer" goto :summary
exit /b 0

:run_ci
echo =============================================================================
echo   CI TEST SUITE
echo =============================================================================
echo.
call :run_unit
call :run_integration
goto :summary

:run_specific
echo Running specific test: !TEST_FILTER!
if exist "%BUILD_DIR%\!TEST_FILTER!.exe" (
    "%BUILD_DIR%\!TEST_FILTER!.exe"
    exit /b %errorlevel%
) else (
    echo Test not found: %BUILD_DIR%\!TEST_FILTER!.exe
    exit /b 1
)

:summary
echo =============================================================================
echo   TEST SUMMARY
echo =============================================================================
echo   Total:  !TOTAL_TESTS!
echo   Passed: !PASSED_TESTS!
echo   Failed: !FAILED_TESTS!
echo =============================================================================

if !FAILED_TESTS! gtr 0 (
    echo   ❌ SOME TESTS FAILED
    echo =============================================================================
    exit /b 1
) else (
    echo   ✅ ALL TESTS PASSED
    echo =============================================================================
    exit /b 0
)

:end
exit /b 0
