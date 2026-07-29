@echo off
REM ===========================================================================
REM run_sovereign_test_suite.bat
REM Runs the SovereignTest_Suite pre-build CI/CD gate
REM Returns non-zero on any test failure
REM ===========================================================================
setlocal

set "BUILD_DIR=%~dp0build_fix3"
set "TEST_EXE=%BUILD_DIR%\bin\SovereignTest_Suite.exe"

echo ========================================================
echo  Sovereign Test Suite - Pre-Build CI/CD Gate
echo ========================================================
echo.

if not exist "%TEST_EXE%" (
    echo [-] SovereignTest_Suite.exe not found.
    echo [*] Run build_sovereign_test_suite.bat first.
    exit /b 1
)

REM Run the test suite
"%TEST_EXE%"
set "EXIT_CODE=%ERRORLEVEL%"

echo.
if %EXIT_CODE% equ 0 (
    echo [+] ALL SOVEREIGN TESTS PASSED
) else (
    echo [-] SOVEREIGN TESTS FAILED (exit code: %EXIT_CODE%)
)

exit /b %EXIT_CODE%
