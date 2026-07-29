@echo off
REM ===========================================================================
REM build_sovereign_test_suite.bat
REM Builds the SovereignTest_Suite pre-build CI/CD gate
REM ===========================================================================
setlocal enabledelayedexpansion

set "BUILD_DIR=%~dp0build_fix3"
set "SCRIPT_DIR=%~dp0"

echo [*] Building SovereignTest_Suite...

REM Ensure build directory exists
if not exist "%BUILD_DIR%" (
    echo [-] Build directory not found. Run CMake configure first.
    exit /b 1
)

REM Build the test suite target
cmake --build "%BUILD_DIR%" --target SovereignTest_Suite -j4
if %ERRORLEVEL% neq 0 (
    echo [-] SovereignTest_Suite build FAILED
    exit /b %ERRORLEVEL%
)

echo [+] SovereignTest_Suite built successfully
exit /b 0
