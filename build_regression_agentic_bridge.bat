@echo off
REM ============================================================================
REM build_regression_agentic_bridge.bat
REM Standalone build for Tier-1 Agentic Bridge Regression Test
REM No CMake required — uses cl.exe directly from VS2022 Enterprise
REM ============================================================================

setlocal EnableDelayedExpansion

REM --- Configuration ---
set "SRC=tests\regression_agentic_bridge.cpp"
set "OUT=build\tests\regression_agentic_bridge.exe"
set "LOG=build\tests\regression_agentic_bridge_build.log"

REM --- Find VS2022 Enterprise compiler ---
set "VC_DIR=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717"
set "CL=%VC_DIR%\bin\Hostx64\x64\cl.exe"
set "INCLUDE_DIRS=/I. /Iinclude /Isrc"
set "FLAGS=/std:c++20 /EHsc /O2 /W3 /nologo /Fe:%OUT%"

if not exist "%CL%" (
    echo ERROR: cl.exe not found at %CL%
    echo Please install Visual Studio 2022 Enterprise or update VC_DIR in this script.
    exit /b 1
)

REM --- Ensure output directory exists ---
if not exist "build\tests" mkdir "build\tests"

REM --- Build ---
echo Building regression_agentic_bridge.exe...
echo   Source: %SRC%
echo   Output: %OUT%
echo   Compiler: %CL%
echo.

"%CL%" %FLAGS% %INCLUDE_DIRS% %SRC% 2>"%LOG%"

if %ERRORLEVEL% neq 0 (
    echo FAILED: Build error. See %LOG%
    type "%LOG%"
    exit /b 1
)

echo SUCCESS: Built %OUT%
echo.

REM --- Run the test ---
echo Running regression_agentic_bridge.exe...
echo   Set RAWRXD_TEST_MODEL_PATH to a valid .gguf file for full test.
echo.

set "RAWRXD_PARITY_CPU=1"
"%OUT%"

set "TEST_RESULT=%ERRORLEVEL%"
if %TEST_RESULT% equ 0 (
    echo.
    echo ========================================
    echo REGRESSION TEST PASSED
    echo ========================================
    exit /b 0
) else (
    echo.
    echo ========================================
    echo REGRESSION TEST FAILED (exit code %TEST_RESULT%)
    echo ========================================
    exit /b 1
)
