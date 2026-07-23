@echo off
REM ============================================================================
REM Build Agentic Platform - Autonomous Multi-Agent Reverse Engineering System
REM ============================================================================

setlocal enabledelayedexpansion

echo.
echo ╔══════════════════════════════════════════════════════════════════════╗
echo ║     Build Agentic Reverse Engineering Platform                        ║
echo ║     Autonomous Multi-Agent System with Self-Improvement              ║
echo ╚══════════════════════════════════════════════════════════════════════╝
echo.

set "SRC_DIR=d:\RawrXD\src"
set "BUILD_DIR=d:\RawrXD\build\agentic_platform"
set "INCLUDE_DIR=d:\RawrXD\include"
set "THIRD_PARTY=d:\RawrXD\third_party"

if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"
if not exist "output" mkdir output

set "CXXFLAGS=-std=c++17 -O2 -Wall -I"%SRC_DIR%" -I"%INCLUDE_DIR%" -I"%THIRD_PARTY%" -I"%THIRD_PARTY%\json\include""

echo [1/2] Compiling test harness...
g++.exe %CXXFLAGS% -o "%BUILD_DIR%\AgenticPlatformTest.exe" "%SRC_DIR%\tests\AgenticPlatformTest.cpp" 2>&1
if %ERRORLEVEL% neq 0 (
    echo.
    echo ╔══════════════════════════════════════════════════════════════════════╗
    echo ║     BUILD FAILED!                                                    ║
    echo ╚══════════════════════════════════════════════════════════════════════╝
    echo.
    exit /b 1
)

echo.
echo ╔══════════════════════════════════════════════════════════════════════╗
echo ║     BUILD COMPLETE!                                                   ║
echo ╚══════════════════════════════════════════════════════════════════════╝
echo.
echo Output: %BUILD_DIR%\AgenticPlatformTest.exe
echo.
echo [2/2] Running tests...
echo.
"%BUILD_DIR%\AgenticPlatformTest.exe"

endlocal
