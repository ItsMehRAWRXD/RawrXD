@echo off
REM ============================================================================
REM Build Agentic Reasoning Loop
REM ============================================================================
REM Run this from VS Developer Command Prompt (x64 Native Tools)
REM
REM Usage:
REM   build_agentic.bat
REM   build_agentic.bat clean
REM ============================================================================

setlocal enabledelayedexpansion

set SRC_DIR=%~dp0
set BUILD_DIR=%SRC_DIR%\build_agentic
set EXE_NAME=AgenticTest.exe

if "%1"=="clean" (
    echo Cleaning build directory...
    if exist "%BUILD_DIR%" rmdir /S /Q "%BUILD_DIR%"
    echo Clean complete.
    exit /b 0
)

if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

echo ========================================
echo Building Agentic Reasoning Loop
echo ========================================
echo.

REM Compiler flags:
REM /O2          - Maximum optimization (favor speed)
REM /EHsc        - Exception handling (synchronous)
REM /W3          - Warning level 3
REM /Zi          - Debug information
REM /Fe          - Output executable name

set CL_FLAGS=/O2 /EHsc /W3 /Zi /Fe%BUILD_DIR%\%EXE_NAME%

echo Compiling agentic_reasoning_loop.cpp...
cl %CL_FLAGS% %SRC_DIR%\agentic_reasoning_loop.cpp

if errorlevel 1 (
    echo.
    echo [ERROR] Compilation failed!
    exit /b 1
)

echo.
echo ========================================
echo Build successful!
echo ========================================
echo Executable: %BUILD_DIR%\%EXE_NAME%
echo.
echo To run: %BUILD_DIR%\%EXE_NAME%
echo ========================================

endlocal
