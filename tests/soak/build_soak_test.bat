@echo off
:: RawrXD Phase 7A: 24-Hour Soak Test Build Script
:: Builds the production-grade soak test harness

setlocal enabledelayedexpansion

echo ============================================
echo RawrXD Phase 7A: Soak Test Build
echo ============================================
echo.

:: Configuration
set "SRC_DIR=%~dp0"
set "BUILD_DIR=%SRC_DIR%\..\..\build"
set "CXX=g++.exe"

:: Compiler flags
set "CXXFLAGS=-std=c++17 -O2 -Wall -Wextra -DUNICODE -D_UNICODE"
set "CXXFLAGS=%CXXFLAGS% -I%SRC_DIR%\..\..\include"
set "CXXFLAGS=%CXXFLAGS% -I%SRC_DIR%\..\..\src\core"

:: Linker flags
set "LDFLAGS=-lpdh -ld3d12 -ldxgi -lkernel32 -luser32 -lshell32"

:: Create build directory
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

:: Source files
set "SOURCES=%SRC_DIR%\main.cpp %SRC_DIR%\soak_test_harness.cpp"
set "OUTPUT=%BUILD_DIR%\soak_test.exe"

echo Building Phase 7A Soak Test Harness...
echo.
echo Compiler: %CXX%
echo Output: %OUTPUT%
echo.

:: Compile
%CXX% %CXXFLAGS% %SOURCES% -o %OUTPUT% %LDFLAGS%

if %ERRORLEVEL% neq 0 (
    echo.
    echo ============================================
    echo BUILD FAILED
    echo ============================================
    exit /b 1
)

echo.
echo ============================================
echo BUILD SUCCESSFUL
echo ============================================
echo.
echo Executable: %OUTPUT%
echo.
echo Usage:
echo   soak_test.exe -d 24 -m model.gguf -o reports
echo.
echo Options:
echo   -d, --duration-hours    Test duration in hours ^(default: 24^)
echo   -w, --warmup-minutes    Warmup period in minutes ^(default: 5^)
echo   -m, --model             Path to GGUF model to test
echo   -o, --output            Output directory ^(default: soak_reports^)
echo   -f, --fault-injection   Enable fault injection testing
echo.

endlocal
