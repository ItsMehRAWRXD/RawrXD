@echo off
:: RawRamXD GPU Fabric Test Build Script
:: Real implementation - NOT simulated

setlocal enabledelayedexpansion

echo ============================================
echo RawRamXD GPU Fabric Test Build
echo ============================================
echo.

:: Configuration
set "SRC_DIR=%~dp0"
set "BUILD_DIR=%SRC_DIR%\..\..\build"
set "CXX=g++.exe"

:: Compiler flags
set "CXXFLAGS=-std=c++17 -O2 -Wall -Wextra -DUNICODE -D_UNICODE"
set "CXXFLAGS=%CXXFLAGS% -I%SRC_DIR%\..\..\include"

:: Linker flags - Windows-specific
set "LDFLAGS=-ld3d12 -ldxgi -lcuda -lkernel32 -luser32 -ladvapi32"

:: Create build directory
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

echo Building RawRamXD GPU Fabric...
echo.

:: Compile fabric implementation
%CXX% %CXXFLAGS% -c "%SRC_DIR%\..\..\src\rawramxd\gpu_fabric.cpp" -o "%BUILD_DIR%\gpu_fabric.o"
if %ERRORLEVEL% neq 0 (
    echo FAILED: gpu_fabric.cpp compilation
    exit /b 1
)

:: Compile test
echo Building test suite...
%CXX% %CXXFLAGS% "%SRC_DIR%\test_gpu_fabric.cpp" "%BUILD_DIR%\gpu_fabric.o" -o "%BUILD_DIR%\test_gpu_fabric.exe" %LDFLAGS%
if %ERRORLEVEL% neq 0 (
    echo FAILED: test compilation
    exit /b 1
)

echo.
echo ============================================
echo BUILD SUCCESSFUL
echo ============================================
echo.
echo Test executable: %BUILD_DIR%\test_gpu_fabric.exe
echo.
echo Run with:
echo   %BUILD_DIR%\test_gpu_fabric.exe
echo.

endlocal
