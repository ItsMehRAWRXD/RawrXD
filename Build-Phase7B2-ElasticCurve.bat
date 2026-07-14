@echo off
:: RawRamXD Phase 7B.2: Elastic Residency Validation Build Script
:: Generates TPS collapse → Residency cost model

setlocal enabledelayedexpansion

echo ============================================
echo RawRamXD Phase 7B.2: Elastic Curve
echo TPS Collapse - Residency Cost Model
echo ============================================
echo.

:: Configuration
set "SRC_DIR=%~dp0"
set "BUILD_DIR=%SRC_DIR%\build"
set "CXX=g++.exe"

:: Compiler flags
set "CXXFLAGS=-std=c++17 -O2 -Wall -Wextra -DUNICODE -D_UNICODE"
set "CXXFLAGS=%CXXFLAGS% -I%SRC_DIR%\include"

:: Linker flags
set "LDFLAGS=-ld3d12 -ldxgi -lkernel32 -luser32 -lpsapi"

:: Create build directory
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

echo Building Phase 7B.2 Elastic Curve Benchmark...
echo.

:: Compile
%CXX% %CXXFLAGS% "%SRC_DIR%\RawRamXD_Phase7B2_ElasticCurve.cpp" "%SRC_DIR%\src\rawramxd\gpu_fabric.cpp" -o "%BUILD_DIR%\RawRamXD_Phase7B2_ElasticCurve.exe" %LDFLAGS%

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
echo Executable: %BUILD_DIR%\RawRamXD_Phase7B2_ElasticCurve.exe
echo.
echo Running validation sweep...
echo.

:: Run benchmark
"%BUILD_DIR%\RawRamXD_Phase7B2_ElasticCurve.exe"

if %ERRORLEVEL% neq 0 (
    echo.
    echo Benchmark failed with error code %ERRORLEVEL%
    exit /b 1
)

echo.
echo ============================================
echo VALIDATION COMPLETE
echo ============================================
echo.
echo Artifacts generated:
echo   - rawramxd_elastic_curve.csv
echo   - phase7b2_elastic_report.md
echo.
echo Next: Phase 7C - Fabric Intelligence
echo.

endlocal
