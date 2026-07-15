@echo off
:: Phase 7B.2: Elastic Residency Validation Build Script
:: Builds and runs the pressure sweep validation

setlocal enabledelayedexpansion

echo ============================================
echo Phase 7B.2: Elastic Residency Validation
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
set "LDFLAGS=-ld3d12 -ldxgi -lkernel32 -luser32 -ladvapi32"

:: Create build directory
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

echo Building Phase 7B.2 Elastic Residency Validator...
echo.

:: Compile
%CXX% %CXXFLAGS% -c "%SRC_DIR%\src\rawramxd\gpu_fabric.cpp" -o "%BUILD_DIR%\gpu_fabric.o"
if %ERRORLEVEL% neq 0 (
    echo FAILED: gpu_fabric.cpp compilation
    exit /b 1
)

%CXX% %CXXFLAGS% "%SRC_DIR%\Phase7B2_ElasticResidency_Validation.cpp" "%BUILD_DIR%\gpu_fabric.o" -o "%BUILD_DIR%\Phase7B2_ElasticResidency.exe" %LDFLAGS%
if %ERRORLEVEL% neq 0 (
    echo FAILED: Phase7B2 compilation
    exit /b 1
)

echo.
echo ============================================
echo BUILD SUCCESSFUL
echo ============================================
echo.
echo Executable: %BUILD_DIR%\Phase7B2_ElasticResidency.exe
echo.

:: Run validation
echo Running Elastic Residency Validation...
echo This will take approximately 5 minutes.
echo.

"%BUILD_DIR%\Phase7B2_ElasticResidency.exe"

if %ERRORLEVEL% neq 0 (
    echo.
    echo ============================================
    echo VALIDATION FAILED
echo ============================================
    exit /b 1
)

echo.
echo ============================================
echo VALIDATION COMPLETE
echo ============================================
echo.
echo Output files:
echo   - rawramxd_elastic_curve.csv
echo   - rawramxd_telemetry.log
echo.

endlocal
