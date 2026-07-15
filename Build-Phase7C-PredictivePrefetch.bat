@echo off
chcp 65001 > nul
echo ============================================
echo RawRamXD Phase 7C: Predictive Prefetch
echo Autonomous Residency Engine
echo ============================================
echo.

set SOURCE=RawRamXD_Phase7C_PredictivePrefetch.cpp
set PREDICTOR_SRC=src\rawramxd\tensor_predictor.cpp
set FABRIC_SRC=src\rawramxd\gpu_fabric.cpp
set OUTPUT=build\RawRamXD_Phase7C_PredictivePrefetch.exe

if not exist build mkdir build

echo Building Phase 7C Predictive Prefetch Benchmark...
echo.

g++ -std=c++17 -O2 -g -Wall -Wextra -I. -Iinclude -DUNICODE -D_UNICODE -DWIN32_LEAN_AND_MEAN -D_AMD64_ -DNDEBUG %SOURCE% %PREDICTOR_SRC% %FABRIC_SRC% -o %OUTPUT% -ld3d12 -ldxgi -lpsapi -lkernel32 -ladvapi32 -lgdi32 -luser32 -lsynchronization

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
echo Running predictive prefetch benchmark...
echo.

%OUTPUT%

if %ERRORLEVEL% neq 0 (
    echo.
    echo Benchmark failed with error code %ERRORLEVEL%
    exit /b 1
)

echo.
echo ============================================
echo BENCHMARK COMPLETE
echo ============================================
