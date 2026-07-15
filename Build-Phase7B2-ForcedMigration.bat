@echo off
chcp 65001 > nul
echo ============================================
echo RawRamXD Phase 7B.2: Forced Migration
echo Micro-Benchmark - Production Readiness Gate
echo ============================================
echo.

set SOURCE=RawRamXD_Phase7B2_ForcedMigration.cpp
set FABRIC_SRC=src/rawramxd/gpu_fabric.cpp
set OUTPUT=build\RawRamXD_Phase7B2_ForcedMigration.exe

if not exist build mkdir build

echo Building Forced Migration Micro-Benchmark...
echo.

g++ -std=c++17 -O2 -g -Wall -Wextra -I. -Iinclude -DUNICODE -D_UNICODE -DWIN32_LEAN_AND_MEAN -D_AMD64_ -DNDEBUG %SOURCE% %FABRIC_SRC% -o %OUTPUT% -ld3d12 -ldxgi -lpsapi -lkernel32 -ladvapi32 -lgdi32 -luser32 -lsynchronization

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
echo Running forced migration benchmark...
echo This will fill VRAM and force eviction events.
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
