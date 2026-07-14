@echo off
chcp 65001 > nul
title RawRamXD Real Hardware Benchmark Build
cls

echo ========================================
echo RawRamXD REAL Over-Capacity Benchmark
echo Hardware-Backed Implementation
echo ========================================
echo.
echo This benchmark uses ACTUAL hardware:
echo   - Real GPU VRAM via DirectX 12
echo   - Real system RAM via VirtualAlloc
echo   - Real NVMe storage via memory-mapped files
echo.
echo It will trigger REAL tier migrations:
echo   VRAM -^> RAM -^> NVMe
echo.
echo And measure REAL performance degradation.
echo.
pause

set "SOURCE=RawRamXD_RealBench.cpp"
set "OUTPUT=RawRamXD_RealBench.exe"
set "BUILD_DIR=build_realbench"

if not exist %BUILD_DIR% mkdir %BUILD_DIR%

echo.
echo [+] Finding compiler...

set "COMPILER="
where g++.exe > nul 2>&1
if %ERRORLEVEL% == 0 (
    set "COMPILER=g++.exe"
    goto :found
)

if exist "C:\msys64\mingw64\bin\g++.exe" (
    set "COMPILER=C:\msys64\mingw64\bin\g++.exe"
    goto :found
)

if exist "C:\Program Files\mingw64\bin\g++.exe" (
    set "COMPILER=C:\Program Files\mingw64\bin\g++.exe"
    goto :found
)

echo [!] Compiler not found!
pause
exit /b 1

:found
echo     Found: %COMPILER%
echo.

echo [+] Compiling %SOURCE%...
echo     Flags: -std=c++20 -O3 -march=native
echo.

%COMPILER% -std=c++20 -O3 -march=native -o %BUILD_DIR%\%OUTPUT% %SOURCE% ^
    -ld3d12 -ldxgi -lkernel32 -luser32 -lpthread 2>&1

if %ERRORLEVEL% neq 0 (
    echo.
    echo [!] Compilation failed!
    echo     Make sure you have MinGW-w64 with C++20 support
    pause
    exit /b 1
)

echo.
echo [OK] Build successful: %BUILD_DIR%\%OUTPUT%
echo.

echo ========================================
echo Running REAL Hardware Benchmark
echo ========================================
echo.
echo This will:
echo   1. Detect your actual GPU and VRAM
echo   2. Detect your system RAM
echo   3. Detect your NVMe storage
echo   4. Allocate a 20GB model across tiers
echo   5. Force VRAM spill to RAM/NVMe
echo   6. Measure real latency and TPS
echo   7. Verify data integrity
echo.
echo WARNING: This will use significant system resources!
echo          Ensure you have 20GB+ free storage space.
echo.
pause

cd %BUILD_DIR%
.\%OUTPUT%

cd ..

echo.
echo ========================================
echo Benchmark complete!
echo ========================================
echo.
echo Output files:
echo   - real_overcapacity_results.csv
echo   - real_overcapacity_report.txt
echo.
echo To analyze results:
echo   python analyze_results.py
echo.
pause