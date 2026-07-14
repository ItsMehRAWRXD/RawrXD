@echo off
chcp 65001 > nul
title RawRamXD Over-Capacity Benchmark Build
cls

echo ========================================
echo RawRamXD Over-Capacity Benchmark
echo Build Script
echo ========================================
echo.

set "SOURCE=RawRamXD_OverCapacity_Benchmark.cpp"
set "OUTPUT=OverCapacity_Benchmark.exe"
set "BUILD_DIR=build_overcapacity"

if not exist %BUILD_DIR% mkdir %BUILD_DIR%

echo [+] Finding compiler...

set "COMPILER="
where g++.exe > nul 2>&1
if %ERRORLEVEL% == 0 (
    set "COMPILER=g++.exe"
    goto :found_compiler
)

if exist "C:\msys64\mingw64\bin\g++.exe" (
    set "COMPILER=C:\msys64\mingw64\bin\g++.exe"
    goto :found_compiler
)

if exist "C:\Program Files\mingw64\bin\g++.exe" (
    set "COMPILER=C:\Program Files\mingw64\bin\g++.exe"
    goto :found_compiler
)

echo [!] Compiler not found!
echo     Please install MinGW-w64 or add g++ to PATH
exit /b 1

:found_compiler
echo     Found: %COMPILER%
echo.

echo [+] Compiling %SOURCE%...
echo.

%COMPILER% -std=c++20 -O3 -o %BUILD_DIR%\%OUTPUT% %SOURCE% -lpthread 2>&1

if %ERRORLEVEL% neq 0 (
    echo.
    echo [!] Compilation failed!
    exit /b 1
)

echo.
echo [OK] Build successful: %BUILD_DIR%\%OUTPUT%
echo.

echo ========================================
echo Running Over-Capacity Benchmark
echo ========================================
echo.
echo This will test RawRamXD with models exceeding VRAM capacity:
echo   - Baseline: 12GB model (75%% of 16GB VRAM)
echo   - Target:   20GB model (125%% of VRAM)
echo   - Extreme:  48GB model (300%% of VRAM)
echo.
echo Press any key to start...
pause > nul

cd %BUILD_DIR%
.\%OUTPUT%

cd ..

echo.
echo ========================================
echo Benchmark complete!
echo ========================================
echo.
echo Output files:
echo   - overcapacity_latency.csv
echo   - overcapacity_residency.csv
echo   - overcapacity_report.txt
echo.
echo To visualize results, run:
echo   powershell -File Visualize-OverCapacity.ps1
echo.
pause