@echo off
chcp 65001 > nul
title RawRamXD Kernel-Backed Elastic Curve Benchmark Build
cls

echo ========================================
echo RawRamXD KERNEL-BACKED ELASTIC CURVE
echo Real Windows Kernel Telemetry
echo ========================================
echo.
echo This benchmark uses ACTUAL kernel APIs:
echo   - DXGI QueryVideoMemoryInfo (VRAM residency)
echo   - QueryWorkingSetEx (RAM page residency)
echo   - DeviceIoControl IOCTL_DISK_PERFORMANCE (NVMe I/O)
echo   - ETW tracing (high-res I/O events)
echo.
echo It produces the RAW RAM XD ELASTIC MEMORY CURVE:
echo   TPS = f(VRAM_pressure, RAM_pressure, IO_pressure)
echo.
echo NO SIMULATION - ALL REAL KERNEL DATA
echo.
pause

set "SOURCE1=RawRamXD_KernelTelemetry.cpp"
set "SOURCE2=RawRamXD_ElasticCurveBench.cpp"
set "OUTPUT=RawRamXD_ElasticCurve.exe"
set "BUILD_DIR=build_elastic"

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
echo     Install MinGW-w64 with C++20 support
echo     Or ensure g++.exe is in PATH
pause
exit /b 1

:found
echo     Found: %COMPILER%
echo.

echo [+] Compiling kernel telemetry module...
echo     %SOURCE1%
echo.

%COMPILER% -std=c++20 -O3 -march=native -c %SOURCE1% -o %BUILD_DIR%\telemetry.o ^
    -I. 2>&1

if %ERRORLEVEL% neq 0 (
    echo.
    echo [!] Telemetry compilation failed!
    pause
    exit /b 1
)

echo [+] Compiling elastic curve benchmark...
echo     %SOURCE2%
echo.

%COMPILER% -std=c++20 -O3 -march=native -o %BUILD_DIR%\%OUTPUT% %BUILD_DIR%\telemetry.o %SOURCE2% ^
    -ld3d12 -ldxgi -ldxguid -ltdh -ladvapi32 -lkernel32 -luser32 -lpsapi -lpthread 2>&1

if %ERRORLEVEL% neq 0 (
    echo.
    echo [!] Benchmark compilation failed!
    pause
    exit /b 1
)

echo.
echo [OK] Build successful: %BUILD_DIR%\%OUTPUT%
echo.

echo ========================================
echo Running Kernel-Backed Elastic Curve Benchmark
echo ========================================
echo.
echo This will:
echo   1. Query your GPU via DXGI kernel driver
echo   2. Query VRAM residency via QueryVideoMemoryInfo
echo   3. Query RAM paging via QueryWorkingSetEx
echo   4. Query NVMe I/O via DeviceIoControl
echo   5. Allocate real tensors, trigger real spills
echo   6. Detect TPS collapse points from real data
echo   7. Generate the elastic memory curve equation
echo.
echo WARNING: This uses real system resources!
echo          Ensure you have 20GB+ free space.
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
echo   - elastic_curve_data.csv (raw telemetry)
echo   - elastic_curve_report.txt (analysis)
echo.
echo The elastic curve equation:
echo   TPS = TPS_max / (1 + a*VRAM_p + b*RAM_p + c*IO_p)
echo.
pause