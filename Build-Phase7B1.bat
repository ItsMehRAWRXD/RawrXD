@echo off
chcp 65001 > nul
title RawRamXD Phase 7B.1 - Real Migration Benchmark Build
cls

echo ========================================
echo RawRamXD Phase 7B.1: REAL Migration
echo Production-grade tier migration
echo ========================================
echo.
echo Fixes applied:
echo   [1] DXGI QueryVideoMemoryInfo for real VRAM budget
echo   [2] Handle table for resource tracking
echo   [3] Staging buffer pipeline for cross-tier copies
echo   [4] Direct NVMe I/O with FILE_FLAG_NO_BUFFERING
echo   [5] Valid TPS measurement with migration overhead
echo.
echo This produces the RAW RAM XD ELASTIC MEMORY CURVE:
echo   TPS = f(VRAM_pressure, RAM_pressure, IO_pressure)
echo.
pause

set "SOURCE=RawRamXD_Phase7B1_RealMigration.cpp"
set "OUTPUT=RawRamXD_Phase7B1.exe"
set "BUILD_DIR=build_phase7b1"

if not exist %BUILD_DIR% mkdir %BUILD_DIR%

echo.
echo [+] Finding Visual C++ compiler...

set "VSWHERE=C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe"
set "VCVARS="

if exist "%VSWHERE%" (
    for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
        set "VCVARS=%%i\VC\Auxiliary\Build\vcvars64.bat"
    )
)

if exist "%VCVARS%" (
    echo     Found VS at: %VCVARS%
    call "%VCVARS%" > nul
) else (
    echo     Checking for cl.exe in PATH...
    where cl.exe > nul 2>&1
    if %ERRORLEVEL% neq 0 (
        echo [!] Visual C++ not found!
        echo     Install Visual Studio 2022 with C++ workload
        pause
        exit /b 1
    )
)

echo.
echo [+] Compiling Phase 7B.1 benchmark...
echo     Source: %SOURCE%
echo.

cl.exe /O2 /EHsc /std:c++20 /arch:AVX2 /fp:fast ^
    %SOURCE% ^
    d3d12.lib dxgi.lib kernel32.lib user32.lib advapi32.lib ole32.lib ^
    /Fe:%BUILD_DIR%\%OUTPUT% ^
    /Fo:%BUILD_DIR%\ ^
    /link /SUBSYSTEM:CONSOLE /OPT:REF /OPT:ICF ^
    2>&1

if %ERRORLEVEL% neq 0 (
    echo.
    echo [!] Compilation failed!
    pause
    exit /b 1
)

echo.
echo [OK] Build successful: %BUILD_DIR%\%OUTPUT%
echo.

echo ========================================
echo Running Phase 7B.1 Real Migration Benchmark
echo ========================================
echo.
echo This will:
echo   1. Query real VRAM budget via DXGI
echo   2. Allocate real GPU memory (D3D12)
echo   3. Allocate pinned RAM (VirtualAlloc+VirtualLock)
echo   4. Allocate NVMe storage (direct I/O)
echo   5. Execute real DMA migrations (staging buffers)
echo   6. Measure actual TPS with migration overhead
echo   7. Generate elastic memory curve at 100%%-140%% pressure
echo.
echo WARNING: This uses real system resources!
echo          Ensure you have 25GB+ free space.
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
pause