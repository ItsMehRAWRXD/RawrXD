@echo off
chcp 65001 > nul
title RawRamXD Phase 7B.2 - Multi-GPU Fabric Federation Build
cls

echo ========================================
echo RawRamXD Phase 7B.2: Multi-GPU Fabric Federation
echo Unified Heterogeneous Memory Scheduler
echo ========================================
echo.
echo Features:
echo   - Multi-GPU enumeration and management
echo   - Peer-to-peer DMA between GPUs
echo   - Fabric federation across nodes
echo   - Unified scheduling policies
echo.
echo Hardware Support:
echo   - AMD Radeon (Infinity Fabric)
echo   - NVIDIA GeForce (NVLink)
echo   - Intel Arc (Direct P2P)
echo   - Cross-vendor bridge fallback
echo.
pause

set "SOURCE=RawRamXD_Phase7B2_MultiGPU_Federation.cpp"
set "TEST_SOURCE=RawRamXD_Phase7B2_Test.cpp"
set "OUTPUT=RawRamXD_Phase7B2.exe"
set "TEST_OUTPUT=RawRamXD_Phase7B2_Test.exe"
set "BUILD_DIR=build_phase7b2"

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
echo [+] Compiling Phase 7B.2 Multi-GPU Federation...
echo     Source: %SOURCE%
echo.

cl.exe /O2 /EHsc /std:c++17 /arch:AVX2 /fp:fast /MD ^
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
echo Running Phase 7B.2 Multi-GPU Federation Test
echo ========================================
echo.
echo This will:
echo   1. Enumerate all GPUs in the system
echo   2. Detect peer-to-peer access capabilities
echo   3. Initialize fabric federation
echo   4. Test unified memory scheduling
echo   5. Demonstrate cross-GPU migration
echo.
echo Detected GPUs:
cd %BUILD_DIR%
.\%OUTPUT%
cd ..

echo.
echo ========================================
echo Phase 7B.2 Complete!
echo ========================================
echo.
echo Next: Run over-capacity benchmark with
echo       multi-GPU federation enabled.
echo.
pause