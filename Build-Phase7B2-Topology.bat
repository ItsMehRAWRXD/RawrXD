@echo off
chcp 65001 > nul
title RawRamXD Phase 7B.2 - Topology Validated Build
cls

echo ========================================
echo RawRamXD Phase 7B.2: Topology Validated
echo Acceptance Gates F1-F6
echo ========================================
echo.
echo Gates:
echo   [F1] Real GPU enumeration (DXGI identity)
echo   [F2] Real topology graph (PCI link info)
echo   [F3] Peer path validation (measured bandwidth)
echo   [F4] Tensor placement (shard residency map)
echo   [F5] Federated inference (tokens/sec across nodes)
echo   [F6] Migration economics (cost model vs latency)
echo.
echo Output:
echo   - rawramxd_fabric_topology.json
echo   - tensor*_residency.json
echo.
pause

set "SOURCE=RawRamXD_Phase7B2_TopologyValidated.cpp"
set "TEST_SOURCE=RawRamXD_Phase7B2_TopologyTest.cpp"
set "OUTPUT=RawRamXD_Phase7B2_Topology.exe"
set "BUILD_DIR=build_phase7b2_topology"

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
        pause
        exit /b 1
    )
)

echo.
echo [+] Compiling Phase 7B.2 Topology Validated...
echo.

cl.exe /O2 /EHsc /std:c++17 /arch:AVX2 /fp:fast /MD ^
    %SOURCE% %TEST_SOURCE% ^
    d3d12.lib dxgi.lib setupapi.lib cfgmgr32.lib kernel32.lib user32.lib ^
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
echo Running F1-F6 Acceptance Gates
echo ========================================
echo.

cd %BUILD_DIR%
.\%OUTPUT%
cd ..

echo.
echo ========================================
echo Phase 7B.2 Complete!
echo ========================================
echo.
echo Output files:
echo   - %BUILD_DIR%\rawramxd_fabric_topology.json
echo   - %BUILD_DIR%\tensor*_residency.json
echo.
echo Next: Phase 7B.3 - Autonomous Placement Engine
echo.
pause