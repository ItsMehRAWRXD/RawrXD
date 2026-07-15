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
echo [+] Setting up Visual C++ environment...

:: Set up paths manually
set "VS_ROOT=C:\Program Files\Microsoft Visual Studio\18\Enterprise"
set "VC_TOOLS=%VS_ROOT%\VC\Tools\MSVC\14.51.36231"
set "WINSDK_ROOT=C:\Program Files (x86)\Windows Kits\10"
set "WINSDK_VER=10.0.22621.0"

:: Add to PATH
set "PATH=%VC_TOOLS%\bin\Hostx64\x64;%PATH%"

:: Set include paths
set "INCLUDE=%VC_TOOLS%\include;%WINSDK_ROOT%\Include\%WINSDK_VER%\ucrt;%WINSDK_ROOT%\Include\%WINSDK_VER%\um;%WINSDK_ROOT%\Include\%WINSDK_VER%\shared;%WINSDK_ROOT%\Include\%WINSDK_VER%\winrt;%WINSDK_ROOT%\Include\%WINSDK_VER%\cppwinrt"

:: Set lib paths
set "LIB=%VC_TOOLS%\lib\x64;%WINSDK_ROOT%\Lib\%WINSDK_VER%\ucrt\x64;%WINSDK_ROOT%\Lib\%WINSDK_VER%\um\x64"

:: Add JsonCpp include path (adjust if needed)
set "INCLUDE=C:\vcpkg\installed\x64-windows\include;%INCLUDE%"
set "LIB=C:\vcpkg\installed\x64-windows\lib;%LIB%"

echo     INCLUDE paths set
echo     LIB paths set

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