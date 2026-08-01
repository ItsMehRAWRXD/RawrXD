@echo off
REM ===================================================================================
REM ENGINE BUILD: RawrXD Phase 7A Native Engine Kernel
REM Targets: Core.asm + SIMDMath + GpuDevice + ECS + AIRuntime + Engine Main Loop
REM ===================================================================================
setLOCAL EnableDelayedExpansion

echo ================================================================================
echo BUILDING RAWRXD ENGINE KERNEL (Phase 7A)
echo ================================================================================

REM 1. Toolchain
set "VS_PATH=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build"
if exist "!VS_PATH!\vcvars64.bat" (call "!VS_PATH!\vcvars64.bat" >nul) else (
    echo Toolchain not found
    exit /b 1
)

if not exist "out" mkdir out
if not exist "release" mkdir release

REM 2. MASM Core
echo [ASSEMBLY] Core.asm
ml64.exe /c /Cx /Zi /Fo out\Core.obj src\engine\Core.asm >nul
if %ERRORLEVEL% NEQ 0 (echo MASM failed && exit /b 1)

REM 3. C++ Engine Modules
echo [COMPILE] Engine.cpp
cl.exe /c /EHsc /O2 /W3 /std:c++17 /Fo:out\Engine.obj src\engine\Engine.cpp >nul

echo [COMPILE] GpuDevice.cpp
cl.exe /c /EHsc /O2 /W3 /std:c++17 /Fo:out\GpuDevice.obj src\engine\Renderer\GpuDevice.cpp >nul

echo [COMPILE] AIRuntime.cpp
cl.exe /c /EHsc /O2 /W3 /std:c++17 /Fo:out\AIRuntime.obj src\engine\AIRuntime\AIRuntime.cpp >nul

REM 4. Backend Modules
echo [COMPILE] BackendConfig.cpp
cl.exe /c /EHsc /O2 /W3 /std:c++17 /Fo:out\BackendConfig.obj src\orchestration\BackendConfig.cpp >nul

echo [COMPILE] BackendManager.cpp
cl.exe /c /EHsc /O2 /W3 /std:c++17 /Fo:out\BackendManager.obj src\orchestration\BackendManager.cpp >nul

echo [COMPILE] PowerShellDriver.cpp
cl.exe /c /EHsc /O2 /W3 /std:c++17 /Fo:out\PowerShellDriver.obj src\orchestration\PowerShellDriver.cpp >nul

echo [COMPILE] BareMetalDriver.cpp
cl.exe /c /EHsc /O2 /W3 /std:c++17 /Fo:out\BareMetalDriver.obj src\orchestration\BareMetalDriver.cpp >nul

echo [COMPILE] ProcessorMetrics.cpp
cl.exe /c /EHsc /O2 /W3 /std:c++17 /Fo:out\ProcessorMetrics.obj src\metrics\ProcessorMetrics.cpp >nul

echo [COMPILE] GpuMetrics.cpp
cl.exe /c /EHsc /O2 /W3 /std:c++17 /Fo:out\GpuMetrics.obj src\metrics\GpuMetrics.cpp >nul

echo [COMPILE] BackendTelemetry.cpp
cl.exe /c /EHsc /O2 /W3 /std:c++17 /Fo:out\BackendTelemetry.obj src\metrics\BackendTelemetry.cpp >nul

echo [COMPILE] GdiDashboardPainter.cpp
cl.exe /c /EHsc /O2 /W3 /std:c++17 /Fo:out\GdiDashboardPainter.obj src\ui\GdiDashboardPainter.cpp >nul

REM 5. Link Engine + Backend + Telemetry
echo [LINK] RawrXDEngine.exe
link.exe /SUBSYSTEM:CONSOLE /NXCOMPAT /DYNAMICBASE /HIGHENTROPYVA ^
    out\Core.obj ^
    out\Engine.obj ^
    out\GpuDevice.obj ^
    out\AIRuntime.obj ^
    out\BackendConfig.obj ^
    out\BackendManager.obj ^
    out\PowerShellDriver.obj ^
    out\BareMetalDriver.obj ^
    out\ProcessorMetrics.obj ^
    out\GpuMetrics.obj ^
    out\BackendTelemetry.obj ^
    out\GdiDashboardPainter.obj ^
    /OUT:release\RawrXDEngine.exe >nul

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ================================================================================
    echo SUCCESS: release\RawrXDEngine.exe built
    echo ================================================================================
) else (
    echo Linker failed
    exit /b 1
)
