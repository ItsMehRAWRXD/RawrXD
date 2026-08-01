@echo off
REM ===================================================================================
REM HARDENED BUILD: RawrXD Phase 7A with exploit mitigations
REM ===================================================================================
setLOCAL EnableDelayedExpansion

set "MINGW_PATH=C:\ProgramData\mingw64\mingw64\bin"
set "PATH=%MINGW_PATH%;%PATH%"

echo ================================================================================
echo BUILDING HARDENED RAWRXD ENGINE
echo ================================================================================

if not exist "out" mkdir out
if not exist "release" mkdir release

REM Compile all modules
echo [COMPILE] EngineMain.cpp
g++ -c -std=c++17 -O2 -Isrc -Isrc\engine -Isrc\orchestration -Isrc\metrics -Isrc\ui -Isrc\security -o out\EngineMain.o src\engine\EngineMain.cpp
if %ERRORLEVEL% NEQ 0 exit /b 1

echo [COMPILE] Engine.cpp
g++ -c -std=c++17 -O2 -Isrc -Isrc\engine -Isrc\orchestration -Isrc\metrics -Isrc\ui -Isrc\security -o out\Engine.o src\engine\Engine.cpp
if %ERRORLEVEL% NEQ 0 exit /b 1

echo [COMPILE] GpuDevice.cpp
g++ -c -std=c++17 -O2 -Isrc -Isrc\engine -Isrc\orchestration -Isrc\metrics -Isrc\ui -Isrc\security -o out\GpuDevice.o src\engine\Renderer\GpuDevice.cpp
if %ERRORLEVEL% NEQ 0 exit /b 1

echo [COMPILE] AIRuntime.cpp
g++ -c -std=c++17 -O2 -Isrc -Isrc\engine -Isrc\orchestration -Isrc\metrics -Isrc\ui -Isrc\security -o out\AIRuntime.o src\engine\AIRuntime\AIRuntime.cpp
if %ERRORLEVEL% NEQ 0 exit /b 1

echo [COMPILE] BackendConfig.cpp
g++ -c -std=c++17 -O2 -Isrc -Isrc\engine -Isrc\orchestration -Isrc\metrics -Isrc\ui -Isrc\security -o out\BackendConfig.o src\orchestration\BackendConfig.cpp
if %ERRORLEVEL% NEQ 0 exit /b 1

echo [COMPILE] BackendFactory.cpp
g++ -c -std=c++17 -O2 -Isrc -Isrc\engine -Isrc\orchestration -Isrc\metrics -Isrc\ui -Isrc\security -o out\BackendFactory.o src\orchestration\BackendFactory.cpp
if %ERRORLEVEL% NEQ 0 exit /b 1

echo [COMPILE] BackendManager.cpp
g++ -c -std=c++17 -O2 -Isrc -Isrc\engine -Isrc\orchestration -Isrc\metrics -Isrc\ui -Isrc\security -o out\BackendManager.o src\orchestration\BackendManager.cpp
if %ERRORLEVEL% NEQ 0 exit /b 1

echo [COMPILE] PowerShellDriver.cpp
g++ -c -std=c++17 -O2 -Isrc -Isrc\engine -Isrc\orchestration -Isrc\metrics -Isrc\ui -Isrc\security -o out\PowerShellDriver.o src\orchestration\PowerShellDriver.cpp
if %ERRORLEVEL% NEQ 0 exit /b 1

echo [COMPILE] BareMetalDriver.cpp
g++ -c -std=c++17 -O2 -Isrc -Isrc\engine -Isrc\orchestration -Isrc\metrics -Isrc\ui -Isrc\security -o out\BareMetalDriver.o src\orchestration\BareMetalDriver.cpp
if %ERRORLEVEL% NEQ 0 exit /b 1

echo [COMPILE] ProcessorMetrics.cpp
g++ -c -std=c++17 -O2 -Isrc -Isrc\engine -Isrc\orchestration -Isrc\metrics -Isrc\ui -Isrc\security -o out\ProcessorMetrics.o src\metrics\ProcessorMetrics.cpp
if %ERRORLEVEL% NEQ 0 exit /b 1

echo [COMPILE] GpuMetrics.cpp
g++ -c -std=c++17 -O2 -Isrc -Isrc\engine -Isrc\orchestration -Isrc\metrics -Isrc\ui -Isrc\security -o out\GpuMetrics.o src\metrics\GpuMetrics.cpp
if %ERRORLEVEL% NEQ 0 exit /b 1

echo [COMPILE] BackendTelemetry.cpp
g++ -c -std=c++17 -O2 -Isrc -Isrc\engine -Isrc\orchestration -Isrc\metrics -Isrc\ui -Isrc\security -o out\BackendTelemetry.o src\metrics\BackendTelemetry.cpp
if %ERRORLEVEL% NEQ 0 exit /b 1

echo [COMPILE] GdiDashboardPainter.cpp
g++ -c -std=c++17 -O2 -Isrc -Isrc\engine -Isrc\orchestration -Isrc\metrics -Isrc\ui -Isrc\security -o out\GdiDashboardPainter.o src\ui\GdiDashboardPainter.cpp
if %ERRORLEVEL% NEQ 0 exit /b 1

REM Assemble MASM modules
echo [ASSEMBLY] BackendRegistry.asm
C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe /c /Cx /Zi /Fo out\BackendRegistry.obj src\orchestration\BackendRegistry.asm
if %ERRORLEVEL% NEQ 0 exit /b 1

echo [ASSEMBLY] Core.asm
C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe /c /Cx /Zi /Fo out\Core.obj src\engine\Core.asm
if %ERRORLEVEL% NEQ 0 exit /b 1

REM Link hardened binary
echo [LINK] RawrXD_Hardened.exe
g++ -o release\RawrXD_Hardened.exe ^
    out\EngineMain.o out\Engine.o out\GpuDevice.o out\AIRuntime.o ^
    out\BackendConfig.o out\BackendFactory.o out\BackendManager.o ^
    out\PowerShellDriver.o out\BareMetalDriver.o ^
    out\ProcessorMetrics.o out\GpuMetrics.o out\BackendTelemetry.o ^
    out\GdiDashboardPainter.o out\BackendRegistry.obj out\Core.obj ^
    -lwinmm -ldxgi -ld3d11 -lgdi32 -static -mconsole ^
    -fstack-protector-strong -Wl,-nxcompat -Wl,-dynamicbase -Wl,-high-entropy-va

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ================================================================================
    echo SUCCESS: release\RawrXD_Hardened.exe built with exploit mitigations
    echo ================================================================================
) else (
    echo Linker failed
    exit /b 1
)
