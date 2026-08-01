@echo off
REM ===================================================================================
REM HARDENED BUILD ENGINE: RawrXD Exploit Mitigation Compiling Protocol
REM Target: Zero-Surface Standalone Security-Hardened Executable
REM ===================================================================================
setLOCAL EnableDelayedExpansion

echo ================================================================================
echo INITIALIZING HIGH-SECURITY HARDENED PRODUCTION PIPELINE
echo ================================================================================

REM 1. Establish Environment Context
set "VS_PATH=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build"
if exist "!VS_PATH!\vcvars64.bat" (call "!VS_PATH!\vcvars64.bat" >nul)

if not exist "out" mkdir out
if not exist "release" mkdir release

REM 2. Compile MASM x64 Modules
ml64.exe /c /Cx /Zi /Fo out\BackendRegistry.obj src\orchestration\BackendRegistry.asm >nul

REM 3. Compile C++ Translation Units with Exploit Mitigations
REM Flag Breakdown:
REM /GS  - Force buffer security check cookies on stack frames
REM /sdl - Enable additional Security Development Lifecycle recommended checks
REM /guard:cf - Generate Control Flow Guard instrumentation pointers
echo [HARDENING] Injecting compiler cookies and Control Flow Guard tracking...
cl.exe /c /EHsc /O2 /W3 /std:c++17 /GS /sdl /guard:cf /Fo:out\ src\orchestration\BackendConfig.cpp src\orchestration\BackendManager.cpp src\metrics\ProcessorMetrics.cpp src\metrics\GpuMetrics.cpp src\metrics\BackendTelemetry.cpp src\ui\GdiDashboardPainter.cpp >nul

REM 4. Compile Production Resources Descriptor Manifest
rc.exe /v /fo out\RawrXD_Branding.res src\release\RawrXD_Branding.rc >nul

REM 5. Link Final Binary with Hardware-Enforced Safety Allocations
REM Flag Breakdown:
REM /NXCOMPAT  - Enforce Data Execution Prevention (DEP / No-Execute)
REM /HIGHENTROPYVA /DYNAMICBASE - Enable 64-bit Address Space Layout Randomization (ASLR)
REM /GUARD:CF  - Inform linker to perform Control Flow Guard validation passes
echo [HARDENING] Applying DEP, ASLR, and High Entropy VA linker attributes...
link.exe /SUBSYSTEM:WINDOWS /ENTRY:WinMainCRTStartup /NXCOMPAT /DYNAMICBASE /HIGHENTROPYVA /GUARD:CF out\BackendConfig.obj out\BackendManager.obj out\ProcessorMetrics.obj out\GpuMetrics.obj out\BackendTelemetry.obj out\GdiDashboardPainter.obj out\BackendRegistry.obj out\RawrXD_Branding.res /OUT:release\RawrXD.exe >nul

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ================================================================================
    echo SUCCESS: Hardened binary generated at release\RawrXD.exe
    echo ================================================================================
) else (
    echo Linker security configuration pass failed.
    exit /b 1
)
