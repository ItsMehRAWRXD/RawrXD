@echo off
REM ===================================================================================
REM ENTERPRISE COMPILATION SUITE: RawrXD Production Optimization Build Toolchain
REM Targets: x64 Bare-Metal Win32 Executable Architecture & High-Load Validation Tests
REM ===================================================================================
setLOCAL EnableDelayedExpansion

echo ================================================================================
echo INITIALIZING PRODUCTION BUILD AND COMPILATION PIPELINE
echo ================================================================================

REM 1. MSVC Toolchain Detection Layer
echo [PHASE 1] Scanning host environment for MSVC Build Tools variables...
where cl.exe >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [INFO] Standard paths absent. Attempting fallback structural discovery...
    set "VS_PATH=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build"
    if exist "!VS_PATH!\vcvars64.bat" (
        call "!VS_PATH!\vcvars64.bat" >nul
    ) else (
        echo CRITICAL TOOLCHAIN ERROR: vcvars64.bat setup framework not found.
        echo Please run this pipeline from an authenticated Developer Command Prompt.
        exit /b 1
    )
)
echo Toolchain verified: Microsoft Visual C++ Compiler & Assembler detected.

REM 2. Directory Structure Management
echo.
echo [PHASE 2] Syncing output target workspaces...
if not exist "out" mkdir out
if not exist "release" mkdir release

REM 3. Core Assembly (MASM x64) Kernel Processing Pass
echo.
echo [PHASE 3] Compiling low-overhead x64 assembly vector kernels (ml64)...
ml64.exe /c /Cx /Zi /Fo out\BackendRegistry.obj src\orchestration\BackendRegistry.asm >nul
if %ERRORLEVEL% NEQ 0 (echo MASM Compilation Abort: BackendRegistry.asm && exit /b 1)
echo Assembly Infrastructure Kernel Objects compiled successfully.

REM 4. Compile Component Translation Units (C++)
echo.
echo [PHASE 4] Compiling native C++ backend providers & GDI UI dashboard...
cl.exe /c /EHsc /O2 /W3 /std:c++17 /Fo:out\ src\orchestration\BackendConfig.cpp src\orchestration\BackendManager.cpp src\metrics\ProcessorMetrics.cpp src\metrics\GpuMetrics.cpp src\metrics\BackendTelemetry.cpp src\ui\GdiDashboardPainter.cpp >nul
if %ERRORLEVEL% NEQ 0 (echo C++ Compilation Abort inside core Translation Units && exit /b 1)
echo All native infrastructure translation units mapped cleanly.

REM 5. Compile and Link High-Load Stress Test Harness Binary
echo.
echo [PHASE 5] Assembling and verifying Multi-Threaded Stress Test Suite...
cl.exe /EHsc /std:c++17 /Fo:out\TelemetryStressTest.obj /Fe:out\TelemetryStressTest.exe src\tests\TelemetryStressTest.cpp out\ProcessorMetrics.obj out\GpuMetrics.obj out\BackendTelemetry.obj >nul
if %ERRORLEVEL% NEQ 0 (echo Stress Test Compilation Abort && exit /b 1)
echo Executing Telemetry System Test...
out\TelemetryStressTest.exe
if %ERRORLEVEL% NEQ 0 (echo CRITICAL REGRESSION: Stress verification suite failed verification checks && exit /b 1)

REM 6. Production Executable Compilation and Resource Binding Sequence
echo.
echo [PHASE 6] Compiling production resource descriptors and version metrics...
rc.exe /v /fo out\RawrXD_Branding.res src\release\RawrXD_Branding.rc >nul

echo Linking final production-grade standalone asset binary...
link.exe /SUBSYSTEM:WINDOWS /ENTRY:WinMainCRTStartup out\BackendConfig.obj out\BackendManager.obj out\ProcessorMetrics.obj out\GpuMetrics.obj out\BackendTelemetry.obj out\GdiDashboardPainter.obj out\BackendRegistry.obj out\RawrXD_Branding.res /OUT:release\RawrXD.exe >nul
if %ERRORLEVEL% NEQ 0 (echo Linker Execution Boundary Abort && exit /b 1)

echo.
echo ================================================================================
echo PRODUCTION INTEGRATION COMPLETE: release\RawrXD.exe is online.
echo ================================================================================
exit /b 0
