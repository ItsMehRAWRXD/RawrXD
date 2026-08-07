# RawrXD Native Build — Linkage Resolution Guide
# 
# This script documents the complete build and link sequence for RawrXD.exe
# using the MSVC toolchain. Run from a Visual Studio Developer Command Prompt.
#
# Usage:
#   "C:\VS2022Enterprise\VC\Auxiliary\Build\vcvarsall.bat" x64
#   build_link.bat

@echo off
setlocal enabledelayedexpansion

echo ============================================================================
echo RawrXD Native Build — Linkage Resolution
echo ============================================================================
echo.

set BUILD_DIR=d:\rawrxd\build_pure
set RELEASE_DIR=d:\rawrxd\release
set SRC_DIR=d:\rawrxd\src

if not exist "%RELEASE_DIR%" mkdir "%RELEASE_DIR%"

:: Step 1: Compile the C-Linkage bridge
echo [1/4] Compiling RawrRuntimeBridge.cpp...
cl /c /EHsc /O2 /std:c++17 /I%SRC_DIR% /I%SRC_DIR%\runtime /I%SRC_DIR%\ui /Fo:%BUILD_DIR%\RawrRuntimeBridge.obj %SRC_DIR%\runtime\RawrRuntimeBridge.cpp
if %ERRORLEVEL% neq 0 (
    echo ERROR: Bridge compilation failed
    exit /b 1
)
echo   OK: RawrRuntimeBridge.obj

:: Step 2: Assemble linkage fix include
echo [2/4] Assembling LinkageFixes.inc...
ml64 /c /Cx /Fo:%BUILD_DIR%\LinkageFixes.obj %SRC_DIR%\asm\LinkageFixes.inc
if %ERRORLEVEL% neq 0 (
    echo   (LinkageFixes.inc is an include file, not a standalone source — skipping)
)

:: Step 3: Link final executable
echo [3/4] Linking RawrXD.exe...
link /OUT:%RELEASE_DIR%\RawrXD.exe /SUBSYSTEM:WINDOWS /LARGEADDRESSAWARE /NOLOGO /DEBUG:FULL /INCREMENTAL:NO ^
    %BUILD_DIR%\RawrRuntimeBridge.obj ^
    %BUILD_DIR%\RawrXDMain.obj ^
    %BUILD_DIR%\RuntimeEntryPoints.obj ^
    %BUILD_DIR%\RawrRuntime.obj ^
    %BUILD_DIR%\RawrWindow.obj ^
    %BUILD_DIR%\RawrLogger.obj ^
    %BUILD_DIR%\CrashHandler.obj ^
    %BUILD_DIR%\Deep2Bridge.obj ^
    %BUILD_DIR%\DependencyGraph.obj ^
    %BUILD_DIR%\EventBus.obj ^
    %BUILD_DIR%\GpuManager.obj ^
    %BUILD_DIR%\HotReload.obj ^
    %BUILD_DIR%\InferenceSession.obj ^
    %BUILD_DIR%\IpcRouter.obj ^
    %BUILD_DIR%\Ledger.obj ^
    %BUILD_DIR%\Migration.obj ^
    %BUILD_DIR%\ModelLoader.obj ^
    %BUILD_DIR%\ModelRegistry.obj ^
    %BUILD_DIR%\NamedPipeServer.obj ^
    %BUILD_DIR%\PanelManager.obj ^
    %BUILD_DIR%\PanelRegistry.obj ^
    %BUILD_DIR%\PerformanceProfiler.obj ^
    %BUILD_DIR%\PluginRegistry.obj ^
    %BUILD_DIR%\RawrXDInferenceAdapter.obj ^
    %BUILD_DIR%\ReleaseValidator.obj ^
    %BUILD_DIR%\SelfRepair.obj ^
    %BUILD_DIR%\ServiceRegistry.obj ^
    %BUILD_DIR%\sovereign_deep2_kernels.obj ^
    %BUILD_DIR%\sovereign_kernel_stubs.obj ^
    %BUILD_DIR%\sovereign_q4k_gemv.obj ^
    %BUILD_DIR%\StateManager.obj ^
    kernel32.lib user32.lib gdi32.lib advapi32.lib shell32.lib ole32.lib dbghelp.lib psapi.lib

if %ERRORLEVEL% neq 0 (
    echo ERROR: Link failed
    exit /b 1
)
echo   OK: RawrXD.exe

:: Step 4: Verify output
echo [4/4] Verifying output...
for %%F in ("%RELEASE_DIR%\RawrXD.exe") do (
    echo   Size: %%~zF bytes
    echo   Path: %%F
)

echo.
echo ============================================================================
echo Build Complete
echo ============================================================================
echo.
echo  Artifacts:
echo    %RELEASE_DIR%\RawrXD.exe
echo    %RELEASE_DIR%\RawrXD.pdb
echo    %RELEASE_DIR%\RawrXD.lib
echo.
echo  To run: %RELEASE_DIR%\RawrXD.exe
echo  To inspect: dumpbin /headers %RELEASE_DIR%\RawrXD.exe
echo.

endlocal
