@echo off
REM ============================================================================
REM build_certify_inference.bat — Build the Inference Certification Tool
REM Links certify_inference_main.cpp against existing RawrXD build artifacts
REM and real MASM kernels.
REM ============================================================================

setlocal enabledelayedexpansion

echo ========================================
echo  Build certify_inference.exe
echo ========================================
echo.

REM Use VS 18 environment
call "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1

REM Paths
set "SRC=D:\rawrxd\src"
set "BUILD=D:\rawrxd\build_pure"
set "BENCH=%~dp0"
set "OUT=%~dp0..\..\build\bin"

if not exist "%OUT%" mkdir "%OUT%"

REM Set include paths
set "MSVC_INC=C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\include"
set "WINSDK_UCRT=C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\ucrt"
set "WINSDK_SHARED=C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\shared"
set "WINSDK_UM=C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\um"
set INCLUDE=%MSVC_INC%;%WINSDK_UCRT%;%WINSDK_SHARED%;%WINSDK_UM%;D:\rawrxd\src

REM Set lib paths
set "MSVC_LIB=C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\lib\x64"
set "WINSDK_UCRT_LIB=C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64"
set "WINSDK_UM_LIB=C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64"
set LIB=%MSVC_LIB%;%WINSDK_UCRT_LIB%;%WINSDK_UM_LIB%

set "CFLAGS=/std:c++17 /O2 /W3 /nologo /EHsc /D_CRT_SECURE_NO_WARNINGS /DWIN32_LEAN_AND_MEAN"

echo Compiling certify_inference_main.cpp...
cl %CFLAGS% /Fe"%OUT%\certify_inference.exe" ^
    "%BENCH%\certify_inference_main.cpp" ^
    "%BUILD%\RawrRuntime.obj" ^
    "%BUILD%\Deep2Bridge.obj" ^
    "%BUILD%\InferenceSession.obj" ^
    "%BUILD%\ModelLoader.obj" ^
    "%BUILD%\ModelRegistry.obj" ^
    "%BUILD%\RawrXDInferenceAdapter.obj" ^
    "%BUILD%\RawrLogger.obj" ^
    "%BUILD%\EventBus.obj" ^
    "%BUILD%\ServiceRegistry.obj" ^
    "%BUILD%\StateManager.obj" ^
    "%BUILD%\GpuManager.obj" ^
    "%BUILD%\sovereign_q4k_gemv.obj" ^
    "%BUILD%\sovereign_deep2_kernels.obj" ^
    "%BUILD%\sovereign_kernel_stubs.obj" ^
    "%BUILD%\PluginRegistry.obj" ^
    "%BUILD%\DependencyGraph.obj" ^
    "%BUILD%\HotReload.obj" ^
    "%BUILD%\CrashHandler.obj" ^
    "%BUILD%\SelfRepair.obj" ^
    "%BUILD%\IpcRouter.obj" ^
    "%BUILD%\NamedPipeServer.obj" ^
    "%BUILD%\Ledger.obj" ^
    "%BUILD%\Migration.obj" ^
    "%BUILD%\PanelManager.obj" ^
    "%BUILD%\RawrWindow.obj" ^
    "%BUILD%\PanelRegistry.obj" ^
    kernel32.lib user32.lib gdi32.lib advapi32.lib shell32.lib ole32.lib dbghelp.lib

if errorlevel 1 (
    echo.
    echo [ERROR] Build failed
    exit /b 1
)

echo.
echo ========================================
echo  Build Complete!
echo  Output: %OUT%\certify_inference.exe
echo ========================================

endlocal
