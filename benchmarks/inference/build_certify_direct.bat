@echo off
setlocal enabledelayedexpansion

REM Build certify_inference.exe with proper VS 18 environment
call "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1

REM Add Windows SDK include paths
set "INCLUDE=!INCLUDE!;C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\shared;C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\um;C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\ucrt"
set "LIB=!LIB!;C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64"

cl /nologo /O2 /EHsc /std:c++17 /Fe:d:\rawrxd-ci-bootstrap\build\bin\certify_inference.exe /ID:\rawrxd\src ^
    d:\rawrxd-ci-bootstrap\benchmarks\inference\certify_inference_main.cpp ^
    d:\rawrxd\build_pure\RawrRuntime.obj ^
    d:\rawrxd\build_pure\Deep2Bridge.obj ^
    d:\rawrxd\build_pure\InferenceSession.obj ^
    d:\rawrxd\build_pure\ModelLoader.obj ^
    d:\rawrxd\build_pure\ModelRegistry.obj ^
    d:\rawrxd\build_pure\RawrXDInferenceAdapter.obj ^
    d:\rawrxd\build_pure\RawrLogger.obj ^
    d:\rawrxd\build_pure\EventBus.obj ^
    d:\rawrxd\build_pure\ServiceRegistry.obj ^
    d:\rawrxd\build_pure\StateManager.obj ^
    d:\rawrxd\build_pure\GpuManager.obj ^
    d:\rawrxd\build_pure\sovereign_q4k_gemv.obj ^
    d:\rawrxd\build_pure\sovereign_deep2_kernels.obj ^
    d:\rawrxd\build_pure\sovereign_kernel_stubs.obj ^
    d:\rawrxd\build_pure\PluginRegistry.obj ^
    d:\rawrxd\build_pure\DependencyGraph.obj ^
    d:\rawrxd\build_pure\HotReload.obj ^
    d:\rawrxd\build_pure\CrashHandler.obj ^
    d:\rawrxd\build_pure\SelfRepair.obj ^
    d:\rawrxd\build_pure\IpcRouter.obj ^
    d:\rawrxd\build_pure\NamedPipeServer.obj ^
    d:\rawrxd\build_pure\Ledger.obj ^
    d:\rawrxd\build_pure\Migration.obj ^
    d:\rawrxd\build_pure\PanelManager.obj ^
    d:\rawrxd\build_pure\RawrWindow.obj ^
    d:\rawrxd\build_pure\PanelRegistry.obj ^
    kernel32.lib user32.lib gdi32.lib advapi32.lib shell32.lib ole32.lib dbghelp.lib

if errorlevel 1 (
    echo Build failed
    exit /b 1
)
echo Build complete: d:\rawrxd-ci-bootstrap\build\bin\certify_inference.exe
