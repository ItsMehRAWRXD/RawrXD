@echo off
REM ============================================================================
REM build_pure.bat — Build Pure Native RawrXD
REM MASM + C++ compilation, linking, resource embedding
REM ============================================================================

setlocal enabledelayedexpansion

echo ========================================
echo  RawrXD Pure Native Build
echo ========================================
echo.

REM Tool paths
set "ML64=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"
set "RC=C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64\rc.exe"

REM Use VS 18 environment for cl and link
call "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1

REM Directories
set "SRC=%~dp0src"
set "BUILD=%~dp0build_pure"
set "RELEASE=%~dp0release"

if not exist "%BUILD%" mkdir "%BUILD%"
if not exist "%RELEASE%" mkdir "%RELEASE%"

REM Set include paths
set "MSVC_INC=C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\include"
set "WINSDK_UCRT=C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\ucrt"
set "WINSDK_SHARED=C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\shared"
set "WINSDK_UM=C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\um"
set INCLUDE=%MSVC_INC%;%WINSDK_UCRT%;%WINSDK_SHARED%;%WINSDK_UM%

REM Set lib paths
set "MSVC_LIB=C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\lib\x64"
set "WINSDK_UCRT_LIB=C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64"
set "WINSDK_UM_LIB=C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64"
set LIB=%MSVC_LIB%;%WINSDK_UCRT_LIB%;%WINSDK_UM_LIB%

set "CFLAGS=/std:c++20 /O2 /W3 /nologo /EHsc /D_CRT_SECURE_NO_WARNINGS /DWIN32_LEAN_AND_MEAN"

echo [1/5] Assembling MASM files...
"%ML64%" /c /nologo /Fo"%BUILD%\RawrXDMain.obj" "%SRC%\native\RawrXDMain.asm"
if errorlevel 1 goto error
echo   [OK] RawrXDMain.asm

"%ML64%" /c /nologo /Fo"%BUILD%\PanelRegistry.obj" "%SRC%\ui\PanelRegistry.asm"
if errorlevel 1 goto error
echo   [OK] PanelRegistry.asm

"%ML64%" /c /nologo /Fo"%BUILD%\sovereign_q4k_gemv.obj" "%SRC%\deep2\sovereign_q4k_gemv.asm"
if errorlevel 1 goto error
echo   [OK] sovereign_q4k_gemv.asm

"%ML64%" /c /nologo /Fo"%BUILD%\sovereign_deep2_kernels.obj" "%SRC%\deep2\sovereign_deep2_kernels.asm"
if errorlevel 1 goto error
echo   [OK] sovereign_deep2_kernels.asm

"%ML64%" /c /nologo /Fo"%BUILD%\sovereign_kernel_stubs.obj" "%SRC%\deep2\sovereign_kernel_stubs.asm"
if errorlevel 1 goto error
echo   [OK] sovereign_kernel_stubs.asm

echo [2/5] Compiling C++ sources...
cl %CFLAGS% /c /Fo"%BUILD%\RawrRuntime.obj" "%SRC%\runtime\RawrRuntime.cpp"
if errorlevel 1 goto error
echo   [OK] RawrRuntime.cpp

cl %CFLAGS% /c /Fo"%BUILD%\ServiceRegistry.obj" "%SRC%\runtime\ServiceRegistry.cpp"
if errorlevel 1 goto error
echo   [OK] ServiceRegistry.cpp

cl %CFLAGS% /c /Fo"%BUILD%\EventBus.obj" "%SRC%\runtime\EventBus.cpp"
if errorlevel 1 goto error
echo   [OK] EventBus.cpp

cl %CFLAGS% /c /Fo"%BUILD%\RawrLogger.obj" "%SRC%\runtime\RawrLogger.cpp"
if errorlevel 1 goto error
echo   [OK] RawrLogger.cpp

cl %CFLAGS% /c /Fo"%BUILD%\Deep2Bridge.obj" "%SRC%\deep2\Deep2Bridge.cpp"
if errorlevel 1 goto error
echo   [OK] Deep2Bridge.cpp

cl %CFLAGS% /c /Fo"%BUILD%\InferenceSession.obj" "%SRC%\deep2\InferenceSession.cpp"
if errorlevel 1 goto error
echo   [OK] InferenceSession.cpp

cl %CFLAGS% /c /Fo"%BUILD%\ModelRegistry.obj" "%SRC%\deep2\ModelRegistry.cpp"
if errorlevel 1 goto error
echo   [OK] ModelRegistry.cpp

cl %CFLAGS% /c /Fo"%BUILD%\PanelManager.obj" "%SRC%\ui\PanelManager.cpp"
if errorlevel 1 goto error
echo   [OK] PanelManager.cpp

cl %CFLAGS% /c /Fo"%BUILD%\RawrWindow.obj" "%SRC%\ui\RawrWindow.cpp"
if errorlevel 1 goto error
echo   [OK] RawrWindow.cpp

cl %CFLAGS% /c /Fo"%BUILD%\StateManager.obj" "%SRC%\state\StateManager.cpp"
if errorlevel 1 goto error
echo   [OK] StateManager.cpp

cl %CFLAGS% /c /Fo"%BUILD%\Ledger.obj" "%SRC%\storage\Ledger.cpp"
if errorlevel 1 goto error
echo   [OK] Ledger.cpp

cl %CFLAGS% /c /Fo"%BUILD%\Migration.obj" "%SRC%\storage\Migration.cpp"
if errorlevel 1 goto error
echo   [OK] Migration.cpp

cl %CFLAGS% /c /Fo"%BUILD%\IpcRouter.obj" "%SRC%\ipc\IpcRouter.cpp"
if errorlevel 1 goto error
echo   [OK] IpcRouter.cpp

cl %CFLAGS% /c /Fo"%BUILD%\NamedPipeServer.obj" "%SRC%\ipc\NamedPipeServer.cpp"
if errorlevel 1 goto error
echo   [OK] NamedPipeServer.cpp

cl %CFLAGS% /c /Fo"%BUILD%\CrashHandler.obj" "%SRC%\recovery\CrashHandler.cpp"
if errorlevel 1 goto error
echo   [OK] CrashHandler.cpp

cl %CFLAGS% /c /Fo"%BUILD%\SelfRepair.obj" "%SRC%\recovery\SelfRepair.cpp"
if errorlevel 1 goto error
echo   [OK] SelfRepair.cpp

cl %CFLAGS% /c /Fo"%BUILD%\PluginRegistry.obj" "%SRC%\plugins\PluginRegistry.cpp"
if errorlevel 1 goto error
echo   [OK] PluginRegistry.cpp

cl %CFLAGS% /c /Fo"%BUILD%\DependencyGraph.obj" "%SRC%\plugins\DependencyGraph.cpp"
if errorlevel 1 goto error
echo   [OK] DependencyGraph.cpp

cl %CFLAGS% /c /Fo"%BUILD%\HotReload.obj" "%SRC%\plugins\HotReload.cpp"
if errorlevel 1 goto error
echo   [OK] HotReload.cpp

cl %CFLAGS% /c /Fo"%BUILD%\PerformanceProfiler.obj" "%SRC%\diagnostics\PerformanceProfilerStub.cpp"
if errorlevel 1 goto error
echo   [OK] PerformanceProfilerStub.cpp

cl %CFLAGS% /c /Fo"%BUILD%\RawrXDInferenceAdapter.obj" "%SRC%\deep2\RawrXDInferenceAdapter.cpp"
if errorlevel 1 goto error
echo   [OK] RawrXDInferenceAdapter.cpp

cl %CFLAGS% /c /Fo"%BUILD%\ModelLoader.obj" "%SRC%\deep2\ModelLoader.cpp"
if errorlevel 1 goto error
echo   [OK] ModelLoader.cpp

cl %CFLAGS% /c /Fo"%BUILD%\GpuManager.obj" "%SRC%\gpu\GpuManager.cpp"
if errorlevel 1 goto error
echo   [OK] GpuManager.cpp

cl %CFLAGS% /c /Fo"%BUILD%\RuntimeEntryPoints.obj" "%SRC%\native\RuntimeEntryPoints.cpp"
if errorlevel 1 goto error
echo   [OK] RuntimeEntryPoints.cpp

echo [3/5] Compiling release validator...
cl %CFLAGS% /c /Fo"%BUILD%\ReleaseValidator.obj" "%SRC%\..\tools\ReleaseValidator.cpp"
if errorlevel 1 goto error
echo   [OK] ReleaseValidator.cpp

echo [4/5] Compiling resources...
if exist "%RC%" (
    "%RC%" /fo"%BUILD%\RawrXD.res" "%RELEASE%\RawrXD.rc" >nul 2>&1
    if exist "%BUILD%\RawrXD.res" (
        echo   [OK] Resources
    ) else (
        echo   [SKIP] RC failed, linking without resources
        set "RESFILE="
    )
) else (
    echo   [SKIP] RC not found
    set "RESFILE="
)

echo [5/5] Linking RawrXD.exe...
set "OBJS=%BUILD%\RawrXDMain.obj %BUILD%\PanelRegistry.obj"
set "OBJS=%OBJS% %BUILD%\RawrRuntime.obj %BUILD%\ServiceRegistry.obj %BUILD%\EventBus.obj %BUILD%\RawrLogger.obj"
set "OBJS=%OBJS% %BUILD%\Deep2Bridge.obj %BUILD%\InferenceSession.obj %BUILD%\ModelRegistry.obj"
set "OBJS=%OBJS% %BUILD%\PanelManager.obj %BUILD%\RawrWindow.obj"
set "OBJS=%OBJS% %BUILD%\StateManager.obj %BUILD%\Ledger.obj %BUILD%\Migration.obj"
set "OBJS=%OBJS% %BUILD%\IpcRouter.obj %BUILD%\NamedPipeServer.obj"
set "OBJS=%OBJS% %BUILD%\CrashHandler.obj %BUILD%\SelfRepair.obj"
set "OBJS=%OBJS% %BUILD%\PluginRegistry.obj %BUILD%\DependencyGraph.obj %BUILD%\HotReload.obj"
set "OBJS=%OBJS% %BUILD%\RawrXDInferenceAdapter.obj %BUILD%\ModelLoader.obj %BUILD%\GpuManager.obj"
set "OBJS=%OBJS% %BUILD%\sovereign_q4k_gemv.obj %BUILD%\sovereign_deep2_kernels.obj %BUILD%\sovereign_kernel_stubs.obj"
set "OBJS=%OBJS% %BUILD%\RuntimeEntryPoints.obj"

link /OUT:"%RELEASE%\RawrXD.exe" /SUBSYSTEM:WINDOWS /LARGEADDRESSAWARE %OBJS% kernel32.lib user32.lib gdi32.lib advapi32.lib shell32.lib ole32.lib dbghelp.lib
if errorlevel 1 goto error
echo   [OK] RawrXD.exe linked

echo.
echo ========================================
echo  Build Complete!
echo  Output: %RELEASE%\RawrXD.exe
echo ========================================
goto end

:error
echo.
echo [ERROR] Build failed at step above.
exit /b 1

:end
endlocal
