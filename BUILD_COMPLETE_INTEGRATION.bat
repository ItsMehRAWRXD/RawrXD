@echo off
chcp 65001 > nul
setlocal EnableDelayedExpansion

echo ================================================================================
echo RawrXD Complete Integration - SwarmV29 + Sovereign + Heap Patch
echo ================================================================================
echo.

set "ML64=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"
set "LINK=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe"
set "LIB1=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\lib\x64"
set "LIB2=C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64"
set "LIB3=C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64"

set "ROOT=d:\rawrxd"
set "ASM=%ROOT%\src\asm"
set "OUT=%ROOT%\build\final"
set "SOV=d:\sovereign_build"
set "PATCH=%ROOT%\compilers\native_toolchain\sovereign_memory_patch_fixed.obj"

if not exist "%OUT%" mkdir "%OUT%"

echo [1/5] Verifying components...
echo   SwarmV29: %OUT%\SwarmV29_*.obj
echo   Sovereign: %SOV%\*.obj
echo   Heap Patch: %PATCH%
echo.

if not exist "%ML64%" (
    echo ERROR: ml64.exe not found
    exit /b 1
)
if not exist "%LINK%" (
    echo ERROR: link.exe not found
    exit /b 1
)
echo   OK: Toolchain ready

if not exist "%PATCH%" (
    echo ERROR: Heap patch not found
    exit /b 1
)
echo   OK: Heap patch ready

echo.
echo [2/5] Checking SwarmV29 modules...
set SWARMV29_COUNT=0
for %%f in ("%OUT%\SwarmV29_*.obj") do set /a SWARMV29_COUNT+=1
if %SWARMV29_COUNT% lss 10 (
    echo   WARNING: Only %SWARMV29_COUNT% SwarmV29 modules found
    echo   Recompiling...
    cd /d "%ASM%"
    "%ML64%" /c /nologo /Zi SwarmV29_Renderer_State_Cache.asm
    "%ML64%" /c /nologo /Zi SwarmV29_Pipeline_Controller.asm
    "%ML64%" /c /nologo /Zi SwarmV29_NTT_Butterfly.asm
    "%ML64%" /c /nologo /Zi SwarmV29_INTT_Butterfly.asm
    "%ML64%" /c /nologo /Zi SwarmV29_Persistent_Buffer.asm
    "%ML64%" /c /nologo /Zi SwarmV29_Renderer_VTable.asm
    "%ML64%" /c /nologo /Zi SwarmV29_Audit.asm
    "%ML64%" /c /nologo /Zi SwarmV29_VTable_Binding.asm
    "%ML64%" /c /nologo /Zi SwarmV29_Benchmark_Harness.asm
    "%ML64%" /c /nologo /Zi SwarmV29_Verification.asm
    move /Y SwarmV29_*.obj "%OUT%\"
)
echo   OK: %SWARMV29_COUNT% SwarmV29 modules ready

echo.
echo [3/5] Checking Sovereign objects...
set SOV_COUNT=0
for %%f in ("%SOV%\*.obj") do set /a SOV_COUNT+=1
if %SOV_COUNT% lss 8 (
    echo   WARNING: Only %SOV_COUNT% Sovereign objects found
)
echo   OK: %SOV_COUNT% Sovereign objects ready

echo.
echo [4/5] Linking complete integration...

set "LIB_PATHS=/LIBPATH:\"%LIB1%\" /LIBPATH:\"%LIB2%\" /LIBPATH:\"%LIB3%\""

"%LINK%" /NOLOGO /OUT:"%OUT%\RawrXD_Complete.exe" ^
    "%OUT%\SwarmV29_Minimal_Entry.obj" ^
    "%OUT%\SwarmV29_Renderer_State_Cache.obj" ^
    "%OUT%\SwarmV29_Pipeline_Controller.obj" ^
    "%OUT%\SwarmV29_NTT_Butterfly.obj" ^
    "%OUT%\SwarmV29_INTT_Butterfly.obj" ^
    "%OUT%\SwarmV29_Persistent_Buffer.obj" ^
    "%OUT%\SwarmV29_Renderer_VTable.obj" ^
    "%OUT%\SwarmV29_Audit.obj" ^
    "%OUT%\SwarmV29_VTable_Binding.obj" ^
    "%OUT%\SwarmV29_Benchmark_Harness.obj" ^
    "%OUT%\SwarmV29_Verification.obj" ^
    "%SOV%\Sovereign_GGUF_Loader.obj" ^
    "%SOV%\Sovereign_Memory_Manager.obj" ^
    "%SOV%\Sovereign_Forward_Pass.obj" ^
    "%SOV%\Sovereign_KV_Cache_Manager.obj" ^
    "%SOV%\Sovereign_Transformer_Loop.obj" ^
    "%SOV%\Sovereign_Registry_Dispatcher_Complete.obj" ^
    "%SOV%\Sovereign_Sampling_Kernel.obj" ^
    "%PATCH%" ^
    /SUBSYSTEM:CONSOLE ^
    /ENTRY:main ^
    /MACHINE:X64 ^
    %LIB_PATHS% ^
    kernel32.lib user32.lib

if exist "%OUT%\RawrXD_Complete.exe" (
    echo.
    echo ================================================================================
    echo SUCCESS: RawrXD_Complete.exe created
    echo ================================================================================
    dir "%OUT%\RawrXD_Complete.exe"
    echo.
    echo Components linked:
    echo   - SwarmV29 AZDO modules (%SWARMV29_COUNT%)
    echo   - Sovereign objects (%SOV_COUNT%)
    echo   - Heap patch (1)
    echo ================================================================================
) else (
    echo.
    echo ERROR: Link failed
    echo Check for unresolved externals or missing dependencies
    exit /b 1
)

echo.
echo [5/5] Integration summary...
echo.
echo ================================================================================
echo Integration Complete
echo ================================================================================
echo.
echo Executable: %OUT%\RawrXD_Complete.exe
echo.
echo SwarmV29 AZDO Modules:
for %%f in ("%OUT%\SwarmV29_*.obj") do echo   %%~nxf
echo.
echo Sovereign Objects:
for %%f in ("%SOV%\*.obj") do echo   %%~nxf
echo.
echo Heap Patch:
echo   sovereign_memory_patch_fixed.obj
echo.
echo ================================================================================