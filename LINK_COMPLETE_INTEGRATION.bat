@echo off
echo ================================================================================
echo Complete Integration Link - SwarmV29 + Sovereign + Heap Patch
echo ================================================================================
echo.

set "LINK=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe"
set "LIB1=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\lib\x64"
set "LIB2=C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64"
set "LIB3=C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64"

set "ROOT=d:\rawrxd"
set "OUTDIR=%ROOT%\build\final"
set "ASM=%ROOT%\src\asm"
set "SOV=d:\sovereign_build"
set "PATCH=%ROOT%\compilers\native_toolchain\sovereign_memory_patch_fixed.obj"

if not exist "%OUTDIR%" mkdir "%OUTDIR%"

echo [1/3] Verifying components...
if not exist "%LINK%" (
    echo ERROR: LINK.exe not found
    exit /b 1
)
echo   OK: Linker ready

if not exist "%PATCH%" (
    echo ERROR: Heap patch not found at %PATCH%
    exit /b 1
)
echo   OK: Heap patch ready

echo.
echo [2/3] Linking all components...

"%LINK%" /NOLOGO /OUT:"%OUTDIR%\RawrXD_Integrated.exe" ^
    "%OUTDIR%\SwarmV29_Renderer_State_Cache.obj" ^
    "%OUTDIR%\SwarmV29_Pipeline_Controller.obj" ^
    "%OUTDIR%\SwarmV29_NTT_Butterfly.obj" ^
    "%OUTDIR%\SwarmV29_INTT_Butterfly.obj" ^
    "%OUTDIR%\SwarmV29_Persistent_Buffer.obj" ^
    "%OUTDIR%\SwarmV29_Renderer_VTable.obj" ^
    "%OUTDIR%\SwarmV29_Audit.obj" ^
    "%OUTDIR%\SwarmV29_VTable_Binding.obj" ^
    "%OUTDIR%\SwarmV29_Benchmark_Harness.obj" ^
    "%OUTDIR%\SwarmV29_Verification.obj" ^
    "%SOV%\Sovereign_GGUF_Loader.obj" ^
    "%SOV%\Sovereign_Memory_Manager.obj" ^
    "%SOV%\Sovereign_Forward_Pass.obj" ^
    "%SOV%\Sovereign_KV_Cache_Manager.obj" ^
    "%SOV%\Sovereign_Transformer_Loop.obj" ^
    "%SOV%\Sovereign_Registry_Dispatcher_Complete.obj" ^
    "%SOV%\Sovereign_Sampling_Kernel.obj" ^
    "%SOV%\Sovereign_Test_Harness.obj" ^
    "%PATCH%" ^
    /SUBSYSTEM:CONSOLE ^
    /ENTRY:main ^
    /DEBUG ^
    /MACHINE:X64 ^
    /LIBPATH:"%LIB1%" ^
    /LIBPATH:"%LIB2%" ^
    /LIBPATH:"%LIB3%" ^
    kernel32.lib user32.lib ntdll.lib

if exist "%OUTDIR%\RawrXD_Integrated.exe" (
    echo.
    echo ================================================================================
    echo SUCCESS: RawrXD_Integrated.exe created
    echo ================================================================================
    dir "%OUTDIR%\RawrXD_Integrated.exe"
    echo.
    echo Components linked:
    echo   - SwarmV29 AZDO modules (10)
    echo   - Sovereign objects (8)
    echo   - Heap patch (1)
    echo ================================================================================
) else (
    echo.
    echo ERROR: Link failed
    echo Check for unresolved externals or missing dependencies
    exit /b 1
)