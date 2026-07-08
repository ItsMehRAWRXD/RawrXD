@echo off
echo ================================================================================
echo Manual Link - Sovereign with Heap Patch
echo ================================================================================
echo.

set "LINK=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe"
set "OUTDIR=d:\rawrxd\build\final"
set "SOV=d:\sovereign_build"
set "PATCH=d:\rawrxd\compilers\native_toolchain\sovereign_memory_patch.obj"

if not exist "%LINK%" (
    echo ERROR: LINK.exe not found at %LINK%
    echo Please install Visual Studio 2022 with C++ build tools
    exit /b 1
)

if not exist "%OUTDIR%" mkdir "%OUTDIR%"

echo Linking Sovereign executable...
echo.

"%LINK%" /NOLOGO /OUT:"%OUTDIR%\RawrXD_Sovereign.exe" ^
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
    kernel32.lib user32.lib ntdll.lib

if exist "%OUTDIR%\RawrXD_Sovereign.exe" (
    echo.
    echo ================================================================================
    echo SUCCESS: RawrXD_Sovereign.exe created
    echo ================================================================================
    dir "%OUTDIR%\RawrXD_Sovereign.exe"
) else (
    echo.
    echo ERROR: Link failed
    exit /b 1
)

echo.
echo Test with:
echo   %OUTDIR%\RawrXD_Sovereign.exe --help
echo.

endlocal
