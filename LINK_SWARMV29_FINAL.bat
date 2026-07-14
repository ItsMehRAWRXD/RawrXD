@echo off
echo ================================================================================
echo RawrXD SwarmV29 Integration - Final Link
echo ================================================================================
echo.

set "LINK=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe"
set "VC_LIB=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\lib\x64"
set "UM_LIB=C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\um\x64"
set "UCRT_LIB=C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\ucrt\x64"

set "ROOT=d:\rawrxd"
set "OUTDIR=%ROOT%\build\final"
set "ASM=%ROOT%\src\asm"
set "SOV=d:\sovereign_build"
set "PATCH=%ROOT%\compilers\native_toolchain\sovereign_memory_patch_fixed.obj"

if not exist "%OUTDIR%" mkdir "%OUTDIR%"

echo [1/3] Verifying toolchain...
if not exist "%LINK%" (
    echo ERROR: link.exe not found
    exit /b 1
)
echo   OK: Linker found

if not exist "%VC_LIB%\kernel32.lib" (
    echo ERROR: VC libraries not found
    exit /b 1
)
echo   OK: VC libraries found

if not exist "%UM_LIB%\kernel32.lib" (
    echo ERROR: Windows SDK libraries not found
    exit /b 1
)
echo   OK: Windows SDK libraries found

echo.
echo [2/3] Linking SwarmV29 test executable...

"%LINK%" /NOLOGO ^
    /OUT:"%OUTDIR%\SwarmV29_Test.exe" ^
    /SUBSYSTEM:CONSOLE ^
    /ENTRY:main ^
    /MACHINE:X64 ^
    /LIBPATH:"%VC_LIB%" ^
    /LIBPATH:"%UM_LIB%" ^
    /LIBPATH:"%UCRT_LIB%" ^
    "%OUTDIR%\SwarmV29_Test_Entry.obj" ^
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
    kernel32.lib user32.lib

if exist "%OUTDIR%\SwarmV29_Test.exe" (
    echo.
    echo ================================================================================
    echo SUCCESS: SwarmV29_Test.exe created
    echo ================================================================================
    dir "%OUTDIR%\SwarmV29_Test.exe"
    echo.
    echo SwarmV29 AZDO modules linked successfully!
    echo.
    echo [3/3] Running test...
    "%OUTDIR%\SwarmV29_Test.exe"
    echo.
    echo Exit code: %ERRORLEVEL%
) else (
    echo.
    echo ERROR: Link failed
    echo Check for unresolved externals or missing dependencies
    exit /b 1
)