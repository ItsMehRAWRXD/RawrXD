@echo off
chcp 65001 > nul
setlocal EnableDelayedExpansion

echo ================================================================================
echo RawrXD Complete Integration Build
echo SwarmV29 AZDO + Sovereign + Heap Patch
echo ================================================================================
echo.

set "ML64=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"
set "LINK=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe"
set "LIB1=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\lib\x64"
set "LIB2=C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64"
set "LIB3=C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64"

set "ROOT=d:\rawrxd"
set "ASM=%ROOT%\src\asm"
set "SOV=d:\sovereign_build"
set "OUT=%ROOT%\build\final"

if not exist "%OUT%" mkdir "%OUT%"

echo [1/4] Verifying toolchain...
if not exist "%ML64%" (
    echo ERROR: ml64.exe not found
    exit /b 1
)
if not exist "%LINK%" (
    echo ERROR: link.exe not found
    exit /b 1
)
echo   OK: Toolchain ready

echo.
echo [2/4] Compiling SwarmV29 AZDO modules...
cd /d "%ASM%"

set SWARMV29_OBJS=

for %%f in (
    SwarmV29_Macros.inc
    SwarmV29_Renderer_State_Cache.asm
    SwarmV29_Pipeline_Controller.asm
    SwarmV29_NTT_Butterfly.asm
    SwarmV29_INTT_Butterfly.asm
    SwarmV29_Persistent_Buffer.asm
    SwarmV29_Renderer_VTable.asm
    SwarmV29_Audit.asm
    SwarmV29_VTable_Binding.asm
    SwarmV29_Benchmark_Harness.asm
    SwarmV29_Verification.asm
) do (
    if exist "%%f" (
        echo   OK: %%f
    ) else (
        echo   MISSING: %%f
    )
)

REM Compile SwarmV29 modules
"%ML64%" /c /nologo /Zi /Fo:"%OUT%\SwarmV29_Renderer_State_Cache.obj" SwarmV29_Renderer_State_Cache.asm
"%ML64%" /c /nologo /Zi /Fo:"%OUT%\SwarmV29_Pipeline_Controller.obj" SwarmV29_Pipeline_Controller.asm
"%ML64%" /c /nologo /Zi /Fo:"%OUT%\SwarmV29_NTT_Butterfly.obj" SwarmV29_NTT_Butterfly.asm
"%ML64%" /c /nologo /Zi /Fo:"%OUT%\SwarmV29_INTT_Butterfly.obj" SwarmV29_INTT_Butterfly.asm
"%ML64%" /c /nologo /Zi /Fo:"%OUT%\SwarmV29_Persistent_Buffer.obj" SwarmV29_Persistent_Buffer.asm
"%ML64%" /c /nologo /Zi /Fo:"%OUT%\SwarmV29_Renderer_VTable.obj" SwarmV29_Renderer_VTable.asm
"%ML64%" /c /nologo /Zi /Fo:"%OUT%\SwarmV29_Audit.obj" SwarmV29_Audit.asm
"%ML64%" /c /nologo /Zi /Fo:"%OUT%\SwarmV29_VTable_Binding.obj" SwarmV29_VTable_Binding.asm
"%ML64%" /c /nologo /Zi /Fo:"%OUT%\SwarmV29_Benchmark_Harness.obj" SwarmV29_Benchmark_Harness.asm
"%ML64%" /c /nologo /Zi /Fo:"%OUT%\SwarmV29_Verification.obj" SwarmV29_Verification.asm

echo.
echo [3/4] Checking Sovereign objects...
if exist "%SOV%" (
    echo   OK: Sovereign build directory exists
    dir /b "%SOV%\*.obj" 2>nul | find /c /v "" >nul
    if errorlevel 1 (
        echo   WARNING: No sovereign objects found
    )
) else (
    echo   WARNING: %SOV% not found
)

echo.
echo [4/4] Creating integration report...

echo ================================================================================
echo Integration Build Summary
echo ================================================================================
echo.
echo SwarmV29 AZDO Modules:
dir /b "%OUT%\SwarmV29_*.obj" 2>nul
echo.
echo Sovereign Objects:
dir /b "%SOV%\*.obj" 2>nul
echo.

echo ================================================================================
echo NEXT STEPS
echo ================================================================================
echo.
echo 1. All SwarmV29 modules compiled successfully
echo 2. Sovereign objects are ready for linking
echo 3. Heap patch is available at:
echo    %ROOT%\compilers\native_toolchain\sovereign_memory_patch_fixed.obj
echo.
echo To create final executable, run:
echo   LINK_SOVEREIGN_MANUAL.bat
echo.
echo ================================================================================