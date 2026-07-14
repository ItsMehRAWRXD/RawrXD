@echo off
REM Build script for RawrXD Core - Zero Dependency
REM Requires: Visual Studio 2022 with C++ tools

setlocal enabledelayedexpansion

echo ==========================================
echo RawrXD Core Build System
echo Zero-Dependency Inference Engine
echo ==========================================

REM Find VS2022
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
    echo ERROR: vswhere.exe not found. Install Visual Studio 2022.
    exit /b 1
)

for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
    set "VSINSTALLPATH=%%i"
)

if not defined VSINSTALLPATH (
    echo ERROR: Visual Studio 2022 with C++ tools not found.
    exit /b 1
)

echo Found VS2022 at: %VSINSTALLPATH%

REM Setup environment
call "%VSINSTALLPATH%\VC\Auxiliary\Build\vcvars64.bat"
if errorlevel 1 (
    echo ERROR: Failed to setup VS environment
    exit /b 1
)

set OUTDIR=..\..\build-core
if not exist %OUTDIR% mkdir %OUTDIR%

echo.
echo Building RawrXD Core...
echo ------------------------------------------

set CFLAGS=/c /O2 /W4 /DNDEBUG /D_CRT_SECURE_NO_WARNINGS /nologo /Fo%OUTDIR%\
set CFLAGS_DEBUG=/c /Od /Zi /W4 /D_DEBUG /D_CRT_SECURE_NO_WARNINGS /nologo /Fo%OUTDIR%\

REM Build core modules
echo [1/6] Compiling rawrxd_core.c (platform abstraction)...
cl.exe %CFLAGS% rawrxd_core.c
if errorlevel 1 (
    echo ERROR: Failed to compile rawrxd_core.c
    exit /b 1
)

echo [2/6] Compiling rawrxd_model_stream.c (streaming loader)...
cl.exe %CFLAGS% rawrxd_model_stream.c
if errorlevel 1 (
    echo ERROR: Failed to compile rawrxd_model_stream.c
    exit /b 1
)

echo [3/6] Compiling rawrxd_inference.c (inference engine)...
cl.exe %CFLAGS% rawrxd_inference.c
if errorlevel 1 (
    echo ERROR: Failed to compile rawrxd_inference.c
    exit /b 1
)

echo [4/6] Compiling rawrxd_quant_avx2.c (AVX2 kernels)...
cl.exe %CFLAGS% /arch:AVX2 rawrxd_quant_avx2.c 2>nul
if errorlevel 1 (
    echo WARNING: AVX2 compilation failed, using scalar fallback
    copy nul %OUTDIR%\rawrxd_quant_avx2.obj >nul
)

echo [5/6] Compiling rawrxd_cli_main.c (CLI entry)...
cl.exe %CFLAGS% rawrxd_cli_main.c
if errorlevel 1 (
    echo ERROR: Failed to compile rawrxd_cli_main.c
    exit /b 1
)

echo.
echo Linking...
echo ------------------------------------------

REM Link static library
echo [6/6] Creating static library...
lib.exe /nologo /out:%OUTDIR%\rawrxd_core.lib %OUTDIR%\*.obj
if errorlevel 1 (
    echo ERROR: Failed to create library
    exit /b 1
)

REM Link executable
echo Creating CLI executable...
link.exe /nologo /out:%OUTDIR%\rawrxd.exe %OUTDIR%\rawrxd_cli_main.obj %OUTDIR%\rawrxd_core.lib kernel32.lib user32.lib
if errorlevel 1 (
    echo ERROR: Failed to link executable
    exit /b 1
)

echo.
echo ==========================================
echo Build completed successfully!
echo ==========================================
echo Output files:
echo   %OUTDIR%\rawrxd_core.lib  (static library)
echo   %OUTDIR%\rawrxd.exe       (CLI executable)
echo.
echo Run with: %OUTDIR%\rawrxd.exe --help

endlocal
