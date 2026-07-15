@echo off
REM Build script for RawrXD Validation Harness

setlocal enabledelayedexpansion

echo ==========================================
echo RawrXD Validation Harness Build
echo ==========================================

REM Find VS2022
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
    echo ERROR: vswhere.exe not found
    exit /b 1
)

for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
    set "VSINSTALLPATH=%%i"
)

if not defined VSINSTALLPATH (
    echo ERROR: Visual Studio 2022 not found
    exit /b 1
)

call "%VSINSTALLPATH%\VC\Auxiliary\Build\vcvars64.bat"

set OUTDIR=..\..\build-validation
if not exist %OUTDIR% mkdir %OUTDIR%

echo Building validation harness...

set CFLAGS=/c /O2 /W4 /DNDEBUG /nologo /Fo%OUTDIR%\

REM Compile validation modules
echo Compiling validation modules...

cl.exe %CFLAGS% /I..\core rawrxd_validate.c
if errorlevel 1 (
    echo ERROR: Failed to compile rawrxd_validate.c
    exit /b 1
)

cl.exe %CFLAGS% /I..\core rawrxd_validate_gguf.c
if errorlevel 1 (
    echo ERROR: Failed to compile rawrxd_validate_gguf.c
    exit /b 1
)

cl.exe %CFLAGS% /I..\core rawrxd_validate_stress.c
if errorlevel 1 (
    echo ERROR: Failed to compile rawrxd_validate_stress.c
    exit /b 1
)

cl.exe %CFLAGS% /I..\core rawrxd_validate_report.c
if errorlevel 1 (
    echo ERROR: Failed to compile rawrxd_validate_report.c
    exit /b 1
)

REM Link with core library
echo Linking...
link.exe /nologo /out:%OUTDIR%\rawrxd_validate.exe ^
    %OUTDIR%\rawrxd_validate.obj ^
    %OUTDIR%\rawrxd_validate_gguf.obj ^
    %OUTDIR%\rawrxd_validate_stress.obj ^
    %OUTDIR%\rawrxd_validate_report.obj ^
    ..\..\build-core\rawrxd_core.lib kernel32.lib user32.lib

if errorlevel 1 (
    echo ERROR: Link failed
    exit /b 1
)

echo.
echo ==========================================
echo Validation harness built successfully!
echo Output: %OUTDIR%\rawrxd_validate.exe
echo ==========================================
echo.
echo Run with: %OUTDIR%\rawrxd_validate.exe --help

endlocal
