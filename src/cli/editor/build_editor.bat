@echo off
REM Build script for CLI Editor Core
REM Requires: Visual Studio 2022 with MASM64

setlocal enabledelayedexpansion

echo ==========================================
echo RawrXD CLI Editor Core Build
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

set ML64="C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"
if not exist %ML64% (
    set ML64=ml64.exe
)

set OUTDIR=..\..\..\build-cli
if not exist %OUTDIR% mkdir %OUTDIR%

echo.
echo Building MASM64 components...
echo ------------------------------------------

REM Assemble cli_editor_core.asm
echo Building cli_editor_core.asm...
%ML64% /c /W3 /nologo /Zi /Fo%OUTDIR%\cli_editor_core.obj cli_editor_core.asm
if errorlevel 1 (
    echo ERROR: Failed to assemble cli_editor_core.asm
    exit /b 1
)
echo   OK: cli_editor_core.obj

echo.
echo Building C++ components...
echo ------------------------------------------

REM Compile C++ wrapper
cl.exe /c /W4 /EHsc /std:c++17 /O2 /Zi /Fo%OUTDIR%\cli_editor_core_cpp.obj /I..\.. cli_editor_core.cpp
if errorlevel 1 (
    echo ERROR: Failed to compile cli_editor_core.cpp
    exit /b 1
)
echo   OK: cli_editor_core_cpp.obj

echo.
echo Creating static library...
echo ------------------------------------------

lib.exe /nologo /out:%OUTDIR%\cli_editor.lib %OUTDIR%\cli_editor_core.obj %OUTDIR%\cli_editor_core_cpp.obj
if errorlevel 1 (
    echo ERROR: Failed to create library
    exit /b 1
)
echo   OK: cli_editor.lib

echo.
echo ==========================================
echo Build completed successfully!
echo Output: %OUTDIR%\cli_editor.lib
echo ==========================================

endlocal
