@echo off
REM ============================================================================
REM build_sample_plugins.bat - Build Sample RawrXD Plugins
REM ============================================================================
REM This script builds both the MASM and C++ sample plugins.
REM Requires: Visual Studio 2022 (or compatible) with MASM x64 support
REM ============================================================================

setlocal enabledelayedexpansion

echo ============================================
echo RawrXD Sample Plugin Build System
echo ============================================
echo.

REM Find Visual Studio 2022
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
    echo ERROR: Visual Studio 2022 not found
    exit /b 1
)

for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
    set "VSINSTALLPATH=%%i"
)

if not defined VSINSTALLPATH (
    echo ERROR: Could not find VS2022 installation
    exit /b 1
)

echo Found Visual Studio at: %VSINSTALLPATH%
echo.

REM Setup environment
call "%VSINSTALLPATH%\VC\Auxiliary\Build\vcvars64.bat"
if errorlevel 1 (
    echo ERROR: Failed to setup build environment
    exit /b 1
)

REM Create output directory
if not exist "..\..\build\plugins" mkdir "..\..\build\plugins"

REM ============================================================================
REM Build MASM Sample Plugin
REM ============================================================================
echo Building SamplePlugin (MASM)...
cd SamplePlugin

ml64.exe /c /W3 /nologo SamplePlugin.asm
if errorlevel 1 (
    echo ERROR: MASM assembly failed
    exit /b 1
)

link.exe /DLL /OUT:..\..\build\plugins\SamplePlugin.dll SamplePlugin.obj ^
    /SUBSYSTEM:WINDOWS /MACHINE:X64 ^
    /EXPORT:RawrXD_PluginInitialize ^
    /EXPORT:RawrXD_PluginShutdown
if errorlevel 1 (
    echo ERROR: Link failed
    exit /b 1
)

cd ..
echo [OK] SamplePlugin.dll built successfully
echo.

REM ============================================================================
REM Build C++ Sample Plugin
REM ============================================================================
echo Building SamplePluginCpp (C++)...
cd SamplePluginCpp

cl.exe /c /W4 /EHsc /O2 /MD ^
    /I"..\..\include" ^
    /DRAWRXD_PLUGIN_BUILD ^
    SamplePluginCpp.cpp
if errorlevel 1 (
    echo ERROR: C++ compilation failed
    exit /b 1
)

link.exe /DLL /OUT:..\..\build\plugins\SamplePluginCpp.dll SamplePluginCpp.obj ^
    /SUBSYSTEM:WINDOWS /MACHINE:X64
if errorlevel 1 (
    echo ERROR: Link failed
    exit /b 1
)

cd ..
echo [OK] SamplePluginCpp.dll built successfully
echo.

REM ============================================================================
REM Summary
REM ============================================================================
echo ============================================
echo Build Complete!
echo ============================================
echo.
echo Output files:
dir "..\..\build\plugins\*.dll" /b
echo.
echo To install plugins:
echo   copy build\plugins\*.dll RawrXD\plugins\
echo.
echo To test:
echo   1. Copy DLLs to RawrXD/plugins/
echo   2. Start RawrXD IDE
echo   3. Look for plugin initialization messages in console
echo   4. Try Ctrl+Shift+H (MASM) or Ctrl+Shift+C (C++)
echo.

endlocal
