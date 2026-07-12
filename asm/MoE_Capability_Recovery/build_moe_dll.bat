@echo off
REM ==============================================================================
REM Build script for Sovereign MoE DLL
REM Pure x64 MASM, no deps, no CRT, no external resources
REM ==============================================================================

setlocal enabledelayedexpansion

REM Configuration
set SOURCE=SOVEREIGN_MOE.asm
set OBJECT=SOVEREIGN_MOE.obj
set DLL=MoE.dll
set LIB=MoE.lib
set EXP=MoE.exp

REM Find ML64 (Visual Studio)
set ML64_PATH=""

REM Try common VS2022 paths
if exist "C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe" (
    set ML64_PATH="C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"
    goto :found_ml64
)

if exist "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe" (
    set ML64_PATH="C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"
    goto :found_ml64
)

if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe" (
    set ML64_PATH="C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"
    goto :found_ml64
)

REM Try vswhere
for /f "usebackq tokens=*" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -property installationPath 2^>nul`) do (
    if exist "%%i\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe" (
        set ML64_PATH="%%i\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"
        goto :found_ml64
    )
)

:found_ml64
if %ML64_PATH%=="" (
    echo ERROR: Could not find ml64.exe
    echo Please ensure Visual Studio 2022 is installed with C++ build tools
    exit /b 1
)

echo Found ML64: %ML64_PATH%

REM Find LINK (same directory as ML64)
for %%I in (%ML64_PATH%) do set VC_DIR=%%~dpI
set LINK_PATH="%VC_DIR%link.exe"

echo Found LINK: %LINK_PATH%

REM Clean previous builds
echo Cleaning previous builds...
if exist %OBJECT% del %OBJECT%
if exist %DLL% del %DLL%
if exist %LIB% del %LIB%
if exist %EXP% del %EXP%

REM Assemble
echo.
echo ==============================================================================
echo Assembling %SOURCE%...
echo ==============================================================================
%ML64_PATH% /c /W3 /nologo /Fo %OBJECT% %SOURCE%

if errorlevel 1 (
    echo ERROR: Assembly failed
    exit /b 1
)

echo Assembly successful: %OBJECT%

REM Link as DLL
echo.
echo ==============================================================================
echo Linking %DLL%...
echo ==============================================================================
%LINK_PATH% /DLL /NOENTRY /NODEFAULTLIB /SUBSYSTEM:WINDOWS /LARGEADDRESSAWARE:NO /OUT:%DLL% %OBJECT%

if errorlevel 1 (
    echo ERROR: Link failed
    exit /b 1
)

echo.
echo ==============================================================================
echo Build successful!
echo ==============================================================================
echo Output: %DLL%
echo.
echo Exports:
dumpbin /exports %DLL% 2>nul | findstr "MoE_"

echo.
echo Next steps:
echo 1. Copy %DLL% to your Sovereign Runtime bin directory
echo 2. Update MoEBackend.cpp to LoadLibrary("MoE.dll")
echo 3. Build and test with: agent moe generate "hello"
echo.

endlocal
