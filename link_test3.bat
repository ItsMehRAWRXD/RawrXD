@echo off
setlocal enabledelayedexpansion

REM Find VS2022 installation
set "VSWHERE=C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
    echo vswhere not found, trying default path
    set "VS_PATH=C:\VS2022Enterprise"
) else (
    for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
        set "VS_PATH=%%i"
    )
)

echo VS Path: %VS_PATH%

REM Set up environment
set "VS_PATH=C:\Program Files\Microsoft Visual Studio\18\Enterprise"
set "VCINSTALLDIR=%VS_PATH%\VC"
set "VCToolsInstallDir=%VCINSTALLDIR%\Tools\MSVC\14.51.36231"

REM Set LIBPATH
set "LIB=%VCToolsInstallDir%\lib\x64;%VCINSTALLDIR%\Auxiliary\VS\lib\x64;C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64;C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64"
set "LIBPATH=%VCToolsInstallDir%\lib\x64;%VCINSTALLDIR%\Auxiliary\VS\lib\x64"

echo LIB: %LIB%
echo.

REM Run linker
echo Running linker...
"%VCToolsInstallDir%\bin\Hostx64\x64\link.exe" ^
    /SUBSYSTEM:CONSOLE ^
    /ENTRY:main ^
    /MACHINE:X64 ^
    /OUT:d:\rawrxd\test_lora_shadow.exe ^
    d:\rawrxd\test_lora_shadow.obj ^
    d:\rawrxd\src\lora\ApplyLoRA_Clean.obj ^
    kernel32.lib

echo Linker exit code: %ERRORLEVEL%

if %ERRORLEVEL% EQU 0 (
    echo Link successful!
    dir d:\rawrxd\test_lora_shadow.exe
) else (
    echo Link failed with error %ERRORLEVEL%
)
