@echo off
setlocal

REM Set up VS2022 environment
set "VSINSTALLDIR=C:\VS2022Enterprise"
set "VCINSTALLDIR=%VSINSTALLDIR%\VC"
set "VCToolsInstallDir=%VCINSTALLDIR%\Tools\MSVC\14.50.35717"
set "VCToolsRedistDir=%VCINSTALLDIR%\Redist\MSVC\14.50.35717"

REM Add to PATH
set "PATH=%VCToolsInstallDir%\bin\Hostx64\x64;%PATH%"
set "LIB=%VCToolsInstallDir%\lib\x64;%VCINSTALLDIR%\Auxiliary\VS\lib\x64;C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64;C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64"
set "INCLUDE=%VCToolsInstallDir%\include;%VCINSTALLDIR%\Auxiliary\VS\include;C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\ucrt;C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\um;C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\shared"

echo PATH set to: %PATH%
echo.

link.exe ^
    /SUBSYSTEM:CONSOLE ^
    /ENTRY:main ^
    /OUT:d:\rawrxd\test_lora_shadow.exe ^
    d:\rawrxd\test_lora_shadow.obj ^
    d:\rawrxd\src\lora\ApplyLoRA_Clean.obj ^
    kernel32.lib

if %ERRORLEVEL% NEQ 0 (
    echo Link failed with error %ERRORLEVEL%
    exit /b %ERRORLEVEL%
)

echo Link successful!
dir d:\rawrxd\test_lora_shadow.exe
