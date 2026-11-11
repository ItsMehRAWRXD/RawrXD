@echo off
setlocal

set "VS_PATH=C:\Program Files\Microsoft Visual Studio\18\Enterprise"
set "VCINSTALLDIR=%VS_PATH%\VC"
set "VCToolsInstallDir=%VCINSTALLDIR%\Tools\MSVC\14.51.36231"

set "LIB=%VCToolsInstallDir%\lib\x64;%VCINSTALLDIR%\Auxiliary\VS\lib\x64;C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64;C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64"
set "LIBPATH=%VCToolsInstallDir%\lib\x64;%VCINSTALLDIR%\Auxiliary\VS\lib\x64"

echo Linking validation test...
"%VCToolsInstallDir%\bin\Hostx64\x64\link.exe" ^
    /SUBSYSTEM:CONSOLE ^
    /ENTRY:main ^
    /MACHINE:X64 ^
    /OUT:d:\rawrxd\test_lora_validate.exe ^
    d:\rawrxd\test_lora_validate.obj ^
    d:\rawrxd\src\lora\ApplyLoRA_Clean.obj ^
    kernel32.lib

echo Exit code: %ERRORLEVEL%
