@echo off
setlocal

set "VS_PATH=C:\Program Files\Microsoft Visual Studio\18\Enterprise"
set "VCINSTALLDIR=%VS_PATH%\VC"
set "VCToolsInstallDir=%VCINSTALLDIR%\Tools\MSVC\14.51.36231"

set "PATH=%VCToolsInstallDir%\bin\Hostx64\x64;%PATH%"
set "LIB=%VCToolsInstallDir%\lib\x64;%VCINSTALLDIR%\Auxiliary\VS\lib\x64;C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64;C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64"
set "INCLUDE=%VCToolsInstallDir%\include;C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\ucrt;C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\um;C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\shared"

echo Compiling C++ test harness...
cl.exe /c /W3 /nologo /O2 /EHsc /Fo"d:\rawrxd\test_lora_shadow_cpp.obj" "d:\rawrxd\test_lora_shadow_cpp.cpp"
if %ERRORLEVEL% NEQ 0 (
    echo Compile failed!
    exit /b %ERRORLEVEL%
)

echo Linking...
link.exe ^
    /SUBSYSTEM:CONSOLE ^
    /ENTRY:mainCRTStartup ^
    /MACHINE:X64 ^
    /OUT:d:\rawrxd\test_lora_shadow_cpp.exe ^
    d:\rawrxd\test_lora_shadow_cpp.obj ^
    d:\rawrxd\src\lora\ApplyLoRA_Clean.obj ^
    msvcrt.lib ^
    kernel32.lib

echo Exit code: %ERRORLEVEL%
