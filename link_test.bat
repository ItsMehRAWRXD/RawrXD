@echo off
setlocal

"C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe" ^
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
