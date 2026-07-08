@echo off
cd /d d:\rawrxd\compilers\fixed_compilers
"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\link.exe" universal_compiler_fixed.obj /SUBSYSTEM:CONSOLE /ENTRY:main /OUT:universal_compiler_fixed.exe "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64\kernel32.lib"
if %ERRORLEVEL% neq 0 (
    echo Link failed
    exit /b 1
)
echo Link successful
