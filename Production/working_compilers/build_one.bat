@echo off
call "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
cd /d d:\rawrxd\production\working_compilers

C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe /c bash_compiler_from_scratch.asm
if errorlevel 1 (
    echo Assembly failed
    exit /b 1
)

C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe /SUBSYSTEM:CONSOLE /ENTRY:start bash_compiler_from_scratch.obj "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64\kernel32.lib" /OUT:bash_compiler_from_scratch.exe
if errorlevel 1 (
    echo Link failed
    exit /b 1
)

echo Build successful
