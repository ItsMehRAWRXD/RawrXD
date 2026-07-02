@echo off
cd /d D:\rawrxd-ci-bootstrap

echo Building CompleteTest.exe...

"C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe" /c /W3 /nologo /Fo CompleteTest.obj CompleteTest.asm
if errorlevel 1 (
    echo Assembly failed!
    exit /b 1
)

"C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe" /SUBSYSTEM:CONSOLE /ENTRY:main /NODEFAULTLIB /OUT:CompleteTest.exe CompleteTest.obj kernel32.lib
if errorlevel 1 (
    echo Link failed!
    exit /b 1
)

echo Success!
dir CompleteTest.exe
