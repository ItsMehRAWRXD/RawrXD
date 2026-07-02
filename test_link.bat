@echo off
cd /d D:\rawrxd-ci-bootstrap

"C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe" /SUBSYSTEM:CONSOLE /ENTRY:main /NODEFAULTLIB /OUT:TestLink.exe MinimalChat_test.obj kernel32.lib

if errorlevel 1 (
    echo Link failed
) else (
    echo Link succeeded
    dir TestLink.exe
)
