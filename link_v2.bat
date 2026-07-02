@echo off
cd /d D:\rawrxd-ci-bootstrap

"C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe" /SUBSYSTEM:CONSOLE /ENTRY:main /NODEFAULTLIB /OUT:MinimalChat_v2.exe MinimalChat_v2.obj kernel32.lib

if errorlevel 1 (
    echo Link failed
    exit /b 1
)

echo Link succeeded
dir MinimalChat_v2.exe
