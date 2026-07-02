@echo off
cd /d D:\rawrxd-ci-bootstrap

"C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe" /c /W3 /nologo /Zi /Fo MinimalChat_v2.obj MinimalChat_v2.asm

if errorlevel 1 (
    echo Assembly failed
    exit /b 1
)

echo Assembly succeeded
dir MinimalChat_v2.obj
