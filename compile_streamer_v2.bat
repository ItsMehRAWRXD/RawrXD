@echo off
cd /d D:\rawrxd-ci-bootstrap

echo Compiling StreamerImpl_v2.asm...

"C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe" /c /W3 /nologo /Fo StreamerImpl_v2.obj StreamerImpl_v2.asm

if errorlevel 1 (
    echo Compilation failed!
    exit /b 1
)

echo Success!
dir StreamerImpl_v2.obj
