@echo off
cd /d D:\rawrxd-ci-bootstrap

echo Compiling Sovereign_Inference_Worker.asm...

"C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe" /c /W3 /nologo /Zi /Fo Sovereign_Inference_Worker.obj Sovereign_Inference_Worker.asm

if errorlevel 1 (
    echo Compilation failed!
    exit /b 1
)

echo Success!
dir Sovereign_Inference_Worker.obj
