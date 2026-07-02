@echo off
cd /d D:\rawrxd-ci-bootstrap

echo Building Sovereign Inference Worker...

"C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe" /c /W3 /nologo /Zi /Fo Sovereign_Inference_Worker.obj Sovereign_Inference_Worker.asm
if errorlevel 1 (
    echo Assembly failed!
    exit /b 1
)

echo Inference worker built successfully!
dir Sovereign_Inference_Worker.obj
