@echo off
cd /d d:\RawrXD\src\kernels
call "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
ml64.exe /c /Zi /Fo quantized_matmul.obj quantized_matmul.asm
