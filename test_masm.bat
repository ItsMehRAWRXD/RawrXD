@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1

ml64.exe /c /Foobj\quantized_matmul.obj src\kernels\quantized_matmul.asm 2>&1
echo Exit code: %errorlevel%

dir obj\quantized_matmul.obj