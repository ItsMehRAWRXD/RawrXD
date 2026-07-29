@echo off
cd /d d:\RawrXD\src\kernels
call "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
cl.exe /O2 /Zi /EHsc /std:c++17 /I.. test_quantized_kernels.cpp quantized_matmul.obj /Fe:test_val_q42.exe /link /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64" /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64"
