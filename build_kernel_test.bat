@echo off
call "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
cd /d d:\rawrxd
cl.exe /std:c++17 /O2 /EHsc /W4 /Iinclude /Iinclude\kernels /Febin\test_quantized_kernels.exe src\kernels\test_quantized_kernels.cpp lib\RawrXD_QuantizedKernels.lib
