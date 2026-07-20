@echo off
call "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
cd /d d:\rawrxd
cl.exe /std:c++17 /O2 /EHsc /W4 /Iinclude /Iinclude\kernels /Febin\test_dequant.exe src\kernels\test_dequant_microbench.cpp lib\RawrXD_QuantizedKernels.lib /link /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64" /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64"
