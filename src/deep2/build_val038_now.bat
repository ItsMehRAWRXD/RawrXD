@echo off
call "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
cd /d d:\RawrXD\src\deep2
ml64.exe /c /Fo TreeAttention_Fused_VAL038.obj TreeAttention_Fused_VAL038.asm
if errorlevel 1 exit /b 1
ml64.exe /c /Fo softmax_lut_avx512.obj softmax_lut_avx512.asm
if errorlevel 1 exit /b 1
cl.exe /O2 /arch:AVX512 /std:c++17 /EHsc VAL038_Benchmark_Harness.cpp /Fe:VAL038_Benchmark_Harness.exe /link TreeAttention_Fused_VAL038.obj softmax_lut_avx512.obj /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64" /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64"
if errorlevel 1 exit /b 1
