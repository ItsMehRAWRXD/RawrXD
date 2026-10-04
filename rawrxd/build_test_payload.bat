@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64
cl /std:c++20 /EHsc /O2 /arch:AVX2 F:\~dev\rawrxd\tests\deep2\test_avx_payload_112.cpp /Fe:F:\~dev\rawrxd\test_avx_payload_112.exe