@echo off
call "%ProgramFiles%\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars64.bat"

cl /O2 /arch:AVX512 /EHsc /std:c++20 /I src tests\test_fix5a_kv_cache.cpp bin\RawrXD_Fix5A.lib /Fe:bin\test_fix5a_kv_cache.exe /link kernel32.lib
