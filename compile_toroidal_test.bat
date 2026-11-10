@echo off
cd /d F:\rawrxd\~dev
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=x64 -no_logo
cl /std:c++17 /O2 /arch:AVX512 /EHsc /I. /IF:\rawrxd\~dev\rawrxd\src\deep2 /IF:\rawrxd\3rdparty\ggml\src /IF:\rawrxd\3rdparty\ggml\include tests\toroidal_kvcache_selftest.cpp /Fe:toroidal_kvcache_selftest.exe 2>&1