@echo off
cd /d F:\rawrxd\~dev
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=x64 -no_logo
cl /std:c++17 /O2 /arch:AVX512 /I. /IF:\rawrxd\~dev\rawrxd\src\deep2 /IF:\rawrxd\3rdparty\ggml\src /IF:\rawrxd\3rdparty\ggml\include /c tests\roofline_selftest.cpp /Fo roofline_selftest.obj 2>&1