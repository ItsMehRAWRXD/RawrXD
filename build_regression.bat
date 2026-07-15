@echo off
call "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvarsall.bat" x64
cd /d d:\rawrxd
cl /std:c++20 /EHsc /W3 /nologo /Fe:build-ninja\tests\sovereign_baseline_regression.exe tests\regression\sovereign_baseline_regression.cpp /I include /I src /link /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64" /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64"
