@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64
cd /d F:\rawrxd\src
cl.exe /c /O2 /EHsc /std:c++17 /I . /I qtapp gguf_loader.cpp 2>&1