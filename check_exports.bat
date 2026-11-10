@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
dumpbin /exports C:\llama.cpp\build\src\Release\llama.dll | findstr /i capture