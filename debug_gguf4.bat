@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
cd /d F:\rawrxd
cl.exe /nologo debug_gguf4.cpp /Fedebug_gguf4.exe
debug_gguf4.exe