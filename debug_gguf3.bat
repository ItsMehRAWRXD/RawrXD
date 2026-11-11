@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
cd /d F:\rawrxd
cl.exe /nologo debug_gguf3.cpp /Fedebug_gguf3.exe
debug_gguf3.exe