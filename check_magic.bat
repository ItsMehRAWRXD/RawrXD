@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
cd /d F:\rawrxd
cl.exe /nologo check_magic.cpp /Fecheck_magic.exe
check_magic.exe