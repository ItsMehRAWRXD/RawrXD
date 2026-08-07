@echo off
call "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\cl.exe" /nologo /O2 /EHsc /Fe:d:\rawrxd\tmp_size_check.exe d:\rawrxd\tmp_size_check.cpp
d:\rawrxd\tmp_size_check.exe
