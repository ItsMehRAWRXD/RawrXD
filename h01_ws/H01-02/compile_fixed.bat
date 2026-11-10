@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
cl /nologo /EHsc /std:c++20 /Fe:F:\rawrxd\h01_ws\H01-02\test_null_deref_fixed.exe F:\rawrxd\h01_ws\H01-02\test_null_deref_fixed.cpp