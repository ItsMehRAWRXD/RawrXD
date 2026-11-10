@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
cl /nologo /EHsc /std:c++20 /Fe:F:\rawrxd\h01_ws\H01-04\test_resource_leak_fixed.exe F:\rawrxd\h01_ws\H01-04\test_resource_leak_fixed.cpp