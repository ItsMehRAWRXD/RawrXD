@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
cl.exe /nologo /std:c++20 /W4 /WX- /EHsc /O2 test_args.cpp /Fe"F:\rawrxd\tmp_build\test_args.exe"