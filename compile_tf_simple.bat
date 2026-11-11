@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
cl.exe /nologo /std:c++20 /W4 /WX- /EHsc /O2 ^
    /I "F:\rawrxd\src" ^
    /I "F:\rawrxd\include" ^
    /I "F:\rawrxd\src\deep2" ^
    /I "F:\rawrxd\src\deep2\modelgenie" ^
    /I "F:\rawrxd\generated\DeepSeek-V2-Lite-Chat" ^
    teacher_forced_simple.cpp ^
    "F:\rawrxd\src\deep2\modelgenie\ModelGenome.cpp" ^
    /Fe"F:\rawrxd\tmp_build\teacher_forced_simple.exe"