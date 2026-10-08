@echo off
cd /d F:\rawrxd
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
echo #include "ExecutionIR.generated.hpp" > F:\rawrxd\generated\DeepSeek-V2-Lite-Chat\test_compile.cpp
cl.exe /nologo /std:c++20 /W4 /WX- /EHsc /c ^
    /I "F:\rawrxd\src" ^
    /I "F:\rawrxd\include" ^
    /I "F:\rawrxd\src\deep2\modelgenie" ^
    /I "F:\rawrxd\generated\DeepSeek-V2-Lite-Chat" ^
    "F:\rawrxd\generated\DeepSeek-V2-Lite-Chat\test_compile.cpp" ^
    /Fo NUL