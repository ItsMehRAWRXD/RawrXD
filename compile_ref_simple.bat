@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
cl.exe /nologo /std:c++20 /W4 /WX- /EHsc /O2 ^
    /I "F:\rawrxd\tmp_llama-clone" ^
    /I "F:\rawrxd\tmp_llama-clone\include" ^
    /I "F:\rawrxd\tmp_llama-clone\ggml\include" ^
    reference_simple.cpp ^
    /link ^
    /LIBPATH:"F:\rawrxd\tmp_llama-clone\build\src\Release" ^
    /LIBPATH:"F:\rawrxd\tmp_llama-clone\build\ggml\src\Release" ^
    /LIBPATH:"F:\rawrxd\tmp_llama-clone\build\common\Release" ^
    /LIBPATH:"F:\rawrxd\tmp_llama-clone\build\bin\Release" ^
    llama.lib ggml.lib ggml-base.lib ggml-cpu.lib llama-common.lib