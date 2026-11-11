@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64
cl.exe /nologo /EHsc /MD /std:c++20 /I F:\rawrxd\tmp_llama-clone\include /c F:\rawrxd\src\deep2\LlamaInferenceDLL.cpp /FoF:\rawrxd\compilers\native_toolchain\LlamaInferenceDLL.obj