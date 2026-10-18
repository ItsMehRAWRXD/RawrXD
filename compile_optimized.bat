@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64
cl /O2 /Oi /arch:AVX512 G:\VSC0de\Deep2Engine\src\tools\waaf_procedural_optimized.cpp /link /OUT:G:\VSC0de\Deep2Engine\build\bin\Release\waaf_procedural_optimized.exe