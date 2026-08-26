@echo off
cd /d f:\~dev\rawrxd\src\deep2
call "C:\VS2022Enterprise\VC\Auxiliary\Build\vcvars64.bat"
cl.exe /nologo /c /W4 /O2 /arch:AVX2 /EHsc /std:c++20 /I. /I.. /I..\..\include /I..\..\src /I..\tokenizer /I..\sampling /D_CRT_SECURE_NO_WARNINGS Deep2Engine.cpp /FoDeep2Engine_instrumented.obj
