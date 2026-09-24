@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
cd /d f:\~dev\rawrxd\tests\deep2
cl /std:c++20 /I. /I.. /I..\..\include test_layer0_providers.cpp /Fetest_layer0_providers.exe
