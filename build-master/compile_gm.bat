@echo off
call "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
cd /d d:\rawrxd\build-master

cl /c /std:c++20 /W3 /O2 /nologo /Fo:golden_master.obj ..\src\script\golden_master.cpp /I..\src\script
