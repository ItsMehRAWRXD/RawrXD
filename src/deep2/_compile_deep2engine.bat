@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
cd /d d:\rawrxd\src\deep2

set CLFLAGS=/nologo /W3 /O2 /arch:AVX2 /EHsc /std:c++20 /I. /I.. /I..\..\include /I..\sampling /D_CRT_SECURE_NO_WARNINGS

cl.exe %CLFLAGS% /c Deep2Engine.cpp
if %ERRORLEVEL% NEQ 0 (
    echo COMPILE FAILED
    exit /b %ERRORLEVEL%
)

echo COMPILE OK
