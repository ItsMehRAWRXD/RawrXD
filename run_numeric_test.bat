@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64
cl.exe /nologo /EHsc /std:c++20 F:\rawrxd\numeric_safety_test.cpp /FeF:\rawrxd\numeric_safety_test.exe
if errorlevel 1 (
    echo COMPILE FAILED
    exit /b 1
)
F:\rawrxd\numeric_safety_test.exe