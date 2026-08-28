@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
cd /d F:\~dev\rawrxd\src\deep2

set CLFLAGS=/nologo /W3 /O2 /arch:AVX2 /EHsc /std:c++20 /I. /I.. /I..\..\include /I..\sampling /D_CRT_SECURE_NO_WARNINGS

cl.exe %CLFLAGS% /c ListGGUFTensors.cpp
if %ERRORLEVEL% NEQ 0 (
    echo COMPILE FAILED
    exit /b %ERRORLEVEL%
)

cl.exe %CLFLAGS% /Fe:ListGGUFTensors.exe ListGGUFTensors.obj GGUFLoader.obj
if %ERRORLEVEL% NEQ 0 (
    echo LINK FAILED
    exit /b %ERRORLEVEL%
)

echo BUILD OK
ListGGUFTensors.exe G:\OllamaModels\blobs\sha256-9be227448d319e6a7acca8056b71bf7d9a2c6b2811986e6658a9dedc208d0ada
