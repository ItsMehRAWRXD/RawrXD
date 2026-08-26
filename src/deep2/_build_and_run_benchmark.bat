@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
cd /d d:\rawrxd\src\deep2

cl.exe /nologo /W3 /O2 /arch:AVX2 /EHsc /std:c++20 /I. /I.. /I..\..\include /I..\sampling /D_CRT_SECURE_NO_WARNINGS /c GhostCache_Concurrent_Benchmark.cpp
if %ERRORLEVEL% NEQ 0 (
    echo COMPILE FAILED
    exit /b %ERRORLEVEL%
)

cl.exe /nologo /W3 /O2 /arch:AVX2 /EHsc /std:c++20 /I. /I.. /I..\..\include /I..\sampling /D_CRT_SECURE_NO_WARNINGS /FeGhostCache_Concurrent_Benchmark.exe GhostCache_Concurrent_Benchmark.obj ElasticResidencyManager.obj GhostCache.obj QuantKernelRegistry.obj
if %ERRORLEVEL% NEQ 0 (
    echo LINK FAILED
    exit /b %ERRORLEVEL%
)

echo BUILD OK
GhostCache_Concurrent_Benchmark.exe
