@echo off
REM Build GhostCache + ElasticResidencyManager Integration Test

call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"

cd /d d:\rawrxd\src\deep2

cl.exe /nologo /W3 /O2 /arch:AVX2 /EHsc /std:c++20 ^
    /I. /I.. /I..\..\include /I..\sampling ^
    /D_CRT_SECURE_NO_WARNINGS ^
    /FeGhostCache_Elastic_Integration_Test.exe ^
    GhostCache_Elastic_Integration_Test.cpp ^
    GhostCache.obj ^
    ElasticResidencyManager.obj ^
    QuantKernelRegistry.obj

if %ERRORLEVEL% NEQ 0 (
    echo LINK FAILED
    exit /b %ERRORLEVEL%
)

echo LINK OK
