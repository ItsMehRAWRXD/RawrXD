@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
cd /d F:\~dev\rawrxd\src\deep2

set CLFLAGS=/nologo /W3 /O2 /arch:AVX2 /EHsc /std:c++20 /I. /I.. /I..\..\include /I..\sampling /D_CRT_SECURE_NO_WARNINGS

cl.exe %CLFLAGS% /c deep2_link_stubs.cpp
if %ERRORLEVEL% NEQ 0 (
    echo STUB COMPILE FAILED
    exit /b %ERRORLEVEL%
)

cl.exe %CLFLAGS% /c Batch21_Registry_Dispatch_Test.cpp
if %ERRORLEVEL% NEQ 0 (
    echo TEST COMPILE FAILED
    exit /b %ERRORLEVEL%
)

cl.exe %CLFLAGS% /Fe:Batch21_Registry_Dispatch_Test.exe Batch21_Registry_Dispatch_Test.obj QuantKernelRegistry.obj GGUFLoader.obj deep2_link_stubs.obj sovereign_q4k_gemv.obj sovereign_q4_0_gemv.obj sovereign_q2_k_gemv.obj sovereign_iq2_xxs_gemv.obj sovereign_iq3_xxs_gemv.obj sovereign_iq4_nl_gemv.obj sovereign_moe_fused.obj
if %ERRORLEVEL% NEQ 0 (
    echo LINK FAILED
    exit /b %ERRORLEVEL%
)

echo BUILD OK
