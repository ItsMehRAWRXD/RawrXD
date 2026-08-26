@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
cd /d d:\rawrxd\src\deep2

set CLFLAGS=/nologo /W3 /O2 /arch:AVX2 /EHsc /std:c++20 /I. /I.. /I..\..\include /I..\sampling /D_CRT_SECURE_NO_WARNINGS

cl.exe %CLFLAGS% /c Deep2_Elastic_Forward_Test.cpp
if %ERRORLEVEL% NEQ 0 (
    echo COMPILE FAILED
    exit /b %ERRORLEVEL%
)

cl.exe %CLFLAGS% /c deep2_link_stubs.cpp
if %ERRORLEVEL% NEQ 0 (
    echo STUB COMPILE FAILED
    exit /b %ERRORLEVEL%
)

cl.exe %CLFLAGS% /c ReverseIntegration.cpp
cl.exe %CLFLAGS% /c ReverseHotpatchEngine.cpp
cl.exe %CLFLAGS% /c ProductionProfiler.cpp
cl.exe %CLFLAGS% /c Chamber.cpp
cl.exe %CLFLAGS% /c BP16Streamer.cpp
cl.exe %CLFLAGS% /c MoERouter.cpp
cl.exe %CLFLAGS% /c MoEWeightProxy.cpp
cl.exe %CLFLAGS% /c MedusaDecoder.cpp
cl.exe %CLFLAGS% /c NUFusedPacker.cpp
cl.exe %CLFLAGS% /c WarmupScheduler.cpp
cl.exe %CLFLAGS% /c PlasmaGovernor.cpp
cl.exe %CLFLAGS% /c SovereignOutOfCoreRuntime.cpp
cl.exe %CLFLAGS% /c MARS.cpp

cl.exe %CLFLAGS% /Fe:Deep2_Elastic_Forward_Test.exe Deep2_Elastic_Forward_Test.obj Deep2Engine.obj ElasticResidencyManager.obj GhostCache.obj QuantKernelRegistry.obj GGUFLoader.obj ThreadPool.obj KVCache.obj ResidencyManager.obj deep2_link_stubs.obj MoEWeightsLoader.obj ReverseIntegration.obj ReverseHotpatchEngine.obj ProductionProfiler.obj Chamber.obj BP16Streamer.obj MoERouter.obj MoEWeightProxy.obj MedusaDecoder.obj NUFusedPacker.obj WarmupScheduler.obj PlasmaGovernor.obj SovereignOutOfCoreRuntime.obj MARS.obj
if %ERRORLEVEL% NEQ 0 (
    echo LINK FAILED
    exit /b %ERRORLEVEL%
)

echo BUILD OK
Deep2_Elastic_Forward_Test.exe "G:\Franken\BackwardsUnlock\1b\unlock-1B-Q4_K_M.gguf"
