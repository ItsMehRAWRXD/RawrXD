@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
cd /d d:\rawrxd\src\deep2

set CLFLAGS=/nologo /W3 /O2 /arch:AVX2 /EHsc /std:c++20 /I. /I.. /I..\..\include /I..\sampling /D_CRT_SECURE_NO_WARNINGS

cl.exe %CLFLAGS% /c Deep2_Elastic_Forward_Test.cpp > __build_log.txt 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo COMPILE FAILED Deep2_Elastic_Forward_Test.cpp >> __build_log.txt
)

cl.exe %CLFLAGS% /c deep2_link_stubs.cpp >> __build_log.txt 2>&1
cl.exe %CLFLAGS% /c ReverseIntegration.cpp >> __build_log.txt 2>&1
cl.exe %CLFLAGS% /c ReverseHotpatchEngine.cpp >> __build_log.txt 2>&1
cl.exe %CLFLAGS% /c ProductionProfiler.cpp >> __build_log.txt 2>&1
cl.exe %CLFLAGS% /c Chamber.cpp >> __build_log.txt 2>&1
cl.exe %CLFLAGS% /c BP16Streamer.cpp >> __build_log.txt 2>&1
cl.exe %CLFLAGS% /c MoERouter.cpp >> __build_log.txt 2>&1
cl.exe %CLFLAGS% /c MoEWeightProxy.cpp >> __build_log.txt 2>&1
cl.exe %CLFLAGS% /c MedusaDecoder.cpp >> __build_log.txt 2>&1
cl.exe %CLFLAGS% /c NUFusedPacker.cpp >> __build_log.txt 2>&1
cl.exe %CLFLAGS% /c WarmupScheduler.cpp >> __build_log.txt 2>&1
cl.exe %CLFLAGS% /c PlasmaGovernor.cpp >> __build_log.txt 2>&1
cl.exe %CLFLAGS% /c SovereignOutOfCoreRuntime.cpp >> __build_log.txt 2>&1
cl.exe %CLFLAGS% /c MARS.cpp >> __build_log.txt 2>&1

cl.exe %CLFLAGS% /c CompressedKVCache.cpp >> __build_log.txt 2>&1
cl.exe %CLFLAGS% /c NVMeStream.cpp >> __build_log.txt 2>&1
cl.exe %CLFLAGS% /c SlidingWindowEngine.cpp >> __build_log.txt 2>&1
cl.exe %CLFLAGS% /c K2GlobalTensorIndex.cpp >> __build_log.txt 2>&1
cl.exe %CLFLAGS% /c RouterPrefetchTelemetry.cpp >> __build_log.txt 2>&1
cl.exe %CLFLAGS% /c ToroidalKVCache.cpp >> __build_log.txt 2>&1
cl.exe %CLFLAGS% /c HotPatcher.cpp >> __build_log.txt 2>&1
cl.exe %CLFLAGS% /c DualGPUHook.cpp >> __build_log.txt 2>&1
cl.exe %CLFLAGS% /c QuantKernelMASM.cpp >> __build_log.txt 2>&1
cl.exe %CLFLAGS% /c ..\reverse\ReverseEngine.cpp >> __build_log.txt 2>&1
cl.exe %CLFLAGS% /c ..\reverse\ReverseModelLoader.cpp >> __build_log.txt 2>&1
cl.exe %CLFLAGS% /c ..\sampling\advanced_sampler.cpp >> __build_log.txt 2>&1

cl.exe %CLFLAGS% /Fe:Deep2_Elastic_Forward_Test.exe Deep2_Elastic_Forward_Test.obj Deep2Engine.obj ElasticResidencyManager.obj GhostCache.obj QuantKernelRegistry.obj GGUFLoader.obj ThreadPool.obj KVCache.obj ResidencyManager.obj deep2_link_stubs.obj MoEWeightsLoader.obj ReverseIntegration.obj ReverseHotpatchEngine.obj ProductionProfiler.obj Chamber.obj BP16Streamer.obj MoERouter.obj MoEWeightProxy.obj MedusaDecoder.obj NUFusedPacker.obj WarmupScheduler.obj PlasmaGovernor.obj SovereignOutOfCoreRuntime.obj MARS.obj CompressedKVCache.obj NVMeStream.obj SlidingWindowEngine.obj K2GlobalTensorIndex.obj RouterPrefetchTelemetry.obj ToroidalKVCache.obj HotPatcher.obj DualGPUHook.obj QuantKernelMASM.obj ReverseEngine.obj ReverseModelLoader.obj advanced_sampler.obj >> __build_log.txt 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo LINK FAILED >> __build_log.txt
) else (
    echo BUILD OK >> __build_log.txt
)
