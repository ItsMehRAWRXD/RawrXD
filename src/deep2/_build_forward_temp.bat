@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
cd /d F:\~dev\rawrxd\src\deep2

set CLFLAGS=/nologo /W3 /O2 /arch:AVX2 /EHsc /std:c++20 /I. /I.. /I..\..\include /I..\sampling /D_CRT_SECURE_NO_WARNINGS

cl.exe %CLFLAGS% /c Deep2_Elastic_Forward_Test.cpp
if %ERRORLEVEL% NEQ 0 (
    echo COMPILE FAILED
    exit /b %ERRORLEVEL%
)

cl.exe %CLFLAGS% /Fe:Deep2_Elastic_Forward_Test.exe Deep2_Elastic_Forward_Test.obj Deep2Engine.obj ElasticResidencyManager.obj GhostCache.obj QuantKernelRegistry.obj GGUFLoader.obj ThreadPool.obj KVCache.obj ResidencyManager.obj deep2_link_stubs.obj MoEWeightsLoader.obj ReverseIntegration.obj ReverseHotpatchEngine.obj ProductionProfiler.obj Chamber.obj BP16Streamer.obj MoERouter.obj MoEWeightProxy.obj MedusaDecoder.obj NUFusedPacker.obj WarmupScheduler.obj PlasmaGovernor.obj SovereignOutOfCoreRuntime.obj MARS.obj CompressedKVCache.obj NVMeStream.obj SlidingWindowEngine.obj K2GlobalTensorIndex.obj RouterPrefetchTelemetry.obj ToroidalKVCache.obj HotPatcher.obj DualGPUHook.obj QuantKernelMASM.obj ReverseEngine.obj ReverseModelLoader.obj advanced_sampler.obj
if %ERRORLEVEL% NEQ 0 (
    echo LINK FAILED
    exit /b %ERRORLEVEL%
)

echo BUILD OK
