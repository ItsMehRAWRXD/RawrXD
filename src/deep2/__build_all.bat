@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
cd /d d:\rawrxd\src\deep2

set CLFLAGS=/nologo /W3 /O2 /arch:AVX2 /EHsc /std:c++20 /I. /I.. /I..\..\include /I..\sampling /D_CRT_SECURE_NO_WARNINGS

echo === Compiling all TUs ===
cl.exe %CLFLAGS% /c Deep2_Elastic_Forward_Test.cpp
cl.exe %CLFLAGS% /c Deep2_Elastic_Generation_Test.cpp
cl.exe %CLFLAGS% /c deep2_link_stubs.cpp
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
cl.exe %CLFLAGS% /c CompressedKVCache.cpp
cl.exe %CLFLAGS% /c NVMeStream.cpp
cl.exe %CLFLAGS% /c SlidingWindowEngine.cpp
cl.exe %CLFLAGS% /c K2GlobalTensorIndex.cpp
cl.exe %CLFLAGS% /c RouterPrefetchTelemetry.cpp
cl.exe %CLFLAGS% /c ToroidalKVCache.cpp
cl.exe %CLFLAGS% /c HotPatcher.cpp
cl.exe %CLFLAGS% /c HotPatcherSafety.cpp
cl.exe %CLFLAGS% /c DualGPUHook.cpp
cl.exe %CLFLAGS% /c QuantKernelMASM.cpp
cl.exe %CLFLAGS% /c asm_stubs.cpp
cl.exe %CLFLAGS% /c ..\reverse\ReverseEngine.cpp
cl.exe %CLFLAGS% /c ..\reverse\ReverseModelLoader.cpp
cl.exe %CLFLAGS% /c ..\sampling\advanced_sampler.cpp

echo === Linking ===
cl.exe %CLFLAGS% /Fe:Deep2_Elastic_Forward_Test.exe Deep2_Elastic_Forward_Test.obj Deep2Engine.obj ElasticResidencyManager.obj GhostCache.obj QuantKernelRegistry.obj GGUFLoader.obj ThreadPool.obj KVCache.obj ResidencyManager.obj deep2_link_stubs.obj MoEWeightsLoader.obj ReverseIntegration.obj ReverseHotpatchEngine.obj ProductionProfiler.obj Chamber.obj BP16Streamer.obj MoERouter.obj MoEWeightProxy.obj MedusaDecoder.obj NUFusedPacker.obj WarmupScheduler.obj PlasmaGovernor.obj SovereignOutOfCoreRuntime.obj MARS.obj CompressedKVCache.obj NVMeStream.obj SlidingWindowEngine.obj K2GlobalTensorIndex.obj RouterPrefetchTelemetry.obj ToroidalKVCache.obj HotPatcher.obj HotPatcherSafety.obj DualGPUHook.obj QuantKernelMASM.obj asm_stubs.obj ReverseEngine.obj ReverseModelLoader.obj advanced_sampler.obj

cl.exe %CLFLAGS% /Fe:Deep2_Elastic_Generation_Test.exe Deep2_Elastic_Generation_Test.obj Deep2Engine.obj ElasticResidencyManager.obj GhostCache.obj QuantKernelRegistry.obj GGUFLoader.obj ThreadPool.obj KVCache.obj ResidencyManager.obj deep2_link_stubs.obj MoEWeightsLoader.obj ReverseIntegration.obj ReverseHotpatchEngine.obj ProductionProfiler.obj Chamber.obj BP16Streamer.obj MoERouter.obj MoEWeightProxy.obj MedusaDecoder.obj NUFusedPacker.obj WarmupScheduler.obj PlasmaGovernor.obj SovereignOutOfCoreRuntime.obj MARS.obj CompressedKVCache.obj NVMeStream.obj SlidingWindowEngine.obj K2GlobalTensorIndex.obj RouterPrefetchTelemetry.obj ToroidalKVCache.obj HotPatcher.obj HotPatcherSafety.obj DualGPUHook.obj QuantKernelMASM.obj asm_stubs.obj ReverseEngine.obj ReverseModelLoader.obj advanced_sampler.obj

echo === Done ===
