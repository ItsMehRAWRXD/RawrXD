@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
cd /d d:\rawrxd\src\deep2

set CLFLAGS=/nologo /W3 /O2 /arch:AVX2 /EHsc /std:c++20 /I. /I.. /I..\..\include /I..\sampling /D_CRT_SECURE_NO_WARNINGS

cl.exe %CLFLAGS% /c test_generate_token.cpp
if %ERRORLEVEL% NEQ 0 (
    echo COMPILE FAILED
    exit /b %ERRORLEVEL%
)

cl.exe %CLFLAGS% /Fe:test_generate_token.exe test_generate_token.obj ^
    Deep2Engine.obj ^
    GGUFLoader.obj ^
    ElasticResidencyManager.obj ^
    GhostCache.obj ^
    QuantKernelRegistry.obj ^
    KVCache.obj ^
    ThreadPool.obj ^
    ModelLoader.obj ^
    MoERouter.obj ^
    MoEWeightProxy.obj ^
    MoEWeightsLoader.obj ^
    ResidencyManager.obj ^
    ResidencyTrace.obj ^
    RuntimePlanner.obj ^
    TrailBrake.obj ^
    TensorHop.obj ^
    StreamRouter_Dispatch.obj ^
    FusedInference_Dispatch.obj ^
    Deep2ExecutionGraph.obj ^
    Deep2Bridge.obj ^
    Deep2Discovery.obj ^
    DeepSeekMoELoader.obj ^
    K2GlobalTensorIndex.obj ^
    K2MLAWeights.obj ^
    K2MoEWeights.obj ^
    K2TimeLimitedServing.obj ^
    K2TokenEmbedding.obj ^
    IQQuantKernels.obj ^
    RawrXDInferenceAdapter.obj ^
    RawrXDSampler.obj ^
    RawrXDTokenizer.obj ^
    PatchCache.obj ^
    GoalSystem.obj ^
    HotPatcher.obj ^
    AntiPatcher.obj ^
    BottleTTL.obj ^
    CPUFrequency.obj ^
    InferenceSession.obj ^
    IOCPGGUFLoader.obj ^
    QuantKB.obj ^
    VAL038_Benchmark_Harness.obj ^
    TreeAttention_Fused_VAL038.obj ^
    softmax_lut_avx512.obj ^
    Sovereign_Attention_KV_AVX512.obj ^
    sovereign_q4k_gemv.obj ^
    sovereign_q4_0_gemv.obj ^
    sovereign_q4_1_gemv.obj ^
    sovereign_q5_k_gemv.obj ^
    sovereign_q8_0_gemv.obj ^
    sovereign_q2_k_gemv.obj ^
    sovereign_iq2_xxs_gemv.obj ^
    sovereign_iq3_xxs_gemv.obj ^
    sovereign_iq4_nl_gemv.obj ^
    sovereign_moe_fused.obj ^
    /link /LIBPATH:"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\lib\x64" /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64" /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64"
if %ERRORLEVEL% NEQ 0 (
    echo LINK FAILED
    exit /b %ERRORLEVEL%
)

echo BUILD OK
test_generate_token.exe
