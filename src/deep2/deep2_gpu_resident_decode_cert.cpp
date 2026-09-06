// deep2_gpu_resident_decode_cert.cpp — STREAMER_GPU_RESIDENT_DECODE_001
#include "Deep2Engine.h"
#include "Deep2DeviceManager.hpp"
#include "Deep2GpuForward.hpp"
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

using namespace Deep2;

static size_t RunGen(Deep2Engine& engine, const char* prompt, int maxTok) {
    GenerationOptions opts{};
    opts.maxTokens = maxTok; opts.temperature = 0.0f; opts.topK = 1; opts.seed = 42;
    size_t n = 0;
    engine.generateStream(prompt, opts, [&](int32_t, const std::string&) -> bool {
        ++n; return true;
    });
    return n;
}

int main(int argc, char** argv) {
#ifdef _WIN32
    SetEnvironmentVariableA("DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1", "1");
    _putenv_s("RAWRXD_GPU_POLICY", "HYBRID");
    _putenv_s("RAWRXD_GPU_DEVICES", "ALL");
    _putenv_s("DEEP2_HYBRID", "1");
    _putenv_s("DEEP2_HYBRID_CPU_LAYERS", "2");
    _putenv_s("RAWRXD_GPU_FWD", "1");
#endif
    const char* model = argc > 1 ? argv[1]
        : "G:\\~dev\\rawrxd\\models\\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf";
    printf("STREAMER_GPU_RESIDENT_DECODE_001\nModel: %s\n", model);
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\STREAMER_GPU_RESIDENT_DECODE_001", nullptr);

    Deep2Engine engine;
    if (!engine.loadModel(model)) { printf("FAIL load\n"); return 1; }
    const auto& mw = engine.getModelWeights();
    EngineConfig cfg{};
    cfg.hiddenDim = mw.hiddenDim; cfg.numLayers = mw.numLayers;
    cfg.numHeads = mw.numHeads; cfg.numKVHeads = mw.numKVHeads;
    cfg.headDim = mw.headDim; cfg.vocabSize = mw.vocabSize;
    cfg.maxSeqLen = 4096; cfg.useKVCache = true; cfg.useThreadPool = true;
    cfg.numThreads = 16;
    if (!engine.initialize(cfg)) { printf("FAIL init\n"); return 1; }
    engine.enableVulkan(true);
    engine.enableMedusa(false);

    RunGen(engine, "hi", 1); // warm
    auto t0 = std::chrono::steady_clock::now();
    size_t n = RunGen(engine, "hello", 15);
    auto t1 = std::chrono::steady_clock::now();
    double sec = std::chrono::duration<double>(t1 - t0).count();
    double tps = (n > 0 && sec > 0) ? (double)n / sec : 0.0;

    const auto& c = engine.gpuForwardCounters();
    engine.emitLiveDecodeWitnesses(nullptr);

    const uint32_t nLayers = (uint32_t)mw.numLayers;
    const bool pass =
        n > 0 &&
        c.liveDecodeResidentTokens > 0 &&
        c.hostForwardLayerCalls == 0 &&
        c.hostMaterializations == 0 &&
        c.intraSlotHostTransfers == 0 &&
        c.gpuLayersLastToken == nLayers &&
        engine.vulkanGemvFallbackCount() == 0 &&
        engine.vulkanUnplannedFallbacks() == 0 &&
        engine.isRealGpuForward();

    printf("warm_multi15_e2e_tok_s=%.3f tokens=%zu\n", tps, n);
    printf("STREAMER_GPU_RESIDENT_DECODE_001=%s\n", pass ? "PASS" : "FAIL");

    FILE* f = fopen("G:\\~dev\\rawrxd\\evidence\\STREAMER_GPU_RESIDENT_DECODE_001\\GATE_STATUS.txt", "w");
    if (f) {
        engine.emitLiveDecodeWitnesses(f);
        fprintf(f, "warm_multi15_e2e_tok_s=%.3f\n", tps);
        fprintf(f, "STREAMER_GPU_RESIDENT_DECODE_001=%s\n", pass ? "PASS" : "FAIL");
        fclose(f);
    }
    fflush(stdout);
    _exit(pass ? 0 : 2);
}
