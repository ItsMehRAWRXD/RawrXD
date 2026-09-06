// deep2_gpu_solo_decode_cert.cpp — STREAMER_GPU_SOLO_001 GGUF multi15 on R9700
#include "Deep2Engine.h"
#include "StreamerGpuSoloGate.hpp"
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <string>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

using namespace Deep2;

int main(int argc, char** argv) {
    SetEnvironmentVariableA("DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1", "1");
    if (!getenv("DEEP2_GPU_SELECT"))
        SetEnvironmentVariableA("DEEP2_GPU_SELECT", "R9700");
    const char* model = argc > 1 ? argv[1]
        : "G:\\~dev\\rawrxd\\models\\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf";
    printf("STREAMER_GPU_SOLO_001 DECODE\nModel: %s\n", model);

    GpuSoloReport topo{};
    RunStreamerGpuSoloSelect(topo);

    Deep2Engine engine;
    if (!engine.loadModel(model)) { printf("FAIL loadModel\n"); return 1; }
    const auto& mw = engine.getModelWeights();
    EngineConfig cfg{};
    cfg.hiddenDim = mw.hiddenDim; cfg.numLayers = mw.numLayers;
    cfg.numHeads = mw.numHeads; cfg.numKVHeads = mw.numKVHeads;
    cfg.headDim = mw.headDim; cfg.vocabSize = mw.vocabSize;
    cfg.maxSeqLen = 4096; cfg.useKVCache = true; cfg.useThreadPool = true;
    cfg.numThreads = 16;
    if (!engine.initialize(cfg)) { printf("FAIL initialize\n"); return 1; }
    engine.enableVulkan(true);

    const bool vk = engine.isVulkanEnabled();
    std::string selected = "(none)";
    if (vk && engine.getVulkanCompute())
        selected = engine.getVulkanCompute()->GetDeviceInfo().device_name;

    GenerationOptions opts{};
    opts.maxTokens = 15; opts.temperature = 0.0f; opts.topK = 1; opts.seed = 42;
    size_t n = 0;
    auto t0 = std::chrono::steady_clock::now();
    engine.generateStream("hello", opts, [&](int32_t, const std::string&) -> bool {
        ++n; return true;
    });
    auto t1 = std::chrono::steady_clock::now();
    const double sec = std::chrono::duration<double>(t1 - t0).count();
    const double e2e = (n > 0 && sec > 0.0) ? (double)n / sec : 0.0;

    const uint64_t ok = engine.vulkanGemvSuccessCount();
    const uint64_t fail = engine.vulkanGemvFallbackCount();
    const unsigned active = (vk && ok > 0) ? 1u : 0u;
    const char* backend = active ? "GPU" : (vk ? "CPU_FALLBACK" : "CPU_NATIVE");
    printf("DEEP2_COMPUTE_BACKEND=%s\n", backend);
    printf("DEEP2_GPU_SELECTED=%s\n", selected.c_str());
    printf("DEEP2_GPU_COMPUTE_ACTIVE=%u\n", active);
    printf("DEEP2_CPU_FALLBACK_USED=%u\n", fail > 0 ? 1u : 0u);
    printf("DEEP2_REAL_WEIGHT_LAYERS=%llu\n", (unsigned long long)ok);
    printf("DEEP2_REAL_GPU_FORWARD=%u\n", ok > 0 ? 1u : 0u);
    printf("DEEP2_GPU_COUNT=%u\n", topo.adapterCount);
    printf("DUAL_GPU_HOST=%s\n", topo.adapterCount >= 2 ? "YES" : "NO");
    printf("multi15_tokens=%zu e2e_tok_s=%.3f gemv_ok=%llu fail=%llu\n",
           n, e2e, (unsigned long long)ok, (unsigned long long)fail);

    FILE* f = fopen("G:\\~dev\\rawrxd\\evidence\\STREAMER_GPU_SOLO_001\\DECODE_TINYLLAMA.txt", "w");
    if (f) {
        fprintf(f, "model=%s\nDEEP2_COMPUTE_BACKEND=%s\nDEEP2_GPU_SELECTED=%s\n",
                model, backend, selected.c_str());
        fprintf(f, "DEEP2_GPU_COMPUTE_ACTIVE=%u\nDEEP2_CPU_FALLBACK_USED=%u\n",
                active, fail > 0 ? 1u : 0u);
        fprintf(f, "DEEP2_REAL_WEIGHT_LAYERS=%llu\nDEEP2_REAL_GPU_FORWARD=%u\n",
                (unsigned long long)ok, ok > 0 ? 1u : 0u);
        fprintf(f, "multi15_tokens=%zu e2e_tok_s=%.3f gemv_ok=%llu gemv_fail=%llu\n",
                n, e2e, (unsigned long long)ok, (unsigned long long)fail);
        fprintf(f, "CPU_REF_multi15_decode=12.1-12.6\n");
        fclose(f);
    }
    return (vk && ok > 0 && n > 0) ? 0 : 2;
}
