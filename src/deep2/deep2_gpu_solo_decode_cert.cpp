// deep2_gpu_solo_decode_cert.cpp — generic single-GPU path (AUTO → best_compute)
#include "Deep2Engine.h"
#include "Deep2DeviceManager.hpp"
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
    const char* model = argc > 1 ? argv[1]
        : "G:\\~dev\\rawrxd\\models\\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf";
    printf("STREAMER_GPU_SOLO_001 (generic single-GPU)\nModel: %s\n", model);

    DeviceManagerSnapshot snap{};
    Deep2Device_Enumerate(snap);
    Deep2Device_ApplyPolicy(snap);
    Deep2Device_EmitWitnesses(nullptr, snap);

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
    CPUInference::VulkanCompute* vc = nullptr;
    if (vk) {
        vc = engine.getVulkanCompute();
        if (vc) selected = vc->GetDeviceInfo().device_name;
    }

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
    const uint64_t dAlloc = vc ? vc->GemvDescriptorAllocations() : 0;
    const uint64_t dReuse = vc ? vc->GemvDescriptorReuses() : 0;
    const unsigned active = (vk && ok > 0) ? 1u : 0u;
    const unsigned realGemv = ok > 1 ? 1u : 0u;
    printf("DEEP2_GPU_SELECTED=%s\n", selected.c_str());
    printf("DEEP2_GPU_COMPUTE_ACTIVE=%u\n", active);
    printf("DEEP2_CPU_FALLBACK_USED=%u\n", fail > 0 ? 1u : 0u);
    printf("DEEP2_REAL_GPU_GEMV=%u\n", realGemv);
    printf("DEEP2_REAL_GPU_FORWARD=%u\n", 0u);
    printf("DEEP2_GPU_DESCRIPTOR_ALLOCATIONS=%llu\n", (unsigned long long)dAlloc);
    printf("DEEP2_GPU_DESCRIPTOR_REUSES=%llu\n", (unsigned long long)dReuse);
    printf("DEEP2_GPU_GEMV_SUCCESS=%llu\n", (unsigned long long)ok);
    printf("multi15_tokens=%zu e2e_tok_s=%.3f\n", n, e2e);
    printf("STREAMER_GPU_SOLO_BLOCKER=%s\n",
           realGemv ? "UPLOAD_BOUND_NO_RESIDENT_WEIGHTS" : "NO_GPU_GEMV");

    FILE* f = fopen("G:\\~dev\\rawrxd\\evidence\\STREAMER_GPU_SOLO_001\\DECODE_TINYLLAMA.txt", "w");
    if (f) {
        Deep2Device_EmitWitnesses(f, snap);
        fprintf(f, "DEEP2_GPU_SELECTED=%s\nDEEP2_REAL_GPU_GEMV=%u\nDEEP2_REAL_GPU_FORWARD=0\n",
                selected.c_str(), realGemv);
        fprintf(f, "DEEP2_GPU_DESCRIPTOR_ALLOCATIONS=%llu\nDEEP2_GPU_DESCRIPTOR_REUSES=%llu\n",
                (unsigned long long)dAlloc, (unsigned long long)dReuse);
        fprintf(f, "DEEP2_GPU_GEMV_SUCCESS=%llu\nmulti15_e2e_tok_s=%.3f\n",
                (unsigned long long)ok, e2e);
        fprintf(f, "CPU_REF_multi15_decode=12.1-12.6\n");
        fclose(f);
    }
    return (vk && ok > 1 && dAlloc == 1 && n > 0) ? 0 : 2;
}
