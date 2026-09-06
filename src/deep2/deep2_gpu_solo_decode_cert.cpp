// deep2_gpu_solo_decode_cert.cpp — SingleGpu primary: warm resident GEMV multi15
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
    SetEnvironmentVariableA("DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1", "1");
    SetEnvironmentVariableA("RAWRXD_GPU_POLICY", "AUTO");
    const char* model = argc > 1 ? argv[1]
        : "G:\\~dev\\rawrxd\\models\\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf";
    printf("STREAMER_GPU_SOLO_001 resident-GEMV smoke\nModel: %s\n", model);

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
    engine.enableAllEnhancements();

    const bool vk = engine.isVulkanEnabled();
    std::string selected = "(none)";
    CPUInference::VulkanCompute* vc = nullptr;
    if (vk) {
        vc = engine.getVulkanCompute();
        if (vc) selected = vc->GetDeviceInfo().device_name;
    }

    // Cold pass populates DEVICE_LOCAL weight residents.
    const size_t warmN = RunGen(engine, "hi", 1);
    const uint64_t uploadsAfterWarm = vc ? vc->GemvWeightUploads() : 0;
    const uint64_t hitsAfterWarm = vc ? vc->GemvWeightHits() : 0;

    auto t0 = std::chrono::steady_clock::now();
    const size_t n = RunGen(engine, "hello", 15);
    auto t1 = std::chrono::steady_clock::now();
    const double sec = std::chrono::duration<double>(t1 - t0).count();
    const double e2e = (n > 0 && sec > 0.0) ? (double)n / sec : 0.0;

    const uint64_t ok = engine.vulkanGemvSuccessCount();
    const uint64_t fail = engine.vulkanGemvFallbackCount();
    const uint64_t dAlloc = vc ? vc->GemvDescriptorAllocations() : 0;
    const uint64_t dReuse = vc ? vc->GemvDescriptorReuses() : 0;
    const uint64_t wUp = vc ? vc->GemvWeightUploads() : 0;
    const uint64_t wHit = vc ? vc->GemvWeightHits() : 0;
    const uint64_t resB = vc ? vc->GemvResidentBytes() : 0;
    const unsigned active = (vk && ok > 0) ? 1u : 0u;
    const unsigned realGemv = ok > 1 ? 1u : 0u;
    const unsigned residentOk = (wUp > 0 && wHit > wUp && resB > 0) ? 1u : 0u;

    printf("DEEP2_GPU_SELECTED=%s\n", selected.c_str());
    printf("DEEP2_GPU_COMPUTE_ACTIVE=%u\n", active);
    printf("DEEP2_CPU_FALLBACK_USED=%u\n", fail > 0 ? 1u : 0u);
    printf("DEEP2_REAL_GPU_GEMV=%u\n", realGemv);
    printf("DEEP2_REAL_GPU_FORWARD=%u\n", 0u);
    printf("DEEP2_GPU_DESCRIPTOR_ALLOCATIONS=%llu\n", (unsigned long long)dAlloc);
    printf("DEEP2_GPU_DESCRIPTOR_REUSES=%llu\n", (unsigned long long)dReuse);
    printf("DEEP2_GPU_WEIGHT_UPLOADS=%llu\n", (unsigned long long)wUp);
    printf("DEEP2_GPU_WEIGHT_HITS=%llu\n", (unsigned long long)wHit);
    printf("DEEP2_GPU_RESIDENT_BYTES=%llu\n", (unsigned long long)resB);
    printf("DEEP2_GPU_WEIGHT_UPLOADS_AFTER_WARM=%llu\n", (unsigned long long)uploadsAfterWarm);
    printf("DEEP2_GPU_WEIGHT_HITS_AFTER_WARM=%llu\n", (unsigned long long)hitsAfterWarm);
    printf("DEEP2_GPU_GEMV_SUCCESS=%llu\n", (unsigned long long)ok);
    printf("warm1_tokens=%zu multi15_tokens=%zu warm_e2e_tok_s=%.3f\n", warmN, n, e2e);
    printf("STREAMER_GPU_SOLO_BLOCKER=%s\n",
           !realGemv ? "NO_GPU_GEMV"
           : !residentOk ? "WEIGHT_CACHE_MISS"
           : (e2e < 2.0 ? "RESIDENT_BUT_STILL_SLOW" : "NONE"));

    FILE* f = fopen("G:\\~dev\\rawrxd\\evidence\\STREAMER_GPU_SOLO_001\\DECODE_TINYLLAMA.txt", "w");
    if (f) {
        Deep2Device_EmitWitnesses(f, snap);
        fprintf(f, "DEEP2_GPU_SELECTED=%s\nDEEP2_REAL_GPU_GEMV=%u\nDEEP2_REAL_GPU_FORWARD=0\n",
                selected.c_str(), realGemv);
        fprintf(f, "DEEP2_GPU_DESCRIPTOR_ALLOCATIONS=%llu\nDEEP2_GPU_DESCRIPTOR_REUSES=%llu\n",
                (unsigned long long)dAlloc, (unsigned long long)dReuse);
        fprintf(f, "DEEP2_GPU_WEIGHT_UPLOADS=%llu\nDEEP2_GPU_WEIGHT_HITS=%llu\n",
                (unsigned long long)wUp, (unsigned long long)wHit);
        fprintf(f, "DEEP2_GPU_RESIDENT_BYTES=%llu\n", (unsigned long long)resB);
        fprintf(f, "DEEP2_GPU_GEMV_SUCCESS=%llu\nwarm_multi15_e2e_tok_s=%.3f\n",
                (unsigned long long)ok, e2e);
        fprintf(f, "CPU_REF_multi15_decode=12.1-12.6\n");
        fclose(f);
    }
    const bool pass = vk && ok > 1 && dAlloc == 1 && fail == 0 && residentOk && n > 0;
    return pass ? 0 : 2;
}
