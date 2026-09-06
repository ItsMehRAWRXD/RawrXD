// deep2_multi_gpu_layer_cert.cpp — STREAMER_MULTI_GPU_LAYER_001 contiguous placement
#include "Deep2Engine.h"
#include "Deep2DeviceManager.hpp"
#include "Deep2MultiGpuLayerPlan.hpp"
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
    _putenv_s("RAWRXD_GPU_POLICY", "AUTO");
    _putenv_s("RAWRXD_GPU_DEVICES", "ALL");
    _putenv_s("DEEP2_GPU_SELECT", "");
    _putenv_s("RAWRXD_GPU_SELECT", "");
    _putenv_s("RAWRXD_GPU_NAME", "");
#endif
    const char* model = argc > 1 ? argv[1]
        : "G:\\~dev\\rawrxd\\models\\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf";
    printf("STREAMER_MULTI_GPU_LAYER_001\nModel: %s\n", model);
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\STREAMER_MULTI_GPU_LAYER_001", nullptr);

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

    const MultiGpuLayerPlan& plan = engine.multiGpuLayerPlan();
    Deep2MultiGpu_EmitPlanWitnesses(nullptr, plan);

    if (!plan.active || plan.plannedCount < 2 || engine.vulkanDeviceCount() < 2) {
        printf("FAIL multi plan not active opened=%u planned=%u\n",
               engine.vulkanDeviceCount(), plan.plannedCount);
        return 2;
    }

    RunGen(engine, "hi", 1);
    auto t0 = std::chrono::steady_clock::now();
    size_t n = RunGen(engine, "hello", 15);
    auto t1 = std::chrono::steady_clock::now();
    double sec = std::chrono::duration<double>(t1 - t0).count();
    double tps = (n > 0 && sec > 0) ? (double)n / sec : 0.0;

    const MultiGpuLayerPlan& planLive = engine.multiGpuLayerPlan();
    unsigned executing = 0;
    for (unsigned s = 0; s < planLive.plannedCount; ++s) {
        const uint64_t ops = engine.vulkanSlotGemvSuccess(s);
        const uint64_t up = engine.vulkanSlotWeightUploads(s);
        const uint64_t hit = engine.vulkanSlotWeightHits(s);
        printf("DEEP2_DEVICE_%u_COMPUTE_OPS=%llu\n", s, (unsigned long long)ops);
        printf("DEEP2_DEVICE_%u_WEIGHT_UPLOADS=%llu\n", s, (unsigned long long)up);
        printf("DEEP2_DEVICE_%u_WEIGHT_HITS=%llu\n", s, (unsigned long long)hit);
        printf("DEEP2_DEVICE_%u_LAYER_EXECS=%u\n", s, planLive.slotLayerExecs[s]);
        printf("DEEP2_DEVICE_%u_NAME=%s\n", s,
               engine.getVulkanComputeSlot(s)
                   ? engine.getVulkanComputeSlot(s)->GetDeviceInfo().device_name.c_str()
                   : planLive.name[s]);
        if (ops > 0 && up > 0 && planLive.slotLayerExecs[s] > 0) ++executing;
    }

    MultiGpuLayerPlan planOut = planLive;
    planOut.executingCount = executing;
    planOut.openedCount = engine.vulkanDeviceCount();

    const uint64_t fail = engine.vulkanGemvFallbackCount();
    const uint64_t unplanned = engine.vulkanUnplannedFallbacks();
    const bool pass =
        planOut.active &&
        planOut.openedCount >= 2 &&
        planOut.plannedCount >= 2 &&
        executing >= 2 &&
        planOut.layersExecuted >= planOut.numLayers &&
        fail == 0 &&
        unplanned == 0 &&
        n > 0;

    printf("DEEP2_MULTI_GPU_PLAN=%s\n", planOut.active ? "ACTIVE" : "INACTIVE");
    printf("DEEP2_DEVICE_OPENED_COUNT=%u\n", planOut.openedCount);
    printf("DEEP2_DEVICE_PLANNED_COUNT=%u\n", planOut.plannedCount);
    printf("DEEP2_DEVICE_EXECUTING_COUNT=%u\n", executing);
    printf("DEEP2_LAYERS_EXECUTED=%u/%u\n", planOut.layersExecuted, planOut.numLayers);
    printf("DEEP2_REAL_GPU_LAYER_EXEC=%u\n",
           (planOut.layersExecuted >= planOut.numLayers && planOut.numLayers > 0) ? 1u : 0u);
    printf("DEEP2_CPU_FALLBACK_USED=%u\n", fail > 0 ? 1u : 0u);
    printf("DEEP2_UNPLANNED_DEVICE_FALLBACKS=%llu\n", (unsigned long long)unplanned);
    printf("warm_multi15_e2e_tok_s=%.3f tokens=%zu\n", tps, n);
    printf("STREAMER_MULTI_GPU_LAYER_001=%s\n", pass ? "PASS" : "FAIL");

    FILE* f = fopen("G:\\~dev\\rawrxd\\evidence\\STREAMER_MULTI_GPU_LAYER_001\\GATE_STATUS.txt", "w");
    if (f) {
        Deep2MultiGpu_EmitPlanWitnesses(f, planOut);
        for (unsigned s = 0; s < planLive.plannedCount; ++s) {
            fprintf(f, "DEEP2_DEVICE_%u_COMPUTE_OPS=%llu\n", s,
                    (unsigned long long)engine.vulkanSlotGemvSuccess(s));
            fprintf(f, "DEEP2_DEVICE_%u_WEIGHT_UPLOADS=%llu\n", s,
                    (unsigned long long)engine.vulkanSlotWeightUploads(s));
            fprintf(f, "DEEP2_DEVICE_%u_WEIGHT_HITS=%llu\n", s,
                    (unsigned long long)engine.vulkanSlotWeightHits(s));
        }
        fprintf(f, "DEEP2_CPU_FALLBACK_USED=%u\n", fail > 0 ? 1u : 0u);
        fprintf(f, "DEEP2_UNPLANNED_DEVICE_FALLBACKS=%llu\n", (unsigned long long)unplanned);
        fprintf(f, "warm_multi15_e2e_tok_s=%.3f\n", tps);
        fprintf(f, "STREAMER_MULTI_GPU_LAYER_001=%s\n", pass ? "PASS" : "FAIL");
        fclose(f);
    }
    fflush(stdout);
    fflush(stderr);
    // Dual AMD Vulkan + CRT teardown heap-corrupts; seal on witnesses above.
    _exit(pass ? 0 : 2);
}
