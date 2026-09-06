// deep2_hybrid_all_hw_cert.cpp — STREAMER_HYBRID_ALL_HW_001 CPU+GPU planned layers
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
    _putenv_s("RAWRXD_GPU_POLICY", "HYBRID");
    _putenv_s("RAWRXD_GPU_DEVICES", "ALL");
    _putenv_s("DEEP2_HYBRID", "1");
    _putenv_s("DEEP2_HYBRID_CPU_LAYERS", "2");
    _putenv_s("DEEP2_GPU_SELECT", "");
    _putenv_s("RAWRXD_GPU_SELECT", "");
    _putenv_s("RAWRXD_GPU_NAME", "");
#endif
    const char* model = argc > 1 ? argv[1]
        : "G:\\~dev\\rawrxd\\models\\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf";
    printf("STREAMER_HYBRID_ALL_HW_001\nModel: %s\n", model);
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\STREAMER_HYBRID_ALL_HW_001", nullptr);

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

    const MultiGpuLayerPlan& plan0 = engine.multiGpuLayerPlan();
    Deep2MultiGpu_EmitPlanWitnesses(nullptr, plan0);

    if (!plan0.active || !plan0.hybrid || plan0.gpuSlotCount < 1 ||
        plan0.plannedCount <= plan0.gpuSlotCount) {
        printf("FAIL hybrid plan inactive hybrid=%d gpu=%u planned=%u\n",
               plan0.hybrid ? 1 : 0, plan0.gpuSlotCount, plan0.plannedCount);
        return 2;
    }

    RunGen(engine, "hi", 1);
    auto t0 = std::chrono::steady_clock::now();
    size_t n = RunGen(engine, "hello", 15);
    auto t1 = std::chrono::steady_clock::now();
    double sec = std::chrono::duration<double>(t1 - t0).count();
    double tps = (n > 0 && sec > 0) ? (double)n / sec : 0.0;

    const MultiGpuLayerPlan& plan = engine.multiGpuLayerPlan();
    unsigned gpuExec = 0, cpuExec = 0;
    for (unsigned s = 0; s < plan.plannedCount; ++s) {
        printf("DEEP2_PLAN_SLOT_%u_KIND=%s LAYER_EXECS=%u RANGE=%u-%u\n",
               s, plan.isCpuSlot[s] ? "CPU" : "GPU",
               plan.slotLayerExecs[s], plan.rangeLo[s], plan.rangeHi[s]);
        if (plan.isCpuSlot[s]) {
            if (plan.slotLayerExecs[s] > 0) ++cpuExec;
        } else {
            const uint64_t ops = engine.vulkanSlotGemvSuccess(s);
            const uint64_t up = engine.vulkanSlotWeightUploads(s);
            printf("DEEP2_DEVICE_%u_COMPUTE_OPS=%llu UPLOADS=%llu\n", s,
                   (unsigned long long)ops, (unsigned long long)up);
            if (ops > 0 && plan.slotLayerExecs[s] > 0) ++gpuExec;
        }
    }

    const uint64_t fail = engine.vulkanGemvFallbackCount();
    const uint64_t unplanned = engine.vulkanUnplannedFallbacks();
    const uint64_t cpuOps = engine.plannedCpuGemvOps();
    const uint64_t gpuOps = engine.plannedGpuGemvOps();
    const bool pass =
        plan.active && plan.hybrid &&
        plan.openedCount >= 1 &&
        plan.layersExecuted >= plan.numLayers &&
        gpuExec >= 1 && cpuExec >= 1 &&
        cpuOps > 0 && gpuOps > 0 &&
        fail == 0 && unplanned == 0 &&
        n > 0;

    printf("DEEP2_HYBRID_PLAN=%s\n", plan.hybrid ? "ACTIVE" : "INACTIVE");
    printf("DEEP2_LAYERS_EXECUTED=%u/%u\n", plan.layersExecuted, plan.numLayers);
    printf("DEEP2_REAL_GPU_LAYER_EXEC=%u\n",
           (plan.layersExecuted >= plan.numLayers && plan.numLayers > 0) ? 1u : 0u);
    printf("DEEP2_PLANNED_CPU_GEMV_OPS=%llu\n", (unsigned long long)cpuOps);
    printf("DEEP2_PLANNED_GPU_GEMV_OPS=%llu\n", (unsigned long long)gpuOps);
    printf("DEEP2_CPU_FALLBACK_USED=%u\n", fail > 0 ? 1u : 0u);
    printf("DEEP2_UNPLANNED_DEVICE_FALLBACKS=%llu\n", (unsigned long long)unplanned);
    printf("warm_multi15_e2e_tok_s=%.3f tokens=%zu\n", tps, n);
    printf("STREAMER_HYBRID_ALL_HW_001=%s\n", pass ? "PASS" : "FAIL");

    FILE* f = fopen("G:\\~dev\\rawrxd\\evidence\\STREAMER_HYBRID_ALL_HW_001\\GATE_STATUS.txt", "w");
    if (f) {
        Deep2Device_EmitWitnesses(f, snap);
        Deep2MultiGpu_EmitPlanWitnesses(f, plan);
        fprintf(f, "DEEP2_PLANNED_CPU_GEMV_OPS=%llu\n", (unsigned long long)cpuOps);
        fprintf(f, "DEEP2_PLANNED_GPU_GEMV_OPS=%llu\n", (unsigned long long)gpuOps);
        fprintf(f, "DEEP2_CPU_FALLBACK_USED=%u\n", fail > 0 ? 1u : 0u);
        fprintf(f, "DEEP2_UNPLANNED_DEVICE_FALLBACKS=%llu\n", (unsigned long long)unplanned);
        fprintf(f, "warm_multi15_e2e_tok_s=%.3f\n", tps);
        fprintf(f, "STREAMER_HYBRID_ALL_HW_001=%s\n", pass ? "PASS" : "FAIL");
        fclose(f);
    }
    fflush(stdout);
    fflush(stderr);
    _exit(pass ? 0 : 2);
}
