// deep2_placement_cost_cert.cpp — STREAMER_PLACEMENT_COST_001
#include "Deep2Engine.h"
#include "Deep2DeviceManager.hpp"
#include "Deep2MultiGpuLayerPlan.hpp"
#include <cstdio>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

using namespace Deep2;

int main(int argc, char** argv) {
#ifdef _WIN32
    SetEnvironmentVariableA("DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1", "1");
    _putenv_s("RAWRXD_GPU_POLICY", "AUTO");
    _putenv_s("RAWRXD_GPU_DEVICES", "ALL");
    _putenv_s("DEEP2_FORCE_SPLIT", "0");
#endif
    const char* model = argc > 1 ? argv[1]
        : "G:\\~dev\\rawrxd\\models\\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf";
    printf("STREAMER_PLACEMENT_COST_001\nModel: %s\n", model);
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\STREAMER_PLACEMENT_COST_001", nullptr);

    DeviceManagerSnapshot snap{};
    Deep2Device_Enumerate(snap);
    Deep2Device_ApplyPolicy(snap);
    Deep2Device_EmitWitnesses(nullptr, snap);

    MultiGpuLayerPlan plan{};
    const unsigned nL = 22;
    const uint64_t h = 2048;
    if (!Deep2MultiGpu_BuildContiguousPlan(snap, nL, 12ull * h * h * 4, plan)) {
        printf("FAIL build plan\n");
        return 1;
    }
    Deep2MultiGpu_EmitPlanWitnesses(nullptr, plan);
    Deep2MultiGpu_ApplyCostWeightedCut(plan);
    Deep2MultiGpu_EmitPlanWitnesses(nullptr, plan);
    printf("DEEP2_COST_PLANNED=%u DEEP2_COST_GPU_SLOTS=%u\n",
           plan.plannedCount, plan.gpuSlotCount);

    Deep2Engine engine;
    if (!engine.loadModel(model)) { printf("FAIL loadModel\n"); return 2; }
    const auto& mw = engine.getModelWeights();
    EngineConfig cfg{};
    cfg.hiddenDim = mw.hiddenDim; cfg.numLayers = mw.numLayers;
    cfg.numHeads = mw.numHeads; cfg.numKVHeads = mw.numKVHeads;
    cfg.headDim = mw.headDim; cfg.vocabSize = mw.vocabSize;
    cfg.maxSeqLen = 4096; cfg.useKVCache = true; cfg.useThreadPool = true;
    cfg.numThreads = 16;
    if (!engine.initialize(cfg)) { printf("FAIL initialize\n"); return 3; }
    engine.enableAllEnhancements();
    const MultiGpuLayerPlan& live = engine.multiGpuLayerPlan();
    printf("LIVE_PLANNED=%u LIVE_OPENED=%u vk=%d\n",
           live.plannedCount, engine.vulkanDeviceCount(),
           engine.isVulkanEnabled() ? 1 : 0);
    const bool pass = engine.isVulkanEnabled() && plan.plannedCount >= 1;
    FILE* f = nullptr;
    fopen_s(&f, "G:\\~dev\\rawrxd\\evidence\\STREAMER_PLACEMENT_COST_001\\GATE_STATUS.txt", "wb");
    if (f) {
        fprintf(f, "DEEP2_COST_PLANNED=%u DEEP2_COST_GPU_SLOTS=%u\n",
                plan.plannedCount, plan.gpuSlotCount);
        fprintf(f, "LIVE_PLANNED=%u LIVE_OPENED=%u vk=%d\n",
                live.plannedCount, engine.vulkanDeviceCount(),
                engine.isVulkanEnabled() ? 1 : 0);
        fprintf(f, "STREAMER_PLACEMENT_COST_001=%s\n", pass ? "PASS" : "FAIL");
        fclose(f);
    }
    printf("RESULT=%s\n", pass ? "PASS" : "FAIL");
    return pass ? 0 : 4;
}
