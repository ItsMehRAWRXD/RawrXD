// deep2_gpu_dynamic_window_cert.cpp — STREAMER_GPU_DYNAMIC_WINDOW_001
#include "Deep2Engine.h"
#include "Deep2GpuForward.hpp"
#include "vulkan_compute.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif
using namespace Deep2;
using CPUInference::VulkanCompute;

static size_t MaxPacked(const ModelWeights& mw) {
    size_t m = 0;
    auto acc = [&](const WeightTensor& w) {
        if (!w.data || !w.sizeBytes) return;
        const int t = w.type;
        size_t b = w.sizeBytes;
        if (t != (int)GGMLType::GGML_TYPE_Q8_0 && t != (int)GGMLType::GGML_TYPE_Q2_K &&
            t != (int)GGMLType::GGML_TYPE_Q3_K && t != (int)GGMLType::GGML_TYPE_Q4_K &&
            t != (int)GGMLType::GGML_TYPE_Q5_K && t != (int)GGMLType::GGML_TYPE_Q6_K)
            b = w.rows * w.cols * 4;
        if (b > m) m = b;
    };
    for (const auto& L : mw.layers) {
        acc(L.wq); acc(L.wk); acc(L.wv); acc(L.wo); acc(L.attnO);
        acc(L.wGate); acc(L.wUp); acc(L.wDown);
    }
    acc(mw.lmHead);
    return m;
}

static size_t RunGen(Deep2Engine& e, int n) {
    GenerationOptions o{}; o.maxTokens = n; o.temperature = 0; o.topK = 1; o.seed = 42;
    size_t k = 0;
    e.generateStream("hi", o, [&](int32_t, const std::string&) -> bool { ++k; return true; });
    return k;
}

int main(int argc, char** argv) {
#ifdef _WIN32
    SetEnvironmentVariableA("DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1", "1");
    SetEnvironmentVariableA("DEEP2_WEIGHT_SLOTS", nullptr);
    _putenv_s("DEEP2_WEIGHT_MODE", "BOUNDED_STREAM");
    _putenv_s("DEEP2_WEIGHT_BUDGET_MIB", "512");
    _putenv_s("RAWRXD_GPU_POLICY", "SOLO");
    _putenv_s("RAWRXD_GPU_DEVICES", "ALL");
    _putenv_s("RAWRXD_GPU_FWD", "1");
#endif
    const char* model = argc > 1 ? argv[1]
        : "G:\\~dev\\rawrxd\\models\\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf";
    printf("STREAMER_GPU_DYNAMIC_WINDOW_001\n");
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\STREAMER_GPU_DYNAMIC_WINDOW_001", nullptr);
    Deep2Engine engine;
    if (!engine.loadModel(model)) { printf("FAIL load\n"); return 1; }
    const auto& mw = engine.getModelWeights();
    EngineConfig cfg{};
    cfg.hiddenDim = mw.hiddenDim; cfg.numLayers = mw.numLayers;
    cfg.numHeads = mw.numHeads; cfg.numKVHeads = mw.numKVHeads;
    cfg.headDim = mw.headDim; cfg.vocabSize = mw.vocabSize;
    cfg.maxSeqLen = 4096; cfg.useKVCache = true; cfg.useThreadPool = true; cfg.numThreads = 16;
    if (!engine.initialize(cfg)) { printf("FAIL init\n"); return 1; }
    engine.enableVulkan(true); engine.enableMedusa(false);
    auto* vc = engine.getVulkanComputeSlot(0);
    if (!vc) { printf("FAIL vulkan\n"); return 2; }
    const size_t maxB = MaxPacked(mw);
    const size_t arena = VulkanCompute::ForwardArenaReserveBytes(
        (uint32_t)mw.hiddenDim, (uint32_t)mw.intermediateDim,
        (uint32_t)mw.numHeads, (uint32_t)mw.numKVHeads, (uint32_t)mw.headDim,
        4096, (uint32_t)mw.numLayers);
    const size_t heap = vc->DeviceLocalHeapBytes();
    uint32_t nA = 0, nB = 0, nC = 0, nD = 0, nE = 0;
    size_t uA = 0, uB = 0, uC = 0, uD = 0, uE = 0;
    const bool cA = VulkanCompute::ChooseWeightWindow(maxB, (size_t)512 << 20, 0, arena, heap, nA, uA);
    const bool cB = VulkanCompute::ChooseWeightWindow(maxB, (size_t)256 << 20, 0, arena, heap, nB, uB);
    const bool cC = VulkanCompute::ChooseWeightWindow(maxB * 3, (size_t)512 << 20, 0, arena, heap, nC, uC);
    const bool cD = VulkanCompute::ChooseWeightWindow(maxB, (size_t)512 << 20, 3, arena, heap, nD, uD);
    const bool cE = VulkanCompute::ChooseWeightWindow(maxB, (size_t)32 << 20, 0, arena, heap, nE, uE);
    printf("CASE_A auto512 n=%u ok=%d usable=%llu\n", nA, (int)cA, (unsigned long long)uA);
    printf("CASE_B auto256 n=%u ok=%d\n", nB, (int)cB);
    printf("CASE_C geom*3 n=%u ok=%d\n", nC, (int)cC);
    printf("CASE_D ov=3 n=%u ok=%d\n", nD, (int)cD);
    printf("CASE_E bud32 ok=%d\n", (int)cE);
    const bool pol = cA && nA >= 2 && nA <= 16 && cB && nB >= 2 && nB < nA &&
        cC && nC >= 2 && nC < nA && cD && nD == 3 && !cE &&
        (uint64_t)nA * maxB <= uA;
    size_t tok = RunGen(engine, 1) + RunGen(engine, 4);
    const auto& g = engine.gpuForwardCounters();
    const bool liveA = tok > 0 && vc->WeightSlotsAuto() && vc->WeightSlotCount() == nA &&
        vc->WeightStreamPeakBytes() <= vc->WeightUsableBudget() &&
        vc->WeightResidentGrowthAfterInit() == 0 &&
        vc->WeightHotpathCreateBuf() == 0 && vc->WeightHotpathDestroyBuf() == 0 &&
        g.cpuF32Expands == 0 && engine.vulkanGemvFallbackCount() == 0 &&
        g.liveDecodeResidentTokens > 0 && engine.isRealGpuForward();
    _putenv_s("DEEP2_WEIGHT_BUDGET_MIB", "256");
    const bool liveB = vc->ApplyWeightWindowPolicy(maxB, (size_t)256 << 20, 0, arena) &&
        vc->WeightSlotCount() == nB &&
        vc->WeightStreamPeakBytes() <= ((size_t)256 << 20) &&
        vc->WeightStreamPeakBytes() <= vc->WeightUsableBudget();
    _putenv_s("DEEP2_WEIGHT_BUDGET_MIB", "512");
    const bool liveC = vc->ApplyWeightWindowPolicy(maxB * 3, (size_t)512 << 20, 0, arena) &&
        vc->WeightSlotCount() == nC && vc->WeightSlotBytes() == maxB * 3;
    const bool liveD = vc->ApplyWeightWindowPolicy(maxB, (size_t)512 << 20, 3, arena) &&
        vc->WeightSlotCount() == 3 && !vc->WeightSlotsAuto() &&
        vc->WeightSlotBytes() == maxB;
    const uint64_t grow = vc->WeightResidentGrowthAfterInit();
    const bool liveE = !vc->ApplyWeightWindowPolicy(maxB, (size_t)32 << 20, 0, arena) &&
        vc->WeightSlotCount() == 3 && grow == vc->WeightResidentGrowthAfterInit();
    const bool pass = pol && liveA && liveB && liveC && liveD && liveE;
    printf("LIVE_A=%d LIVE_B=%d LIVE_C=%d LIVE_D=%d LIVE_E=%d slotsA=%u\n",
           (int)liveA, (int)liveB, (int)liveC, (int)liveD, (int)liveE, nA);
    printf("STREAMER_GPU_DYNAMIC_WINDOW_001=%s\n", pass ? "PASS" : "FAIL");
    fflush(stdout);
    FILE* f = fopen("G:\\~dev\\rawrxd\\evidence\\STREAMER_GPU_DYNAMIC_WINDOW_001\\GATE_STATUS.txt", "w");
    if (f) { fprintf(f, "STREAMER_GPU_DYNAMIC_WINDOW_001=%s\n", pass ? "PASS" : "FAIL"); fclose(f); }
    _exit(pass ? 0 : 2);
}
