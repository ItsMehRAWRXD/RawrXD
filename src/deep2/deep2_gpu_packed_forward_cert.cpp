// deep2_gpu_packed_forward_cert.cpp — STREAMER_GPU gates 6–15
#include "Deep2Engine.h"
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

static size_t RunGen(Deep2Engine& e, const char* p, int n) {
    GenerationOptions o{}; o.maxTokens = n; o.temperature = 0; o.topK = 1; o.seed = 42;
    size_t k = 0;
    e.generateStream(p, o, [&](int32_t, const std::string&) -> bool { ++k; return true; });
    return k;
}

static bool LinearPacked(const ModelWeights& mw) {
    auto ok = [&](const WeightTensor& w) -> bool {
        if (!w.data || !w.rows) return true;
        if (w.type == (int)GGMLType::GGML_TYPE_F32) return true;
        const int t = w.type;
        return t == (int)GGMLType::GGML_TYPE_Q8_0 || t == (int)GGMLType::GGML_TYPE_Q2_K ||
               t == (int)GGMLType::GGML_TYPE_Q3_K || t == (int)GGMLType::GGML_TYPE_Q4_K ||
               t == (int)GGMLType::GGML_TYPE_Q5_K || t == (int)GGMLType::GGML_TYPE_Q6_K;
    };
    for (const auto& L : mw.layers) {
        if (!ok(L.wq) || !ok(L.wk) || !ok(L.wv) || !ok(L.wo) || !ok(L.attnO) ||
            !ok(L.wGate) || !ok(L.wUp) || !ok(L.wDown))
            return false;
    }
    return ok(mw.lmHead);
}

int main(int argc, char** argv) {
#ifdef _WIN32
    SetEnvironmentVariableA("DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1", "1");
    _putenv_s("DEEP2_WEIGHT_MODE", "BOUNDED_STREAM");
    _putenv_s("DEEP2_WEIGHT_BUDGET_MIB", "512");
    _putenv_s("RAWRXD_GPU_POLICY", "SOLO");
    _putenv_s("RAWRXD_GPU_DEVICES", "ALL");
    _putenv_s("RAWRXD_GPU_FWD", "1");
#endif
    const char* model = argc > 1 ? argv[1]
        : "G:\\~dev\\rawrxd\\models\\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf";
    printf("STREAMER_GPU_PACKED_FORWARD batch 1-15\nModel: %s\n", model);
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\STREAMER_GPU_PACKED_FORWARD_001", nullptr);
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
    RunGen(engine, "hi", 1);
    auto t0 = std::chrono::steady_clock::now();
    size_t n = RunGen(engine, "hello", 8);
    auto t1 = std::chrono::steady_clock::now();
    double tps = n / std::chrono::duration<double>(t1 - t0).count();
    auto* vc = engine.getVulkanComputeSlot(0);
    GpuForwardCounters snap = engine.gpuForwardCounters();
    const bool cov = LinearPacked(mw) && snap.cpuF32Expands == 0 && vc && vc->QuantPackedOps() > 0;
    const bool packedFwd = n > 0 && snap.liveDecodeResidentTokens > 0 &&
        snap.hostForwardLayerCalls == 0 && engine.vulkanGemvFallbackCount() == 0 &&
        engine.isRealGpuForward();
    const bool fuse = snap.layerSubmits > 0 && vc && vc->FusedCbReuses() > vc->FusedCbAllocs();
    const bool qkv = fuse && snap.qkvOps >= 3;
    const bool ffn = fuse && snap.ffnActOps > 0 && snap.oProjOps > 0;
    const bool xfer = vc && vc->XferRecords() > vc->XferSubmits();
    const bool cmd = vc && vc->FusedCbAllocs() > 0 && vc->FusedCbAllocs() <= 4 &&
        vc->WeightHotpathCreateBuf() == 0 && vc->WeightHotpathDestroyBuf() == 0;
    const bool ktune = vc && vc->GemvLocalSize() == 64 && vc->KernelTuneOk();
    const bool mtune = vc && vc->WeightSlotCount() >= 2 && vc->WeightSlotCount() <= 16 &&
        vc->WeightSlotBytes() > 0 &&
        (uint64_t)vc->WeightSlotCount() * vc->WeightSlotBytes() <=
            (vc->WeightBudgetBytes() ? vc->WeightBudgetBytes() : (size_t)512 << 20);
    _putenv_s("DEEP2_WEIGHT_PREFETCH", "1");
    engine.resetGpuForwardCounters();
    size_t n2 = RunGen(engine, "hello", 4);
    const bool async = n2 > 0 && vc && vc->WeightOverlapEvents() > 0;
    bool pass = true;
    auto gate = [&](const char* id, bool p) {
        printf("%s=%s\n", id, p ? "PASS" : "FAIL");
        std::string dir = std::string("G:\\~dev\\rawrxd\\evidence\\") + id;
        CreateDirectoryA(dir.c_str(), nullptr);
        FILE* gf = nullptr;
        fopen_s(&gf, (dir + "\\GATE_STATUS.txt").c_str(), "wb");
        if (gf) {
            fprintf(gf, "%s=%s\n", id, p ? "PASS" : "FAIL");
            fclose(gf);
        }
        return p;
    };
    pass &= gate("STREAMER_GPU_QUANT_COVERAGE_001", cov);
    pass &= gate("STREAMER_GPU_PACKED_FORWARD_001", packedFwd);
    pass &= gate("STREAMER_GPU_ASYNC_PIPELINE_001", async);
    pass &= gate("STREAMER_GPU_TRANSFER_BATCH_001", xfer);
    pass &= gate("STREAMER_GPU_COMMAND_REUSE_001", cmd);
    pass &= gate("STREAMER_GPU_FUSION_001", fuse);
    pass &= gate("STREAMER_GPU_FUSED_QKV_001", qkv);
    pass &= gate("STREAMER_GPU_FUSED_FFN_001", ffn);
    pass &= gate("STREAMER_GPU_KERNEL_TUNE_001", ktune);
    pass &= gate("STREAMER_GPU_MEMORY_TUNE_001", mtune);
    fflush(stdout);
    printf("cpuF32Expands=%llu packedOps=%llu layerSubmits=%llu xfer=%llu/%llu slots=%u\n",
           (unsigned long long)snap.cpuF32Expands, (unsigned long long)(vc ? vc->QuantPackedOps() : 0),
           (unsigned long long)snap.layerSubmits,
           (unsigned long long)(vc ? vc->XferRecords() : 0),
           (unsigned long long)(vc ? vc->XferSubmits() : 0),
           vc ? vc->WeightSlotCount() : 0);
    printf("fused_alloc=%llu reuse=%llu overlap=%llu tok_s=%.3f\n",
           (unsigned long long)(vc ? vc->FusedCbAllocs() : 0),
           (unsigned long long)(vc ? vc->FusedCbReuses() : 0),
           (unsigned long long)(vc ? vc->WeightOverlapEvents() : 0), tps);
    FILE* f = fopen("G:\\~dev\\rawrxd\\evidence\\STREAMER_GPU_PACKED_FORWARD_001\\GATE_STATUS.txt", "w");
    if (f) {
        fprintf(f, "STREAMER_GPU_PACKED_FORWARD_001=%s\n", packedFwd ? "PASS" : "FAIL");
        fprintf(f, "BATCH_PACKED_FORWARD_UMBRELLA=%s\n", pass ? "PASS" : "FAIL");
        fclose(f);
    }
    _exit(pass ? 0 : 2);
}
