// deep2_gpu_transfer_overlap_cert.cpp — GPU_TRANSFER_OVERLAP_001
#include "Deep2Engine.h"
#include "GpuTransferCounters.hpp"
#include "StreamTransferCounters.hpp"
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

struct Arm {
    double tps = 0, wallMs = 0;
    uint64_t copyB = 0, waitUs = 0, overlapUs = 0, overlapEv = 0, overlapB = 0;
    uint64_t hits = 0, misses = 0, reloadB = 0, firstB = 0;
    uint64_t fallback = 0, f32 = 0;
    size_t tokens = 0;
    bool ok = false;
};

static Arm RunArm(const char* model, const char* overlap, const char* tag) {
    Arm a{};
#ifdef _WIN32
    SetEnvironmentVariableA("DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1", "1");
    _putenv_s("DEEP2_WEIGHT_MODE", "BOUNDED_STREAM");
    _putenv_s("DEEP2_WEIGHT_SLOTS", "4");
    _putenv_s("DEEP2_WEIGHT_BUDGET_MIB", "512");
    _putenv_s("DEEP2_WEIGHT_PREFETCH", "1");
    _putenv_s("DEEP2_WEIGHT_OVERLAP", overlap);
    _putenv_s("RAWRXD_GPU_POLICY", "SOLO");
    _putenv_s("RAWRXD_GPU_DEVICES", "ALL");
    _putenv_s("RAWRXD_GPU_FWD", "1");
    _putenv_s("DEEP2_FUSED", "1");
#endif
    StreamTransfer_Reset();
    GpuTransfer_Reset();
    Deep2Engine engine;
    if (!engine.loadModel(model)) return a;
    const auto& mw = engine.getModelWeights();
    EngineConfig cfg{};
    cfg.hiddenDim = mw.hiddenDim; cfg.numLayers = mw.numLayers;
    cfg.numHeads = mw.numHeads; cfg.numKVHeads = mw.numKVHeads;
    cfg.headDim = mw.headDim; cfg.vocabSize = mw.vocabSize;
    cfg.maxSeqLen = 256; cfg.useKVCache = true; cfg.useThreadPool = true;
    cfg.numThreads = 8;
    if (!engine.initialize(cfg)) return a;
    engine.enableVulkan(true);
    GenerationOptions opts{};
    opts.maxTokens = 8; opts.temperature = 0.0f; opts.topK = 1; opts.seed = 42;
    // Warm
    engine.generateStream("hi", opts, [](int32_t, const std::string&) { return true; });
    StreamTransfer_Reset();
    GpuTransfer_Reset();
    auto t0 = std::chrono::steady_clock::now();
    engine.generateStream("hello", opts, [&](int32_t, const std::string&) -> bool {
        ++a.tokens; GpuTransfer_RecordToken(); return true;
    });
    a.wallMs = std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - t0).count();
    a.tps = (a.tokens && a.wallMs > 0) ? (1000.0 * (double)a.tokens / a.wallMs) : 0.0;
    auto g = GpuTransfer_Snapshot();
    a.copyB = g.copyBytes; a.waitUs = g.waitUs; a.overlapUs = g.overlapUs;
    a.overlapEv = g.overlapEvents; a.overlapB = g.overlapBytes;
    a.hits = g.weightHits; a.misses = g.weightMisses;
    a.reloadB = g.reloadBytes; a.firstB = g.firstLoadBytes;
    const auto& c = engine.gpuForwardCounters();
    a.fallback = c.hostForwardLayerCalls; a.f32 = c.cpuF32Expands;
    a.ok = a.tokens > 0 && a.fallback == 0 && a.f32 == 0;
    printf("[%s] tokens=%zu tps=%.3f wait=%llu overlap=%llu ev=%llu copy=%llu hits=%llu\n",
           tag, a.tokens, a.tps,
           (unsigned long long)a.waitUs, (unsigned long long)a.overlapUs,
           (unsigned long long)a.overlapEv, (unsigned long long)a.copyB,
           (unsigned long long)a.hits);
    GpuTransfer_Emit(stdout);
    return a;
}

int main(int argc, char** argv) {
    const char* model = argc > 1 ? argv[1]
        : "G:\\~dev\\rawrxd\\models\\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf";
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\GPU_TRANSFER_OVERLAP_001", nullptr);
    printf("GPU_TRANSFER_OVERLAP_001\nMODEL=%s\n", model);
    Arm A = RunArm(model, "0", "A_SERIAL");
    Arm B = RunArm(model, "1", "B_OVERLAP");
    const bool overlapUp = B.overlapUs > 0 && B.overlapEv > 0;
    const bool waitDown = B.waitUs < A.waitUs;
    const bool tpsUp = B.tps > A.tps;
    const bool bytesFlat = B.copyB <= A.copyB;
    // Gate closes when overlap is real AND (wait drops OR throughput rises)
    // with no regression in copy volume / correctness.
    const bool pass = A.ok && B.ok && overlapUp && bytesFlat && (waitDown || tpsUp);
    printf("A_WAIT_US=%llu B_WAIT_US=%llu\n",
           (unsigned long long)A.waitUs, (unsigned long long)B.waitUs);
    printf("A_OVERLAP_US=%llu B_OVERLAP_US=%llu\n",
           (unsigned long long)A.overlapUs, (unsigned long long)B.overlapUs);
    printf("A_TPS=%.3f B_TPS=%.3f\n", A.tps, B.tps);
    printf("A_COPY=%llu B_COPY=%llu A_HITS=%llu B_HITS=%llu\n",
           (unsigned long long)A.copyB, (unsigned long long)B.copyB,
           (unsigned long long)A.hits, (unsigned long long)B.hits);
    printf("OVERLAP_EVENTS_B=%llu OVERLAP_BYTES_B=%llu\n",
           (unsigned long long)B.overlapEv, (unsigned long long)B.overlapB);
    printf("GPU_TRANSFER_OVERLAP_001=%s\n", pass ? "PASS" : "FAIL");
    FILE* f = fopen(
        "G:\\~dev\\rawrxd\\evidence\\GPU_TRANSFER_OVERLAP_001\\GATE_STATUS.txt", "w");
    if (f) {
        fprintf(f, "GPU_TRANSFER_OVERLAP_001=%s\n", pass ? "PASS" : "FAIL");
        fprintf(f, "A_WAIT=%llu B_WAIT=%llu A_OV=%llu B_OV=%llu\n",
                (unsigned long long)A.waitUs, (unsigned long long)B.waitUs,
                (unsigned long long)A.overlapUs, (unsigned long long)B.overlapUs);
        fprintf(f, "A_TPS=%.3f B_TPS=%.3f\n", A.tps, B.tps);
        fclose(f);
    }
    (void)0;
    fflush(stdout);
    _exit(pass ? 0 : 2);
}
