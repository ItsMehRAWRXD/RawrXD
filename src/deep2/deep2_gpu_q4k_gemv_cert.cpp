// deep2_gpu_q4k_gemv_cert.cpp — STREAMER_GPU_Q4K_GEMV_001
#include "Deep2Engine.h"
#include "Deep2GpuForward.hpp"
#include "QuantKernelRegistry.hpp"
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif
using namespace Deep2;

static size_t RunGen(Deep2Engine& e, const char* p, int n) {
    GenerationOptions o{};
    o.maxTokens = n; o.temperature = 0; o.topK = 1; o.seed = 42;
    size_t k = 0;
    e.generateStream(p, o, [&](int32_t, const std::string&) -> bool { ++k; return true; });
    return k;
}

static bool PackedParity(Deep2Engine& e, double& maxAbs, double& rms) {
    auto* vc = e.getVulkanComputeSlot(0);
    const auto& mw = e.getModelWeights();
    if (!vc || mw.layers.empty()) return false;
    const WeightTensor& wt = mw.layers[0].wq;
    if (wt.type != (int)GGMLType::GGML_TYPE_Q4_K || !wt.data || !wt.sizeBytes)
        return false;
    auto deq = QuantKernelRegistry::Instance().GetDequant(wt.type);
    if (!deq) return false;
    const size_t rows = wt.rows, cols = wt.cols;
    std::vector<float> W(rows * cols), x(cols), yCpu(rows), yGpu(rows);
    deq(reinterpret_cast<const uint8_t*>(wt.data), W.data(), W.size());
    for (size_t i = 0; i < cols; ++i) x[i] = 0.01f * (float)((i % 17) + 1);
    for (size_t r = 0; r < rows; ++r) {
        double s = 0;
        for (size_t c = 0; c < cols; ++c) s += (double)W[r * cols + c] * (double)x[c];
        yCpu[r] = (float)s;
    }
    if (!vc->DispatchGEMVPacked(wt.data, wt.sizeBytes, x.data(), yGpu.data(),
                                (uint32_t)rows, (uint32_t)cols))
        return false;
    double ss = 0; maxAbs = 0;
    for (size_t r = 0; r < rows; ++r) {
        double d = std::fabs((double)yGpu[r] - (double)yCpu[r]);
        if (d > maxAbs) maxAbs = d;
        ss += d * d;
    }
    rms = std::sqrt(ss / (double)rows);
    return maxAbs < 1e-2 && rms < 1e-3;
}

int main(int argc, char** argv) {
#ifdef _WIN32
    SetEnvironmentVariableA("DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1", "1");
    _putenv_s("DEEP2_WEIGHT_MODE", "BOUNDED_STREAM");
    _putenv_s("DEEP2_WEIGHT_SLOTS", "2");
    _putenv_s("DEEP2_WEIGHT_BUDGET_MIB", "512");
    _putenv_s("RAWRXD_GPU_POLICY", "SOLO");
    _putenv_s("RAWRXD_GPU_DEVICES", "ALL");
    _putenv_s("RAWRXD_GPU_FWD", "1");
#endif
    const char* model = argc > 1 ? argv[1]
        : "G:\\~dev\\rawrxd\\models\\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf";
    printf("STREAMER_GPU_Q4K_GEMV_001\nModel: %s\n", model);
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\STREAMER_GPU_Q4K_GEMV_001", nullptr);
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
    RunGen(engine, "hi", 1);
    auto t0 = std::chrono::steady_clock::now();
    size_t n = RunGen(engine, "hello", 8);
    auto t1 = std::chrono::steady_clock::now();
    double sec = std::chrono::duration<double>(t1 - t0).count();
    double tps = (n > 0 && sec > 0) ? (double)n / sec : 0.0;
    double maxAbs = 0, rms = 0;
    const bool parity = PackedParity(engine, maxAbs, rms);
    auto* vc = engine.getVulkanComputeSlot(0);
    const auto& c = engine.gpuForwardCounters();
    uint64_t q4kT = 0, otherT = 0;
    auto tally = [&](const WeightTensor& w) {
        if (!w.data || !w.rows) return;
        if (w.type == (int)GGMLType::GGML_TYPE_Q4_K) ++q4kT;
        else if (w.type != (int)GGMLType::GGML_TYPE_F32) ++otherT;
    };
    for (const auto& L : mw.layers) {
        tally(L.wq); tally(L.wk); tally(L.wv); tally(L.wo); tally(L.attnO);
        tally(L.wGate); tally(L.wUp); tally(L.wDown);
    }
    const uint64_t packed = vc ? vc->Q4kPackedOps() : 0;
    const uint64_t createBuf = vc ? vc->WeightHotpathCreateBuf() : 0;
    const uint64_t destroyBuf = vc ? vc->WeightHotpathDestroyBuf() : 0;
    const bool pass =
        n > 0 && parity && packed > 0 && q4kT > 0 &&
        (otherT > 0 || c.cpuF32Expands == 0) &&
        packed >= q4kT &&
        vc && vc->WeightStreamActive() &&
        vc->WeightResidentGrowthAfterInit() == 0 &&
        createBuf == 0 && destroyBuf == 0 &&
        engine.vulkanGemvFallbackCount() == 0 &&
        c.liveDecodeResidentTokens > 0 &&
        c.hostForwardLayerCalls == 0 &&
        engine.isRealGpuForward() &&
        tps > 0.4;
    auto emit = [&](FILE* o) {
        if (!o) return;
        fprintf(o, "Q4K_LAYER_TENSORS=%llu OTHER_QUANT_GEMV=%llu\n",
                (unsigned long long)q4kT, (unsigned long long)otherT);
        fprintf(o, "DEEP2_GPU_Q4K_PACKED_OPS=%llu\n", (unsigned long long)packed);
        fprintf(o, "DEEP2_GPU_CPU_F32_EXPANDS=%llu\n",
                (unsigned long long)c.cpuF32Expands);
        fprintf(o, "Q4K_GEMV_MAX_ABS=%.6g RMS=%.6g\n", maxAbs, rms);
        fprintf(o, "HOTPATH_WEIGHT_CREATE_BUFFER=%llu\n", (unsigned long long)createBuf);
        fprintf(o, "HOTPATH_WEIGHT_DESTROY_BUFFER=%llu\n", (unsigned long long)destroyBuf);
        fprintf(o, "RESIDENT_WEIGHT_GROWTH_AFTER_INIT=%llu\n",
                (unsigned long long)(vc ? vc->WeightResidentGrowthAfterInit() : 0));
        fprintf(o, "FALLBACK=%llu\n", (unsigned long long)engine.vulkanGemvFallbackCount());
        fprintf(o, "LIVE_DECODE_RESIDENT_FORWARD=%u\n",
                c.liveDecodeResidentTokens > 0 ? 1u : 0u);
        fprintf(o, "warm_solo8_e2e_tok_s=%.3f\n", tps);
        fprintf(o, "STREAMER_GPU_Q4K_GEMV_001=%s\n", pass ? "PASS" : "FAIL");
    };
    emit(stdout);
    FILE* f = fopen("G:\\~dev\\rawrxd\\evidence\\STREAMER_GPU_Q4K_GEMV_001\\GATE_STATUS.txt", "w");
    if (f) { emit(f); fclose(f); }
    fflush(stdout);
    _exit(pass ? 0 : 2);
}
