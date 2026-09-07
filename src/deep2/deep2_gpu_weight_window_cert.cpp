// deep2_gpu_weight_window_cert.cpp — STREAMER_GPU_WEIGHT_WINDOW_001
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

static size_t RunGen(Deep2Engine& engine, const char* prompt, int maxTok) {
    GenerationOptions opts{};
    opts.maxTokens = maxTok; opts.temperature = 0.0f; opts.topK = 1; opts.seed = 42;
    size_t n = 0;
    engine.generateStream(prompt, opts, [&](int32_t, const std::string&) -> bool {
        ++n; return true;
    });
    return n;
}

static uint64_t ModelF32EquivBytes(const ModelWeights& mw) {
    uint64_t t = 0;
    auto add = [&](const WeightTensor& w) {
        if (w.data && w.rows && w.cols) t += (uint64_t)w.rows * (uint64_t)w.cols * 4ull;
    };
    add(mw.tokenEmbed); add(mw.lmHead); add(mw.finalNorm);
    for (const auto& L : mw.layers) {
        add(L.wq); add(L.wk); add(L.wv); add(L.wo); add(L.attnO);
        add(L.wGate); add(L.wUp); add(L.wDown); add(L.attnNorm); add(L.ffnNorm);
    }
    return t;
}

static bool NumericalParityGemv(Deep2Engine& engine) {
    auto* vc = engine.getVulkanComputeSlot(0);
    if (!vc) return false;
    const auto& mw = engine.getModelWeights();
    if (mw.layers.empty() || !mw.layers[0].wq.data) return false;
    const WeightTensor& wt = mw.layers[0].wq;
    auto deq = QuantKernelRegistry::Instance().GetDequant(wt.type);
    if (!deq) return false;
    const size_t cols = wt.cols, rows = wt.rows;
    std::vector<float> W(rows * cols), x(cols, 0.f), yCpu(rows), yGpu(rows);
    deq(reinterpret_cast<const uint8_t*>(wt.data), W.data(), W.size());
    for (size_t i = 0; i < cols; ++i) x[i] = 0.01f * (float)((i % 17) + 1);
    for (size_t r = 0; r < rows; ++r) {
        double s = 0.0;
        for (size_t c = 0; c < cols; ++c) s += (double)W[r * cols + c] * (double)x[c];
        yCpu[r] = (float)s;
    }
    if (!vc->DispatchGEMV(W.data(), x.data(), yGpu.data(),
                          (uint32_t)rows, (uint32_t)cols, 0xC0FFEEULL))
        return false;
    double maxAbs = 0.0;
    for (size_t r = 0; r < rows; ++r) {
        double d = std::fabs((double)yGpu[r] - (double)yCpu[r]);
        if (d > maxAbs) maxAbs = d;
    }
    printf("NUMERICAL_PARITY_MAX_ABS=%.6g\n", maxAbs);
    return maxAbs < 1e-3;
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
    printf("STREAMER_GPU_WEIGHT_WINDOW_001\nModel: %s\n", model);
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\STREAMER_GPU_WEIGHT_WINDOW_001", nullptr);

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
    auto* vc = engine.getVulkanComputeSlot(0);
    const uint64_t peakAfterWarm = vc ? vc->WeightStreamPeakBytes() : 0;
    const uint64_t allocsAfterInit = vc ? vc->WeightSlotAllocs() : 0;

    auto t0 = std::chrono::steady_clock::now();
    size_t n = RunGen(engine, "hello", 8);
    auto t1 = std::chrono::steady_clock::now();
    double sec = std::chrono::duration<double>(t1 - t0).count();
    double tps = (n > 0 && sec > 0) ? (double)n / sec : 0.0;

    const bool parity = NumericalParityGemv(engine);
    const auto& c = engine.gpuForwardCounters();
    const uint64_t modelBytes = ModelF32EquivBytes(mw);
    const uint64_t modelQuantBytes = [&]() {
        uint64_t t = 0;
        auto add = [&](const WeightTensor& w) { if (w.data) t += (uint64_t)w.sizeBytes; };
        add(mw.tokenEmbed); add(mw.lmHead); add(mw.finalNorm);
        for (const auto& L : mw.layers) {
            add(L.wq); add(L.wk); add(L.wv); add(L.wo); add(L.attnO);
            add(L.wGate); add(L.wUp); add(L.wDown);
        }
        return t;
    }();
    const uint64_t windowBytes = vc ? vc->WeightStreamPeakBytes() : 0;
    const uint64_t streamTotal = vc ? vc->WeightStreamBytesTotal() : 0;
    const uint32_t slots = vc ? vc->WeightSlotCount() : 0;
    const uint64_t reuses = vc ? vc->WeightSlotReuses() : 0;
    const uint64_t allocs = vc ? vc->WeightSlotAllocs() : 0;
    const uint64_t growth = vc ? vc->WeightResidentGrowthAfterInit() : 0;
    const uint64_t waitIdle = vc ? vc->WeightHotpathWaitIdle() : 0;
    const uint64_t createBuf = vc ? vc->WeightHotpathCreateBuf() : 0;
    const uint64_t destroyBuf = vc ? vc->WeightHotpathDestroyBuf() : 0;
    const uint64_t prefetch = vc ? vc->WeightPrefetchDistance() : 0;
    const bool quantSrc = !mw.layers.empty() &&
        mw.layers[0].wq.type != (int)GGMLType::GGML_TYPE_F32;
    const bool permanentF32 = vc ? vc->PermanentF32WeightCache() : true;
    const bool streamActive = vc && vc->WeightStreamActive();

    const bool pass =
        n > 0 &&
        c.liveDecodeResidentTokens > 0 &&
        c.hostForwardLayerCalls == 0 &&
        streamActive &&
        slots >= 2 &&
        allocs == allocsAfterInit &&
        reuses > 0 &&
        windowBytes > 0 &&
        windowBytes <= ((uint64_t)1024 << 20) &&
        growth == 0 &&
        peakAfterWarm == windowBytes &&
        streamTotal > windowBytes &&
        modelBytes > windowBytes &&
        (modelBytes / windowBytes) >= 4 &&
        quantSrc &&
        !permanentF32 &&
        waitIdle == 0 &&
        createBuf == 0 &&
        destroyBuf == 0 &&
        prefetch >= 1 &&
        vc->GemvSuccess() > 0 &&
        parity &&
        engine.vulkanGemvFallbackCount() == 0 &&
        engine.isRealGpuForward();

    auto emit = [&](FILE* o) {
        if (!o) return;
        fprintf(o, "WEIGHT_MODE=%s\n", streamActive ? "BOUNDED_STREAM" : "OTHER");
        fprintf(o, "WEIGHT_SLOT_COUNT=%u\n", slots);
        fprintf(o, "WEIGHT_SLOT_ALLOCS=%llu\n", (unsigned long long)allocs);
        fprintf(o, "WEIGHT_SLOT_REUSES=%llu\n", (unsigned long long)reuses);
        fprintf(o, "DEEP2_WEIGHT_STREAM_BYTES_TOTAL=%llu\n", (unsigned long long)streamTotal);
        fprintf(o, "DEEP2_WEIGHT_STREAM_PEAK_BYTES=%llu\n", (unsigned long long)windowBytes);
        fprintf(o, "GPU_WEIGHT_WINDOW_BYTES=%llu\n", (unsigned long long)windowBytes);
        fprintf(o, "MODEL_WEIGHT_BYTES=%llu\n", (unsigned long long)modelQuantBytes);
        fprintf(o, "MODEL_F32_EQUIV_BYTES=%llu\n", (unsigned long long)modelBytes);
        fprintf(o, "RESIDENT_WEIGHT_GROWTH_AFTER_INIT=%llu\n", (unsigned long long)growth);
        fprintf(o, "WEIGHT_SOURCE_QUANTIZED=%u\n", quantSrc ? 1u : 0u);
        fprintf(o, "PERMANENT_F32_WEIGHT_CACHE=%u\n", permanentF32 ? 1u : 0u);
        fprintf(o, "HOTPATH_QUEUE_WAIT_IDLE=%llu\n", (unsigned long long)waitIdle);
        fprintf(o, "HOTPATH_WEIGHT_CREATE_BUFFER=%llu\n", (unsigned long long)createBuf);
        fprintf(o, "HOTPATH_WEIGHT_DESTROY_BUFFER=%llu\n", (unsigned long long)destroyBuf);
        fprintf(o, "WEIGHT_PREFETCH_DISTANCE=%llu\n", (unsigned long long)prefetch);
        fprintf(o, "GPU_WEIGHT_GEMV_SUCCESS=%llu\n",
                (unsigned long long)(vc ? vc->GemvSuccess() : 0));
        fprintf(o, "NUMERICAL_PARITY=%s\n", parity ? "PASS" : "FAIL");
        fprintf(o, "LIVE_DECODE_RESIDENT_FORWARD=%u\n",
                c.liveDecodeResidentTokens > 0 ? 1u : 0u);
        fprintf(o, "HOST_FORWARD_LAYER_CALLS=%llu\n",
                (unsigned long long)c.hostForwardLayerCalls);
        fprintf(o, "FALLBACK=%llu\n", (unsigned long long)engine.vulkanGemvFallbackCount());
        fprintf(o, "warm_solo8_e2e_tok_s=%.3f\n", tps);
        fprintf(o, "STREAMER_GPU_WEIGHT_WINDOW_001=%s\n", pass ? "PASS" : "FAIL");
    };
    emit(stdout);
    FILE* f = fopen("G:\\~dev\\rawrxd\\evidence\\STREAMER_GPU_WEIGHT_WINDOW_001\\GATE_STATUS.txt", "w");
    if (f) { emit(f); fclose(f); }
    fflush(stdout);
    _exit(pass ? 0 : 2);
}
