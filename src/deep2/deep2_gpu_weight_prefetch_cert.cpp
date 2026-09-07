// deep2_gpu_weight_prefetch_cert.cpp — STREAMER_GPU_WEIGHT_PREFETCH_001
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

struct RunStats {
    double tps = 0;
    uint64_t peak = 0, growth = 0, waitIdle = 0, createB = 0, destroyB = 0;
    uint64_t overlap = 0, reuses = 0, allocs = 0, gemvOk = 0;
    uint32_t slots = 0;
    bool stream = false, permanentF32 = true;
    uint64_t hostFwd = 0, live = 0, fallback = 0;
};

static bool NumericalParity(Deep2Engine& engine) {
    auto* vc = engine.getVulkanComputeSlot(0);
    if (!vc || engine.getModelWeights().layers.empty()) return false;
    const WeightTensor& wt = engine.getModelWeights().layers[0].wq;
    auto deq = QuantKernelRegistry::Instance().GetDequant(wt.type);
    if (!deq) return false;
    const size_t cols = wt.cols, rows = wt.rows;
    std::vector<float> W(rows * cols), x(cols), yCpu(rows), yGpu(rows);
    deq(reinterpret_cast<const uint8_t*>(wt.data), W.data(), W.size());
    for (size_t i = 0; i < cols; ++i) x[i] = 0.01f * (float)((i % 17) + 1);
    for (size_t r = 0; r < rows; ++r) {
        double s = 0.0;
        for (size_t c = 0; c < cols; ++c) s += (double)W[r * cols + c] * (double)x[c];
        yCpu[r] = (float)s;
    }
    if (!vc->DispatchGEMV(W.data(), x.data(), yGpu.data(), (uint32_t)rows, (uint32_t)cols, 1))
        return false;
    double maxAbs = 0.0;
    for (size_t r = 0; r < rows; ++r) {
        double d = std::fabs((double)yGpu[r] - (double)yCpu[r]);
        if (d > maxAbs) maxAbs = d;
    }
    printf("NUMERICAL_PARITY_MAX_ABS=%.6g\n", maxAbs);
    return maxAbs < 1e-3;
}

static RunStats RunOnce(const char* model, const char* prefetchEnv) {
    RunStats st{};
#ifdef _WIN32
    SetEnvironmentVariableA("DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1", "1");
    _putenv_s("DEEP2_WEIGHT_MODE", "BOUNDED_STREAM");
    _putenv_s("DEEP2_WEIGHT_SLOTS", "2");
    _putenv_s("DEEP2_WEIGHT_BUDGET_MIB", "1024");
    _putenv_s("DEEP2_WEIGHT_PREFETCH", prefetchEnv);
    _putenv_s("RAWRXD_GPU_POLICY", "SOLO");
    _putenv_s("RAWRXD_GPU_DEVICES", "ALL");
    _putenv_s("RAWRXD_GPU_FWD", "1");
#endif
    Deep2Engine engine;
    if (!engine.loadModel(model)) return st;
    const auto& mw = engine.getModelWeights();
    EngineConfig cfg{};
    cfg.hiddenDim = mw.hiddenDim; cfg.numLayers = mw.numLayers;
    cfg.numHeads = mw.numHeads; cfg.numKVHeads = mw.numKVHeads;
    cfg.headDim = mw.headDim; cfg.vocabSize = mw.vocabSize;
    cfg.maxSeqLen = 4096; cfg.useKVCache = true; cfg.useThreadPool = true;
    cfg.numThreads = 16;
    if (!engine.initialize(cfg)) return st;
    engine.enableVulkan(true);
    engine.enableMedusa(false);
    RunGen(engine, "hi", 1);
    auto t0 = std::chrono::steady_clock::now();
    size_t n = RunGen(engine, "hello", 8);
    auto t1 = std::chrono::steady_clock::now();
    double sec = std::chrono::duration<double>(t1 - t0).count();
    st.tps = (n > 0 && sec > 0) ? (double)n / sec : 0.0;
    auto* vc = engine.getVulkanComputeSlot(0);
    const auto& c = engine.gpuForwardCounters();
    if (vc) {
        st.peak = vc->WeightStreamPeakBytes();
        st.growth = vc->WeightResidentGrowthAfterInit();
        st.waitIdle = vc->WeightHotpathWaitIdle();
        st.createB = vc->WeightHotpathCreateBuf();
        st.destroyB = vc->WeightHotpathDestroyBuf();
        st.overlap = vc->WeightOverlapEvents();
        st.reuses = vc->WeightSlotReuses();
        st.allocs = vc->WeightSlotAllocs();
        st.gemvOk = vc->GemvSuccess();
        st.slots = vc->WeightSlotCount();
        st.stream = vc->WeightStreamActive();
        st.permanentF32 = vc->PermanentF32WeightCache();
    }
    st.hostFwd = c.hostForwardLayerCalls;
    st.live = c.liveDecodeResidentTokens;
    st.fallback = engine.vulkanGemvFallbackCount();
    return st;
}

int main(int argc, char** argv) {
    const char* model = argc > 1 ? argv[1]
        : "G:\\~dev\\rawrxd\\models\\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf";
    printf("STREAMER_GPU_WEIGHT_PREFETCH_001\nModel: %s\n", model);
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\STREAMER_GPU_WEIGHT_PREFETCH_001", nullptr);

    printf("--- sync baseline (PREFETCH=0) ---\n");
    RunStats sync = RunOnce(model, "0");
    printf("SYNC_TPS=%.3f OVERLAP=%llu\n", sync.tps, (unsigned long long)sync.overlap);

    printf("--- prefetch (PREFETCH=1) ---\n");
    RunStats pf = RunOnce(model, "1");
    printf("PREFETCH_TPS=%.3f OVERLAP=%llu\n", pf.tps, (unsigned long long)pf.overlap);

    // Parity under prefetch config
#ifdef _WIN32
    _putenv_s("DEEP2_WEIGHT_PREFETCH", "1");
    _putenv_s("DEEP2_WEIGHT_MODE", "BOUNDED_STREAM");
    _putenv_s("DEEP2_WEIGHT_SLOTS", "2");
    _putenv_s("RAWRXD_GPU_FWD", "1");
    _putenv_s("RAWRXD_GPU_POLICY", "SOLO");
#endif
    Deep2Engine eng;
    bool parity = false;
    if (eng.loadModel(model)) {
        const auto& mw = eng.getModelWeights();
        EngineConfig cfg{};
        cfg.hiddenDim = mw.hiddenDim; cfg.numLayers = mw.numLayers;
        cfg.numHeads = mw.numHeads; cfg.numKVHeads = mw.numKVHeads;
        cfg.headDim = mw.headDim; cfg.vocabSize = mw.vocabSize;
        cfg.maxSeqLen = 2048; cfg.useKVCache = true; cfg.useThreadPool = true;
        cfg.numThreads = 16;
        if (eng.initialize(cfg)) {
            eng.enableVulkan(true);
            eng.enableMedusa(false);
            parity = NumericalParity(eng);
        }
    }

    const bool pass =
        pf.tps > 0 && sync.tps > 0 &&
        pf.tps > sync.tps &&
        pf.stream &&
        pf.slots >= 2 &&
        pf.growth == 0 &&
        !pf.permanentF32 &&
        pf.waitIdle == 0 &&
        pf.createB == 0 &&
        pf.destroyB == 0 &&
        pf.overlap > 0 &&
        pf.reuses > 0 &&
        pf.allocs == 2 &&
        pf.live > 0 &&
        pf.hostFwd == 0 &&
        pf.fallback == 0 &&
        pf.gemvOk > 0 &&
        parity;

    auto emit = [&](FILE* o) {
        if (!o) return;
        fprintf(o, "WEIGHT_MODE=BOUNDED_STREAM\n");
        fprintf(o, "WEIGHT_PREFETCH=1\n");
        fprintf(o, "WEIGHT_SLOT_COUNT=%u\n", pf.slots);
        fprintf(o, "WEIGHT_SLOT_ALLOCS=%llu\n", (unsigned long long)pf.allocs);
        fprintf(o, "WEIGHT_SLOT_REUSES=%llu\n", (unsigned long long)pf.reuses);
        fprintf(o, "DEEP2_WEIGHT_STREAM_PEAK_BYTES=%llu\n", (unsigned long long)pf.peak);
        fprintf(o, "RESIDENT_WEIGHT_GROWTH_AFTER_INIT=%llu\n", (unsigned long long)pf.growth);
        fprintf(o, "PERMANENT_F32_WEIGHT_CACHE=%u\n", pf.permanentF32 ? 1u : 0u);
        fprintf(o, "HOTPATH_QUEUE_WAIT_IDLE=%llu\n", (unsigned long long)pf.waitIdle);
        fprintf(o, "HOTPATH_WEIGHT_CREATE_BUFFER=%llu\n", (unsigned long long)pf.createB);
        fprintf(o, "HOTPATH_WEIGHT_DESTROY_BUFFER=%llu\n", (unsigned long long)pf.destroyB);
        fprintf(o, "WEIGHT_OVERLAP_EVENTS=%llu\n", (unsigned long long)pf.overlap);
        fprintf(o, "SYNC_BASELINE_TPS=%.3f\n", sync.tps);
        fprintf(o, "PREFETCH_TPS=%.3f\n", pf.tps);
        fprintf(o, "TPS_SPEEDUP=%.3f\n", sync.tps > 0 ? pf.tps / sync.tps : 0.0);
        fprintf(o, "NUMERICAL_PARITY=%s\n", parity ? "PASS" : "FAIL");
        fprintf(o, "LIVE_DECODE_RESIDENT_FORWARD=%u\n", pf.live > 0 ? 1u : 0u);
        fprintf(o, "HOST_FORWARD_LAYER_CALLS=%llu\n", (unsigned long long)pf.hostFwd);
        fprintf(o, "FALLBACK=%llu\n", (unsigned long long)pf.fallback);
        fprintf(o, "STREAMER_GPU_WEIGHT_PREFETCH_001=%s\n", pass ? "PASS" : "FAIL");
    };
    emit(stdout);
    FILE* f = fopen("G:\\~dev\\rawrxd\\evidence\\STREAMER_GPU_WEIGHT_PREFETCH_001\\GATE_STATUS.txt", "w");
    if (f) { emit(f); fclose(f); }
    fflush(stdout);
    _exit(pass ? 0 : 2);
}
