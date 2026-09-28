#include "deep2/Deep2Engine.h"
#include "deep2/Deep2DualGpuRowSplit.hpp"
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <string>
#include <windows.h>

using Deep2::Deep2Engine;
using Deep2::EngineConfig;
using Deep2::GenerationOptions;
using Deep2::GenerationResult;

std::atomic<uint32_t> g_strictGpuViolations{0};

static constexpr uint32_t WARMUP_TOKENS = 16;
static constexpr uint32_t TARGET_TOKENS = 185;
static constexpr double LIMIT_SECONDS = 30.0;
static constexpr double REQUIRED_TPS = double(TARGET_TOKENS) / LIMIT_SECONDS;

static GenerationOptions greedy(uint32_t n) {
    GenerationOptions o{};
    o.maxTokens = n;
    o.temperature = 0.0f;
    o.topK = 1;
    o.topP = 1.0f;
    o.repeatPenalty = 1.0f;
    o.seed = 1;
    return o;
}

static double qpcSeconds(LARGE_INTEGER a, LARGE_INTEGER b, LARGE_INTEGER f) {
    return double(b.QuadPart - a.QuadPart) / double(f.QuadPart);
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: deep2_185in30_gate.exe <model.gguf>\n");
        return 2;
    }

    Deep2Engine e;
    EngineConfig cfg{};
    cfg.maxSeqLen = 4096;
    cfg.numThreads = 0;

    if (!e.initialize(cfg)) return 10;
    if (!e.loadModel(argv[1])) return 11;

    e.setVulkanStrictNoCpuFallback(true);
    e.enableVulkan(true);
    if (!e.isVulkanInitialized()) return 12;

    const auto warm = e.generateStream(
        "Deep2 warmup. Produce deterministic C++ notes. ",
        greedy(WARMUP_TOKENS),
        [](int32_t, const std::string&) { return true; });

    if (warm.generatedTokens != WARMUP_TOKENS) return 13;

    e.reset();
    e.resetGpuForwardCounters();
    Deep2::Deep2ResetDualRowTiming();

    LARGE_INTEGER freq{}, t0{}, t1{};
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t0);

    uint32_t callbackTokens = 0;
    bool deadlineExceeded = false;

    const auto measured = e.generateStream(
        "Write a complete C++ implementation of a lock-free bounded queue. "
        "Include memory ordering and correctness notes. ",
        greedy(TARGET_TOKENS),
        [&](int32_t, const std::string&) {
            ++callbackTokens;
            LARGE_INTEGER now{};
            QueryPerformanceCounter(&now);
            if (qpcSeconds(t0, now, freq) > LIMIT_SECONDS &&
                callbackTokens < TARGET_TOKENS) {
                deadlineExceeded = true;
                return false;
            }
            return true;
        });

    QueryPerformanceCounter(&t1);

    const double sec = qpcSeconds(t0, t1, freq);
    const double tps = sec > 0.0 ? double(measured.generatedTokens) / sec : 0.0;

    const auto& gf = e.gpuForwardCounters();
    const bool realGpu =
        e.isRealGpuForward() ||
        (gf.dualRowDenseTokens > 0 && gf.dualRowSplitOps > 0);

    const bool zeroFallback =
        e.vulkanUnplannedFallbacks() == 0 &&
        !e.vulkanStrictViolation() &&
        g_strictGpuViolations.load(std::memory_order_relaxed) == 0;

    const bool pass =
        measured.generatedTokens == TARGET_TOKENS &&
        callbackTokens == TARGET_TOKENS &&
        !deadlineExceeded &&
        sec <= LIMIT_SECONDS &&
        tps >= REQUIRED_TPS &&
        realGpu &&
        zeroFallback;

    std::fprintf(stderr,
        "GATE=RAWRXD_DEEP2_185_IN_30_001\n"
        "MEASURE_SCOPE=DECODE_AFTER_MODEL_LOAD_AND_16_TOKEN_WARMUP\n"
        "TARGET_TOKENS=185\n"
        "TIME_LIMIT_SECONDS=30.000000\n"
        "REQUIRED_TPS=%.6f\n"
        "GENERATED=%llu\n"
        "CALLBACK_TOKENS=%u\n"
        "WALL_SECONDS=%.6f\n"
        "WALL_TPS=%.6f\n"
        "DECODE_TPS_ENGINE=%.6f\n"
        "REAL_GPU_FORWARD=%u\n"
        "FULL_RESIDENT_GPU=%u\n"
        "DUAL_ROW_DENSE_TOKENS=%llu\n"
        "DUAL_ROW_SPLIT_OPS=%llu\n"
        "UNPLANNED_FALLBACKS=%llu\n"
        "STRICT_GPU_VIOLATION=%u\n"
        "GLOBAL_STRICT_GPU_VIOLATIONS=%u\n"
        "VERDICT=%s\n",
        REQUIRED_TPS,
        (unsigned long long)measured.generatedTokens,
        callbackTokens,
        sec,
        tps,
        measured.generationTimeMs > 0.0
            ? double(measured.generatedTokens) / (measured.generationTimeMs * 0.001)
            : 0.0,
        realGpu ? 1u : 0u,
        e.isRealGpuForward() ? 1u : 0u,
        (unsigned long long)gf.dualRowDenseTokens,
        (unsigned long long)gf.dualRowSplitOps,
        (unsigned long long)e.vulkanUnplannedFallbacks(),
        e.vulkanStrictViolation() ? 1u : 0u,
        g_strictGpuViolations.load(std::memory_order_relaxed),
        pass ? "PASS" : "HOLD");

    return pass ? 0 : 1;
}
