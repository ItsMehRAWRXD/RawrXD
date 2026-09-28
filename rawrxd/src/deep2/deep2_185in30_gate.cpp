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

extern std::atomic<uint32_t> g_strictGpuViolations;

static constexpr uint32_t WARMUP_TOKENS = 16;
static constexpr uint32_t TARGET_TOKENS = 185;
static constexpr double LIMIT_SECONDS = 30.0;
static constexpr double REQUIRED_TPS = double(TARGET_TOKENS) / LIMIT_SECONDS;

static GenerationOptions greedy(uint32_t n) {
    GenerationOptions o{};
    o.maxTokens = n;
    o.temperature = 0.8f;
    o.topK = 40;
    o.topP = 0.95f;
    o.repeatPenalty = 1.0f;
    o.seed = 0; // 0 => auto-seed from std::chrono steady_clock
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

    // D03: enable cost/ownership graph instrumentation
    auto* vc = e.getVulkanCompute();
    if (vc) {
        vc->ResetCostGraph();
        vc->SetCostRecording(true);
    }

    LARGE_INTEGER freq{}, t0{}, t1{};
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t0);

    uint32_t callbackTokens = 0;
    bool deadlineExceeded = false;

    const auto measured = e.generateStream(
        "Write a complete C++ implementation of a lock-free bounded queue. "
        "Include memory ordering and correctness notes. ",
        greedy(TARGET_TOKENS),
        [&](int32_t tok, const std::string&) {
            if (callbackTokens < 16) std::fprintf(stderr, "AUDIT_TOK[%d]\n", tok);
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

    // D03: disable cost recording and emit graph receipt
    if (vc) {
        vc->SetCostRecording(false);
        vc->EmitD03Receipt(stderr);
    }

    const double sec = qpcSeconds(t0, t1, freq);
    const double tps = sec > 0.0 ? double(measured.generatedTokens) / sec : 0.0;

    const auto& gf = e.gpuForwardCounters();

    const char* executionClass;
    if (gf.dualRowDenseTokens > 0 && gf.dualRowSplitOps > 0)
        executionClass = "DUAL_ROW";
    else if (e.isRealGpuForward())
        executionClass = "FULL_RESIDENT";
    else
        executionClass = "UNKNOWN";

    const bool realGpu =
        e.isRealGpuForward() ||
        (gf.dualRowDenseTokens > 0 && gf.dualRowSplitOps > 0);

    const uint64_t dupDestroy = e.vulkanDuplicateDestroyAttempts();
    const bool zeroDuplicateDestroy = dupDestroy == 0;

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
        zeroFallback &&
        zeroDuplicateDestroy &&
        std::strcmp(executionClass, "UNKNOWN") != 0;

    // ---- ResidentAdmissionStreamer telemetry ----
    // vc points to the primary admitted device (slot 0) after admission filter.
    uint32_t gpu0_mode = 255;
    uint64_t weightOomRecov = 0, unhandledFail = 0;
    if (vc) {
        gpu0_mode = static_cast<uint32_t>(vc->LastAdmission().mode);
        weightOomRecov = vc->WeightOomRecoveries();
        unhandledFail = vc->UnhandledAllocFailures();
    }
    // If only one device is admitted and DUPLICATE_DESTROY_ATTEMPTS==0,
    // then full-model duplication did not occur.  If two devices were both
    // admitted in FULL mode, duplication count would be 2.  The runtime
    // already rejects WINDOWED devices, so this is 0 or >=2.
    const uint32_t fullModelDuplicationCount =
        (gpu0_mode == 1 && e.vulkanDeviceCount() > 1) ? e.vulkanDeviceCount() : 0;

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
        "GPU_DEVICE_COUNT=%u\n"
        "EXECUTION_CLASS=%s\n"
        "UNPLANNED_FALLBACKS=%llu\n"
        "STRICT_GPU_VIOLATION=%u\n"
        "DUPLICATE_DESTROY_ATTEMPTS=%llu\n"
        "GLOBAL_STRICT_GPU_VIOLATIONS=%u\n"
        "GPU0_ADMISSION_MODE=%u\n"
        "FULL_MODEL_DUPLICATION_COUNT=%u\n"
        "WEIGHT_OOM_RECOVERIES=%llu\n"
        "UNHANDLED_ALLOC_FAILURES=%llu\n"
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
        e.vulkanDeviceCount(),
        executionClass,
        (unsigned long long)e.vulkanUnplannedFallbacks(),
        e.vulkanStrictViolation() ? 1u : 0u,
        (unsigned long long)dupDestroy,
        g_strictGpuViolations.load(std::memory_order_relaxed),
        gpu0_mode,
        fullModelDuplicationCount,
        (unsigned long long)weightOomRecov,
        (unsigned long long)unhandledFail,
        pass ? "PASS" : "HOLD");

    return pass ? 0 : 1;
}
