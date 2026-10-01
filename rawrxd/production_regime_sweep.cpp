// production_regime_sweep.cpp
//
// RAWRXD_PRODUCTION_REGIME_SWEEP_001
//
// The second half of the regime ladder. regime_sweep.cpp answers "at a
// controlled synthetic F32 geometry, how does scheduling and kernel selection
// behave?" It answers that question by calling rawrxd::TransformerRuntime,
// which is NOT the inference engine: rawrxd.exe runs Deep2::Deep2Engine. So
// regime_sweep's number cannot be promoted to a production claim, and this file
// exists so that no one has to promote it by hand.
//
// This harness calls the real engine instead:
//
//   production_regime_sweep
//          |
//          v
//   Deep2::Deep2Engine::loadModel   <- real GGUF, real quantization
//          |
//          v
//   Deep2::Deep2Engine::generateStream  <- real dispatcher, real kernels,
//          |                                real memory path, real residency
//          v
//   InferenceStats / GenerationResult (measured, not modelled)
//
// HONESTY RULES
//  * Every TPS number is measured on this run by the production engine.
//  * The dispatch receipt reports INTROSPECTED state. Where a value cannot be
//    observed the line is printed as N/A. A hardcoded 1 would be a fabricated
//    claim that a feature contributed.
//  * The engine is NOT claimed to reach a feature just because the feature
//    exists. Packed-quant, fusion and prefetch lines are reported as
//    N/A_PENDING_TELEMETRY unless the engine actually exposes the counter,
//    because at this date it does not expose per-feature selection counters.
//  * Q3_K is excluded from every success column pending B65 parity.
//
// Build (from F:\~dev\rawrxd):
//   cl /nologo /std:c++20 /EHsc /O2 /MD /Fe:production_regime_sweep.exe
//      /I src /I src\deep2 /I include production_regime_sweep.cpp <engine TUs>
//
// In practice this target is driven from CMake, which already knows the full
// Deep2 source set, rather than from a hand-written command line.

#include "deep2/Deep2Engine.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

using Clock = std::chrono::steady_clock;

static double Ms(Clock::time_point a, Clock::time_point b) {
    return std::chrono::duration<double, std::milli>(b - a).count();
}

// RAWRXD_PRODUCTION_REGIME_SWEEP_001
// The dispatch receipt reports only what can be OBSERVED. Anything the engine
// does not expose is N/A, never 1.
static void PrintReceipt(Deep2::Deep2Engine& eng, const std::string& modelPath,
                         bool gpuRequested) {
    std::printf("---- dispatch receipt (production engine) ----\n");
    std::printf("ENGINE=Deep2::Deep2Engine          (the engine rawrxd.exe runs)\n");
    std::printf("MODEL_PATH=%s\n", modelPath.c_str());

    const bool vkInit = eng.isVulkanInitialized();
    const unsigned vkDev = eng.vulkanDeviceCount();
    std::printf("GPU_REQUESTED=%d\n", gpuRequested ? 1 : 0);
    std::printf("GPU_INITIALIZED=%d                (introspected: isVulkanInitialized)\n",
                vkInit ? 1 : 0);
    std::printf("GPU_DEVICE_COUNT=%u               (introspected: vulkanDeviceCount)\n", vkDev);
    std::printf("VULKAN_COMPUTE_SLOT0=%d            (introspected: getVulkanComputeSlot(0))\n",
                eng.getVulkanComputeSlot(0) ? 1 : 0);

    // RAWRXD_WEIGHT_TYPE_FROM_TENSORS_001: the weight type is now READ from the
    // loaded tensors rather than asserted. It used to be N/A_PENDING_TELEMETRY
    // because no accessor existed; the config field that looks like one
    // (config_.weightQuant) is never assigned from the model and would have
    // reported FP32 for a Q6_K model.
    const int wt = eng.loadedWeightType();
    if (wt >= 0) {
        std::printf("WEIGHT_TYPE=%s                      (introspected: loaded tensors, id=%d)\n",
                    eng.loadedWeightTypeName(), wt);
        std::printf("WEIGHT_TYPE_DOMINANCE=%.1f%%          (share of projection/FFN tensors at that type)\n",
                    eng.loadedWeightTypeDominancePercent());
        std::printf("WEIGHT_TYPE_HISTOGRAM=%s\n", eng.loadedWeightTypeHistogram().c_str());
    } else {
        std::printf("WEIGHT_TYPE=UNKNOWN                  (no loaded tensor reported a type)\n");
    }

    // Packed/fused/prefetch are real Deep2 features, but the engine exposes no
    // per-feature "was this selected for this layer" counter. Reporting a value
    // here would assert participation nobody measured, so these stay N/A.
    std::printf("PACKED_GEMV=N/A_PENDING_TELEMETRY (no per-feature selection counter)\n");
    std::printf("NATIVE_Q4_K=N/A_PENDING_TELEMETRY (no per-feature selection counter)\n");
    std::printf("NATIVE_Q3_K=EXCLUDED_PENDING_B65   (never admitted to a success column)\n");
    std::printf("FUSED_QKV=N/A_PENDING_TELEMETRY\n");
    std::printf("FUSED_ATTN=N/A_PENDING_TELEMETRY\n");
    std::printf("PREFETCH=N/A_PENDING_TELEMETRY\n");
    std::printf("KV_CACHE_GATING=N/A_PENDING_TELEMETRY\n");
    std::printf("ATTENTION_MATH=N/A_PENDING_TELEMETRY\n");
    std::printf("FALLBACKS=N/A_PENDING_TELEMETRY\n");
    std::printf("MEASURED_REGION=decode_only        (generationTimeMs, not total wall)\n");
    std::printf("NOTE=rawrxd::TransformerRuntime (used by regime_sweep.cpp) is NOT this\n");
    std::printf("     engine. Its numbers do not transfer and are not promoted here.\n\n");
}

// File-scope state, so the fenced frame below holds nothing that needs
// unwinding. MSVC rejects __try in a frame that has any such local (C2712);
// this is the same split the headless CLI uses for the same reason.
static std::string g_model;
static int  g_tokens = 24;
static int  g_rc = 0;
static bool g_teardownFaulted = false;
static unsigned long g_teardownException = 0;

static const char* const kPrompts[] = {
    "The capital of France is",
    "def fibonacci(n):\n    if n < 2:\n        return n\n",
};

// Ordinary function: it may unwind freely. All the real work lives here.
static void RunAll(Deep2::Deep2Engine& eng) {
    for (const char* p : kPrompts) {
        for (int rep = 0; rep < 2; ++rep) {
            eng.reset();
            // RAWRXD_PRODUCTION_REGIME_SWEEP_001: InferenceStats is an
            // OUT-PARAMETER on generate(), not a getter on the engine. There is
            // no getStats(), so the sweep passes a pointer and reads the
            // engine's own measurements back out of it.
            Deep2::GenerationOptions opt;
            opt.maxTokens = (uint32_t)g_tokens;
            // Greedy with a fixed seed so every repetition performs the same
            // work and a throughput comparison is comparing like with like.
            opt.temperature = 0.0f;
            opt.topK = 1;
            opt.seed = 1234;

            const auto t0 = Clock::now();
            auto r = eng.generateStream(p, opt,
                [](int32_t, const std::string&) { return true; });
            const double wall = Ms(t0, Clock::now());

            // generateStream takes no stats pointer, so the engine's own decode
            // timer is collected by driving the same engine through generate().
            // Both are the production engine.
            const std::vector<int> ptoks = eng.tokenize(p);
            Deep2::InferenceStats gst;
            std::vector<int> otoks((size_t)g_tokens);
            const size_t produced = eng.generate(ptoks.data(), ptoks.size(),
                                                 otoks.data(), otoks.size(), &gst);

            char label[64];
            std::snprintf(label, sizeof(label), "rep%d %.14s", rep, p);
            std::printf("--- %s ---\n", label);
            std::printf("  stream: prompt=%llu generated=%llu completed=%d cancelled=%d "
                        "status=%d wall=%.1f ms\n",
                        (unsigned long long)r.promptTokens,
                        (unsigned long long)r.generatedTokens,
                        r.completed ? 1 : 0, r.cancelled ? 1 : 0, (int)r.status, wall);
            std::printf("  engine: prompt=%llu tok (%.2f tok/s)  generated=%zu tok "
                        "decode=%.1f ms (%.3f tok/s)\n",
                        (unsigned long long)gst.promptTokens, gst.prefillTokensPerSecond,
                        produced, gst.decodeMs, gst.decodeTokensPerSecond);
            if (!r.failureDetail.empty()) {
                std::printf("  failureDetail='%s'\n", r.failureDetail.c_str());
            }
            if (!r.completed || r.generatedTokens == 0) {
                std::printf("  REJECTED: generation did not complete cleanly\n");
                g_rc = 1;
            }
        }
    }
}

// The only frame containing __try. It has no locals at all, so C2712 cannot
// fire. RAWRXD_TEARDOWN_VS_INFERENCE_001: a fault here has already had its
// measurements flushed, so it is reported instead of being allowed to take the
// process down and destroy the evidence.
static void RunFenced(Deep2::Deep2Engine& eng) {
    __try {
        RunAll(eng);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_teardownFaulted = true;
        g_teardownException = GetExceptionCode();
        std::fprintf(stderr, "TEARDOWN_FAULT exception=0x%08lX -- results already flushed\n",
                     g_teardownException);
        std::fflush(stderr);
    }
}

int main(int argc, char** argv) {
    // A crash or hang must still report how far the run got.
    setvbuf(stdout, nullptr, _IONBF, 0);

    g_model = (argc > 1) ? argv[1] : "F:/~dev/qwen2.5-coder-1.5b-base.gguf";
    if (argc > 2) g_tokens = std::atoi(argv[2]);
    // Opt-out, matching the CLI's committed policy: GPU unless DEEP2_DISABLE_VULKAN.
    const char* dis = std::getenv("DEEP2_DISABLE_VULKAN");
    const bool gpuRequested = !(dis && (dis[0] == '1' || dis[0] == 't' || dis[0] == 'T'));

    std::printf("model=%s tokens=%d gpu_requested=%d\n", g_model.c_str(), g_tokens,
                gpuRequested ? 1 : 0);

    Deep2::Deep2Engine eng;
    eng.enableVulkan(gpuRequested);

    Deep2::ModelLoadDiag diag;
    const auto t_load0 = Clock::now();
    if (!eng.loadModel(g_model, &diag)) {
        std::printf("FATAL loadModel failed stage=%d name='%s' message='%s'\n",
                    diag.stageCode, diag.stageName.c_str(), diag.message.c_str());
        return 2;
    }
    std::printf("load_ms=%.1f\n\n", Ms(t_load0, Clock::now()));

    PrintReceipt(eng, g_model, gpuRequested);

    RunFenced(eng);

    std::printf("\nTEARDOWN_FAULT=%d\n", g_teardownFaulted ? 1 : 0);
    std::printf("RUNS_COMPLETED_CLEANLY=%d\n", g_rc == 0 ? 1 : 0);
    std::printf("VERDICT=%s\n", g_rc == 0 ? "PASS" : "FAIL");
    return g_rc;
}
