// ============================================================================
// rawr_run_stream.cpp — RAWR_RUN_STREAM_001
// Thin vertical adapter: `rawr run <alias> '<request>'` -> Deep2 Vulkan path.
//
// Lifted verbatim from the proven invocation sequence in
// tests/qwen32_40tps_gate.cpp + tests/deep2_standalone.cpp. No alternate
// tokenizer. No alternate Vulkan setup. No second scheduler. No CPU demo
// fallback. The product command uses the same execution path as the
// benchmark harness.
// ============================================================================

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <memory>
#include <string>
#include <string_view>

#include "deep2/Deep2Engine.h"

// Strict-GPU violation counter owned by the embedding binary.
// Deep2Engine_Speculative.cpp increments this whenever a strict no-CPU-
// fallback constraint is violated; the gate executables define the same
// symbol. The product binary owns it now.
std::atomic<uint32_t> g_strictGpuViolations{0};

namespace rawrxd {
namespace runstream {

using Deep2::Deep2Engine;
using Deep2::EngineConfig;
using Deep2::GenerationOptions;
using Deep2::GenerationResult;

// Receipt emitted by run_rawr_run() — RAWR_RUN_STREAM_001 authority.
struct RunStreamReceipt {
    int         exitCode            = 1;
    bool        modelResolved       = false;
    bool        engineInitialized   = false;
    bool        modelLoaded         = false;
    bool        vulkanInference     = false;
    bool        cpuDemoEngine       = false;
    bool        modelFallback       = false;
    bool        streamCallbackUsed  = false;
    uint64_t    generatedTokens     = 0;
    uint64_t    promptTokens        = 0;
    double      generationMs        = 0.0;
    double      decodeTps           = 0.0;
    uint64_t    unplannedFallbacks  = 0;
    bool        strictViolation     = false;
    std::string status             = "FAIL";
};

class RawrDeep2Runner {
public:
    // Cold path: initialize engine + load model exactly as the gate does.
    bool load(const std::string& modelPath, RunStreamReceipt& receipt) {
        EngineConfig cfg{};
        cfg.maxSeqLen = 4096;
        cfg.numThreads = 0;

        if (!engine_.initialize(cfg)) {
            std::fprintf(stderr,
                         "[RAWR_RUN_STREAM_001] stage=initialize FAIL\n");
            receipt.engineInitialized = false;
            return false;
        }
        receipt.engineInitialized = true;
        receipt.vulkanInference = false;

        if (!engine_.loadModel(modelPath)) {
            std::fprintf(stderr,
                         "[RAWR_RUN_STREAM_001] stage=load FAIL path=%s\n",
                         modelPath.c_str());
            return false;
        }
        receipt.modelLoaded = true;
        loadedModel_ = modelPath;

        // Same strict Vulkan enablement as qwen32_40tps_gate:
        // no CPU fallback is permitted on the product path.
        engine_.setVulkanStrictNoCpuFallback(true);
        engine_.enableVulkan(true);
        if (!engine_.isVulkanInitialized() ||
            !engine_.gpuResidentDecodeEnabled()) {
            std::fprintf(stderr,
                         "[RAWR_RUN_STREAM_001] stage=vulkan FAIL devices=%u\n",
                         engine_.vulkanDeviceCount());
            return false;
        }
        receipt.vulkanInference = true;
        return true;
    }

    // Warm path: model remains mapped, Vulkan pipelines remain warm.
    bool run(std::string_view prompt, uint32_t maxTokens,
             const std::function<void(std::string_view)>& onToken,
             RunStreamReceipt& receipt) {
        GenerationOptions opts{};
        opts.maxTokens = maxTokens;
        opts.temperature = 0.0f;
        opts.topK = 1;
        opts.topP = 1.0f;
        opts.repeatPenalty = 1.0f;
        opts.seed = 1;

        bool streamed = false;
        const GenerationResult result = engine_.generateStream(
            std::string(prompt), opts,
            [&](int32_t, const std::string& piece) -> bool {
                streamed = true;
                if (onToken) {
                    onToken(std::string_view(piece));
                }
                return true;
            });

        receipt.generatedTokens = result.generatedTokens;
        receipt.promptTokens = result.promptTokens;
        receipt.generationMs = result.generationTimeMs;
        receipt.decodeTps =
            result.generationTimeMs > 0.0
                ? static_cast<double>(result.generatedTokens) /
                      (result.generationTimeMs * 0.001)
                : 0.0;
        receipt.streamCallbackUsed = streamed;
        receipt.unplannedFallbacks = engine_.vulkanUnplannedFallbacks();
        receipt.strictViolation = engine_.vulkanStrictViolation();
        return result.generatedTokens > 0;
    }

    const std::string& loadedModel() const { return loadedModel_; }
    bool loaded() const { return !loadedModel_.empty(); }

private:
    Deep2Engine engine_{};
    std::string loadedModel_;
};

// ---------------------------------------------------------------------------
// Persistent runner (RAWR_RUN_PERSISTENT_ENGINE_001 hook).
// The engine stays alive across requests: warm tokenizer, warm Vulkan
// pipelines, resident weights. Today one process = one invocation, but the
// lifetime already lives here so `rawr process` / IDE server ownership is a
// drop-in change.
// ---------------------------------------------------------------------------
static std::unique_ptr<RawrDeep2Runner> g_runner;
static std::string g_loadedModel;

static void emitReceipt(const RunStreamReceipt& r) {
    std::fprintf(stderr,
                 "RAWR_RUN_STREAM_001_RECEIPT\n"
                 "MODEL_RESOLVED=%d\n"
                 "DEEP2_ENGINE=%d\n"
                 "VULKAN_INFERENCE=%d\n"
                 "CPU_DEMO_ENGINE=%d\n"
                 "MODEL_FALLBACK=%d\n"
                 "STREAM_CALLBACK=%d\n"
                 "PROMPT_TOKENS=%llu\n"
                 "GENERATED_TOKENS=%llu\n"
                 "GENERATION_MS=%.3f\n"
                 "DECODE_TPS=%.3f\n"
                 "UNPLANNED_FALLBACKS=%llu\n"
                 "STRICT_GPU_VIOLATIONS=%d\n"
                 "GEN_EXIT=%d\n"
                 "RAWR_RUN_STREAM_001=%s\n",
                 r.modelResolved ? 1 : 0,
                 r.engineInitialized ? 1 : 0,
                 r.vulkanInference ? 1 : 0,
                 r.cpuDemoEngine ? 1 : 0,
                 r.modelFallback ? 1 : 0,
                 r.streamCallbackUsed ? 1 : 0,
                 static_cast<unsigned long long>(r.promptTokens),
                 static_cast<unsigned long long>(r.generatedTokens),
                 r.generationMs,
                 r.decodeTps,
                 static_cast<unsigned long long>(r.unplannedFallbacks),
                 r.strictViolation ? 1 : 0,
                 r.exitCode,
                 r.status.c_str());
    std::fflush(stderr);
}

// Acquire the persistent runner, loading the model on first use or on model
// switch. Returns nullptr when load fails.
static RawrDeep2Runner* acquireRunner(const std::string& modelPath,
                                       RunStreamReceipt& receipt) {
    if (g_runner && g_loadedModel == modelPath) {
        return g_runner.get();
    }
    g_runner.reset(new RawrDeep2Runner());
    g_loadedModel.clear();
    if (!g_runner->load(modelPath, receipt)) {
        g_runner.reset();
        return nullptr;
    }
    g_loadedModel = modelPath;
    return g_runner.get();
}

// ---------------------------------------------------------------------------
// Top-level entry: full RAWR_RUN_STREAM_001 receipt.
// ---------------------------------------------------------------------------
int run_rawr_run(const std::string& modelPath, const std::string& prompt,
                 uint32_t maxTokens) {
    RunStreamReceipt receipt{};

    if (modelPath.empty()) {
        receipt.modelResolved = false;
        std::fprintf(stderr, "[RAWR_RUN_STREAM_001] MODEL_RESOLVED=0\n");
        emitReceipt(receipt);
        return 1;
    }
    receipt.modelResolved = true;

    RawrDeep2Runner* runner = acquireRunner(modelPath, receipt);
    if (!runner) {
        emitReceipt(receipt);
        return 1;
    }

    const bool ok = runner->run(prompt, maxTokens,
                                [](std::string_view text) {
                                    std::fwrite(text.data(), 1, text.size(),
                                                stdout);
                                    std::fflush(stdout);
                                },
                                receipt);

    const bool pass = ok &&
                      receipt.generatedTokens > 0 &&
                      receipt.streamCallbackUsed &&
                      receipt.unplannedFallbacks == 0 &&
                      !receipt.strictViolation;
    receipt.status = pass ? "PASS" : "FAIL";
    receipt.exitCode = pass ? 0 : 1;

    std::fwrite("\n", 1, 1, stdout);
    std::fflush(stdout);

    emitReceipt(receipt);
    return receipt.exitCode;
}

} // namespace runstream
} // namespace rawrxd