// Deep2Executor.hpp — RAWRXD_POLYMORPHIC_NATIVE_EXECUTION_005
//
// Native Deep2 executor adapter. Connects the production Deep2 inference engine
// (Deep2::Deep2Engine) to the blackboard_v5::ExecutorFn seam. Performs REAL
// inference on a local GGUF model and reports authoritative prefill/decode TPS
// and generated-token counts from Deep2Engine::InferenceStats. GPU dispatch /
// residency / fallback telemetry is captured from gpuForwardCounters() and
// dispatchAccount(). No fabricated measurements: on any failure it returns false
// and the blackboard accounts the failed attempt. No RNG. Volatile only.
#pragma once
#include "AdaptiveBlackboardIntelligenceV5.hpp"
#include "Deep2Engine.h"
#include <atomic>
#include <cstdio>
#include <string>
#include <vector>
#include <thread>
#include <algorithm>
#include <filesystem>

namespace rawrxd {
namespace deep2_native {

// Global execution configuration (model path + cancellation), no persistent state.
inline std::string& ModelPath() {
    static std::string p = "F:\\OllamaModels\\n4-tiny-oracle.gguf";
    return p;
}
inline void SetModelPath(const std::string& p) { ModelPath() = p; }

inline std::atomic<bool>& CancelFlag() { static std::atomic<bool> c{false}; return c; }
inline void RequestCancel() { CancelFlag().store(true); }
inline void ClearCancel()   { CancelFlag().store(false); }

// Discover local GGUF models under a root (e.g. OLLAMA_MODELS).
inline std::vector<std::string> DiscoverGGUF(const std::string& root) {
    std::vector<std::string> out;
    namespace fs = std::filesystem;
    if (!fs::exists(root)) return out;
    for (auto it = fs::recursive_directory_iterator(root,
             fs::directory_options::skip_permission_denied);
         it != fs::recursive_directory_iterator(); ++it) {
        if (it->is_regular_file() && it->path().extension() == ".gguf" &&
            it->file_size() > 0)
            out.push_back(it->path().string());
    }
    return out;
}

// GPU / execution telemetry snapshot (real counters, no fabrication).
struct GpuTelemetry {
    uint64_t forwardLayers = 0, layerSubmits = 0, opSubmits = 0;
    uint64_t forwardFallbacks = 0, hostForwardLayerCalls = 0;
    uint64_t cmdDispatch = 0, queueSubmit = 0, gpuExecNs = 0;
    bool     resident = false;
};

class Deep2Executor {
public:
    // Lazy-load the model once; reuse the engine across experiments.
    bool EnsureLoaded() {
        if (loaded_) return true;
        Deep2::EngineConfig cfg;
        cfg.numThreads = (size_t)std::max(1, (int)std::thread::hardware_concurrency());
        std::snprintf(cfg.modelPath, sizeof(cfg.modelPath), "%s", ModelPath().c_str());
        if (!engine_.initialize(cfg)) return false;
        if (!engine_.loadModel(ModelPath())) return false;
        // Set the thread count once at load. Reconfiguring the thread pool on every
        // request rebuilds device/queue resources and was correlated with the
        // VK_ERROR_DEVICE_LOST observed on the third request.
        engine_.setNumThreads(cfg.numThreads);
        loaded_ = true;
        return true;
    }

    // blackboard_v5::ExecutorFn-compatible real Deep2 inference.
    bool operator()(const blackboard_v5::Controls& c, blackboard_v5::Measured& m) {
        if (CancelFlag().load()) return false;
        if (!EnsureLoaded()) return false;

        // Controls.batch maps to the prefill batching capability where available;
        // Deep2Engine resolves its own prefill chunking from model metadata.
        // (Thread count is fixed at load to avoid per-request device reconfiguration.)

        // Request-scoped GPU counters: reset before each call so forwardLayers is
        // per-request, not cumulative (a cumulative counter cannot detect a
        // device-lost call that executed zero GPU layers).
        engine_.resetGpuForwardCounters();
        engine_.resetDispatchAccount();

        const std::vector<int> toks = engine_.tokenize(prompt_);
        if (toks.empty()) return false;
        std::vector<int> out(std::max<size_t>(1, numPredict_));
        Deep2::InferenceStats st;
        const size_t n = engine_.generate(toks.data(), toks.size(),
                                          out.data(), out.size(), &st, nullptr);
        if (n == 0 || st.decodeTokensPerSecond <= 0.0) return false;

        m.decodeTps  = st.decodeTokensPerSecond;
        m.prefillTps = st.prefillTokensPerSecond;
        m.tokens     = (int)n;
        m.consistent = (st.tokensGenerated > 0);
        m.valid      = (st.decodeMs > 0.0);

        const auto gf = engine_.gpuForwardCounters();
        const auto da = engine_.dispatchAccount();
        lastGpu = GpuTelemetry{
            gf.forwardLayers, gf.layerSubmits, gf.opSubmits,
            gf.forwardFallbacks, gf.hostForwardLayerCalls,
            da.cmdDispatchCount, da.queueSubmitCount, da.gpuExecutionNs,
            Deep2::Deep2GpuForward_Resident(gf)
        };
        // If no GPU forward layers executed THIS request, the GPU path did not
        // engage (device-lost or forced CPU fallback). Flag it as a device failure
        // so the blackboard isolates it from valid performance samples.
        m.hardwareFailure = (gf.forwardLayers == 0);
        m.failure = m.hardwareFailure ? 5 : 0;
        return true;
    }

    GpuTelemetry lastGpu;
    size_t numPredict_ = 256;

private:
    Deep2::Deep2Engine engine_;
    bool loaded_ = false;
    std::string prompt_ = "Explain how computer memory works in 200 words.";
};

// Process-global instance so a plain function pointer satisfies ExecutorFn.
inline Deep2Executor& Global() { static Deep2Executor e; return e; }
inline bool Deep2Exec(const blackboard_v5::Controls& c, blackboard_v5::Measured& m) {
    return Global()(c, m);
}

} // namespace deep2_native
} // namespace rawrxd