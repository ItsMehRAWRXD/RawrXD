#pragma once
// ============================================================================
// rawr_run_stream.hpp — RAWR_RUN_STREAM_001 declarations
// Thin vertical adapter: `rawr run <alias> '<request>'` -> Deep2 Vulkan path.
// Definitions in rawr_run_stream.cpp. The persistent runner is shared with the
// agent loop (rawr_agent.cpp) so both surfaces drive one Deep2Engine.
// ============================================================================
#include <cstdint>
#include <cstdio>
#include <functional>
#include <string>
#include <string_view>

#include "deep2/Deep2Engine.h"

namespace rawrxd {
namespace runstream {

// Receipt emitted by run_rawr_run() — RAWR_RUN_STREAM_001 authority.
struct RunStreamReceipt {
    int         exitCode            = 1;
    bool        modelResolved       = false;
    bool        engineInitialized   = false;
    bool        modelLoaded         = false;
    bool        vulkanInference      = false;
    bool        cpuDemoEngine        = false;
    bool        modelFallback        = false;
    bool        streamCallbackUsed   = false;
    uint64_t    generatedTokens     = 0;
    uint64_t    promptTokens        = 0;
    double      generationMs        = 0.0;
    double      decodeTps           = 0.0;
    uint64_t    unplannedFallbacks  = 0;
    bool        strictViolation     = false;
    std::string status              = "FAIL";
};

class RawrDeep2Runner {
public:
    // Cold path: initialize engine + load model exactly as the gate does.
    bool load(const std::string& modelPath, RunStreamReceipt& receipt);

    // Warm path: model remains mapped, Vulkan pipelines remain warm.
    bool run(std::string_view prompt, uint32_t maxTokens,
             const std::function<void(std::string_view)>& onToken,
             RunStreamReceipt& receipt);

    void reset() { engine_.reset(); }

    // Engine access for the agent loop (same engine, same lifetime).
    Deep2::Deep2Engine& engine() { return engine_; }

    const std::string& loadedModel() const { return loadedModel_; }
    bool loaded() const { return !loadedModel_.empty(); }

private:
    Deep2::Deep2Engine engine_{};
    std::string loadedModel_;
};

// One-shot product stream: RAWR_RUN_STREAM_001.
int run_rawr_run(const std::string& modelPath, const std::string& prompt,
                 uint32_t maxTokens);

// Persistent runner acquisition (RAWR_RUN_PERSISTENT_ENGINE_001 hook).
// Loads on first use / model switch; nullptr on load failure.
RawrDeep2Runner* acquireSharedRunner(const std::string& modelPath,
                                      RunStreamReceipt& receipt);

} // namespace runstream
} // namespace rawrxd