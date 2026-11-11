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

enum class DevicePolicy : uint8_t {
    Gpu,
    Cpu,
    Auto
};

struct RunStreamOptions {
    uint32_t maxTokens = 1024;
    uint32_t contextTokens = 0; // 0 = engine/model default
    DevicePolicy device = DevicePolicy::Gpu;
    bool interactive = false;
    std::string receiptPath;
};

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
    bool        eosReached           = false;
    int         eosToken             = -1;
    bool        contextAdmitted      = false;
    uint64_t    contextLimit         = 0;
    std::string device               = "unselected";
    std::string modelPath;
    std::string error;
    uint64_t    generatedTokens     = 0;
    uint64_t    promptTokens        = 0;
    double      generationMs        = 0.0;
    double      decodeTps           = 0.0;
    uint64_t    unplannedFallbacks  = 0;
    bool        strictViolation     = false;
    uint64_t    dualRowDispatches   = 0;
    uint64_t    dualRowSlot0        = 0;
    uint64_t    dualRowSlot1        = 0;
    uint64_t    gpuForwardLayers    = 0;
    bool        dualPhysicalGpu     = false;
    bool        timestampValid0     = false;
    bool        timestampValid1     = false;
    uint64_t    gpuKernelNs0        = 0;
    uint64_t    gpuKernelNs1        = 0;
    uint64_t    queueSubmits0       = 0;
    uint64_t    queueSubmits1       = 0;
    uint64_t    weightUploads0      = 0;
    uint64_t    weightUploads1      = 0;
    uint64_t    weightHits0         = 0;
    uint64_t    weightHits1         = 0;
    uint64_t    submit_cpu_ns0      = 0;
    uint64_t    submit_cpu_ns1      = 0;
    uint64_t    wait_ns0            = 0;
    uint64_t    wait_ns1            = 0;
    std::string status              = "FAIL";
};

class RawrDeep2Runner {
public:
    // Cold path: initialize engine + load model exactly as the gate does.
    bool load(const std::string& modelPath, RunStreamReceipt& receipt);
    bool load(const std::string& modelPath, const RunStreamOptions& options,
              RunStreamReceipt& receipt);

    // Warm path: model remains mapped, Vulkan pipelines remain warm.
    bool run(std::string_view prompt, uint32_t maxTokens,
             const std::function<void(std::string_view)>& onToken,
             RunStreamReceipt& receipt);
    bool run(std::string_view prompt, const RunStreamOptions& options,
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
int run_rawr_run(const std::string& modelPath, const std::string& prompt,
                 const RunStreamOptions& options);
int run_rawr_interactive(const std::string& modelPath,
                         const RunStreamOptions& options);

// Persistent runner acquisition (RAWR_RUN_PERSISTENT_ENGINE_001 hook).
// Loads on first use / model switch; nullptr on load failure.
RawrDeep2Runner* acquireSharedRunner(const std::string& modelPath,
                                      RunStreamReceipt& receipt);
RawrDeep2Runner* acquireSharedRunner(const std::string& modelPath,
                                      const RunStreamOptions& options,
                                      RunStreamReceipt& receipt);

} // namespace runstream
} // namespace rawrxd
