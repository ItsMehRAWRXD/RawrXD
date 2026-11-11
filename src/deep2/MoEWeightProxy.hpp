// ============================================================================
// MoEWeightProxy.hpp - Single entry point for MoE weight acquisition.
// Thin wrapper over MoEWeightsLoader. Deep2Engine talks to this.
// ============================================================================

#ifndef DEEP2_MOE_WEIGHT_PROXY_HPP
#define DEEP2_MOE_WEIGHT_PROXY_HPP

#include <string>
#include <mutex>
#include <atomic>
#include <cstdint>

namespace Deep2 {

class MoEWeightsLoader;

// ============================================================================
// Per-expert weight handle - exposes the three Q4_K projections
// so the MASM kernel can hit each without re-streaming.
// ============================================================================
struct MoEWeightHandle {
    const void* gateWeights = nullptr;
    const void* upWeights = nullptr;
    const void* downWeights = nullptr;
    size_t expertBytes = 0;
    int layer = -1;
    int expertId = -1;
    bool valid = false;
};

// ============================================================================
// Statistics
// ============================================================================
struct MoEProxyStats {
    std::atomic<uint64_t> totalRequests{0};
    std::atomic<uint64_t> cacheHits{0};
    std::atomic<uint64_t> bytesStreamed{0};
    double avgLatencyMs = 0.0;
};

// ============================================================================
// MoEWeightProxy
// ============================================================================
class MoEWeightProxy {
public:
    MoEWeightProxy() = default;
    ~MoEWeightProxy() = default;

    // Wire the neutral (fixed GGUF v3 parser) loader
    void Attach(MoEWeightsLoader* loader);
    void Detach();

    // Single call to fetch a complete expert.
    // Returns an invalid handle if the loader is not attached or the expert
    // is not present in the file.
    MoEWeightHandle Acquire(int layer, int expert);

    // Configuration
    void SetMaxCacheSize(size_t bytes) const;
    size_t GetCacheSize() const;

    // Stats
    const MoEProxyStats& GetStats() const { return stats_; }
    void ResetStats();

    // Capabilities
    size_t GetNumExpertLayers() const;
    size_t GetExpertsPerLayer() const;
    const std::string& GetArchitecture() const;

    // Active status
    bool IsAttached() const;

private:
    mutable std::mutex attachMutex_;
    MoEWeightsLoader* loader_ = nullptr;  // not owned
    MoEProxyStats stats_;

    MoEWeightHandle AcquireInternal(int layer, int expert);
};

} // namespace Deep2

#endif // DEEP2_MOE_WEIGHT_PROXY_HPP
