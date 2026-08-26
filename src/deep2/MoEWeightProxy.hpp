// ============================================================================
// MoEWeightProxy.hpp - Single entry point for MoE weight acquisition.
// Thin wrapper over MoEWeightsLoader. Deep2Engine talks to this.
// ============================================================================

#ifndef DEEP2_MOE_WEIGHT_PROXY_HPP
#define DEEP2_MOE_WEIGHT_PROXY_HPP

#include <string>
#include <vector>
#include <mutex>
#include <atomic>
#include <cstdint>
#include <unordered_map>

// Forward declarations for Vulkan async transfer
namespace CPUInference { class VulkanCompute; }

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
    int quantType = 0;   // GGMLType enum value (default resolved by proxy)
    bool valid = false;
};

// ============================================================================
// Async prefetch job state — tracks a Vulkan transfer from SUBMITTED to HOT
// ============================================================================
struct PrefetchJob {
    int layer = -1;
    int expertId = -1;
    uint64_t submitTimeUs = 0;      // When the async transfer was submitted
    uint64_t readyTimeUs = 0;       // When the fence signaled (0 if pending)
    bool completed = false;         // True once fence has signaled
    bool consumed = false;          // True once compute has checked and used it

    // Vulkan resources for the async transfer (opaque void* to avoid header dependency)
    void* stagingBuffer = nullptr;    // Host-visible staging buffer (VkBuffer)
    void* stagingMemory = nullptr;  // Host-visible memory (VkDeviceMemory)
    void* deviceBuffer = nullptr;     // Device-local buffer (VkBuffer)
    void* deviceMemory = nullptr;   // Device-local memory (VkDeviceMemory)
    void* fence = nullptr;          // Completion fence (VkFence)
    size_t bytesTransferred = 0;      // Size of the transfer
};

// ============================================================================
// Statistics
// ============================================================================
struct MoEProxyStats {
    std::atomic<uint64_t> totalRequests{0};
    std::atomic<uint64_t> cacheHits{0};
    std::atomic<uint64_t> bytesStreamed{0};
    std::atomic<uint64_t> asyncPrefetchSubmitted{0};
    std::atomic<uint64_t> asyncPrefetchCompleted{0};
    std::atomic<uint64_t> asyncPrefetchReadyAtCompute{0};
    std::atomic<uint64_t> asyncPrefetchLate{0};
    std::atomic<uint64_t> fenceWaitUs{0};
    std::atomic<uint64_t> synchronousFallbacks{0};
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

    // Prefetch a set of experts into the cache without returning handles.
    // Used by the router-driven prefetch pipeline to warm experts before
    // they are actually needed for compute.
    void Prefetch(int layer, const std::vector<int>& expertIds);

    // ------------------------------------------------------------------------
    // Async Vulkan transfer path (fence-based scheduling)
    // ------------------------------------------------------------------------
    // Submit async prefetch jobs for experts. Returns job handles.
    // Does NOT block — caller must check fence status later.
    std::vector<uint64_t> PrefetchAsync(int layer, const std::vector<int>& expertIds,
                                        CPUInference::VulkanCompute* vulkan);

    // Check if a specific prefetch job has completed (fence signaled).
    // Non-blocking. Returns true if the expert is HOT and ready for compute.
    bool CheckPrefetchReady(uint64_t jobHandle, CPUInference::VulkanCompute* vulkan);

    // Wait for a prefetch job to complete (blocking, for fallback path).
    // Records fenceWaitUs in stats. Returns true if expert became HOT.
    bool WaitPrefetch(uint64_t jobHandle, CPUInference::VulkanCompute* vulkan);

    // Get the PrefetchJob info for a handle (for telemetry).
    const PrefetchJob* GetPrefetchJob(uint64_t jobHandle) const;

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

    // Async prefetch job tracking
    mutable std::mutex prefetchMutex_;
    std::unordered_map<uint64_t, PrefetchJob> prefetchJobs_;
    uint64_t nextJobHandle_ = 1;

    MoEWeightHandle AcquireInternal(int layer, int expert);
};

} // namespace Deep2

#endif // DEEP2_MOE_WEIGHT_PROXY_HPP
