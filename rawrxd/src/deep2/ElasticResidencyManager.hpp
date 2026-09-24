#pragma once
// ============================================================================
// ElasticResidencyManager — Layer 0.1 real implementation
// Stateful residency planner with per-tensor tracking, tier management,
// budget enforcement, and prefetch hit/miss accounting.
//
// Design principle: This class decides WHAT should be resident, not HOW
// bytes move. Transfer is delegated to Vulkan/RAM/NVMe providers.
// ============================================================================
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>

namespace Deep2 {

enum class ResidencyState : uint8_t {
    Unknown = 0,
    Requested,
    Prefetching,
    Resident,
    Evictable,
    Evicted
};

enum class ResidencyTier : uint8_t {
    Unknown = 0,
    NVMe,
    RAM,
    VRAM
};

struct ElasticResidencyStats {
    uint64_t predictions = 0;
    uint64_t tensorRequests = 0;
    uint64_t alreadyResidentHits = 0;
    uint64_t prefetchHits = 0;
    uint64_t misses = 0;
    uint64_t promotions = 0;
    uint64_t demotions = 0;
    uint64_t evictions = 0;
    uint64_t bytesRequested = 0;
    uint64_t bytesPromoted = 0;
    uint64_t bytesEvicted = 0;
    uint64_t vramResidentBytes = 0;
    uint64_t ramResidentBytes = 0;
    uint64_t nvmeResidentBytes = 0;
};

struct ResidencyRequest {
    uint32_t layer = 0;
    std::string tensorName;
    ResidencyTier desiredTier = ResidencyTier::Unknown;
    uint64_t bytes = 0;
    uint64_t deadlineEpoch = 0;
    int priority = 0;
};

class ElasticResidencyManager {
public:
    ElasticResidencyManager();
    ~ElasticResidencyManager();

    ElasticResidencyManager(const ElasticResidencyManager&) = delete;
    ElasticResidencyManager& operator=(const ElasticResidencyManager&) = delete;

    // Lifecycle
    void reset();

    // Layer tensor forecast — called before a layer is needed.
    // 'names' are the actual tensor names expected at this layer (from LayerWeights).
    void PredictLayerNeeds(uint32_t layer,
                           const std::vector<std::string>* names,
                           size_t count);

    // Hit rate computed from real prefetch events.
    double PrefetchHitRatePct() const noexcept;

    // Tier transition bookkeeping — called by transfer providers.
    void markResident(const std::string& tensorName, ResidencyTier tier, uint64_t bytes);
    void markEvicted(const std::string& tensorName);
    void markPrefetched(const std::string& tensorName);
    void markMiss(const std::string& tensorName, uint64_t bytes);

    // Budget enforcement
    void setBudget(ResidencyTier tier, uint64_t maxBytes);
    bool enforceBudget(ResidencyTier tier);

    // Current snapshot
    ResidencyState stateOf(const std::string& tensorName) const;
    ResidencyTier  tierOf(const std::string& tensorName) const;

    const ElasticResidencyStats& stats() const noexcept { return stats_; }

    // Pre-register tensor byte size without affecting state (budget planning).
    void registerTensor(const std::string& name, uint64_t bytes);

    // Build residency plan for a layer (produces requests, does NOT execute).
    std::vector<ResidencyRequest> buildPlanForLayer(uint32_t layer) const;

private:
    struct TensorRecord {
        ResidencyState state = ResidencyState::Unknown;
        ResidencyTier  tier  = ResidencyTier::Unknown;
        uint64_t bytes = 0;
        uint64_t lastAccessEpoch = 0;
        uint64_t lastRequestEpoch = 0;
        int priority = 0;
    };

    struct ResidencyTierHash {
        size_t operator()(ResidencyTier t) const noexcept {
            return std::hash<uint8_t>{}(static_cast<uint8_t>(t));
        }
    };

    mutable std::mutex mtx_;
    std::unordered_map<std::string, TensorRecord> tensors_;
    std::unordered_map<uint32_t, std::vector<std::string>> layerTensorNames_;
    ElasticResidencyStats stats_;

    std::unordered_map<ResidencyTier, uint64_t, ResidencyTierHash> budget_;
    uint64_t currentEpoch_ = 1;

    void bumpEpoch();
    uint64_t tierBytes(ResidencyTier tier) const;
};

} // namespace Deep2
