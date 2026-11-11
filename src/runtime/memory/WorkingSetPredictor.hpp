// ============================================================================
// WorkingSetPredictor.hpp
// Deterministic reuse-distance predictor for transformer inference.
// ============================================================================
#pragma once

#include "PlacementPolicy.hpp"
#include <unordered_map>
#include <vector>
#include <mutex>

namespace RawrXD {
namespace Memory {

// One observed access event.
struct AccessRecord {
    TensorId  id;
    uint32_t  layer;
    uint64_t  timestampNs;
    uint64_t  bytes;
    MemoryTier residency;
    uint64_t  transferTimeNs;   // 0 if already resident
    uint32_t  reuseDistance;    // layers until next predicted use; UINT32_MAX = unknown
};

// Per-tensor prediction summary.
struct TensorPrediction {
    TensorId  id;
    uint32_t  lastLayer;
    uint32_t  nextPredictedLayer;
    uint32_t  reuseDistance;    // layers
    uint32_t  score;            // 0–1000 fixed-point
    double    transferCostNorm; // 0–1 (lower = cheaper)
};

class WorkingSetPredictor {
public:
    explicit WorkingSetPredictor(uint32_t lookaheadDepth = 3);
    ~WorkingSetPredictor() = default;

    // Record a completed tensor access.
    void recordAccess(const AccessRecord& rec);

    // Called at the start of each layer to advance internal state.
    void advanceLayer(uint32_t layer);

    // Return predicted tensors needed within lookaheadDepth layers from now.
    std::vector<TensorPrediction> predict(uint32_t currentLayer) const;

    // Return the prediction for a single tensor, or a zero score if unknown.
    TensorPrediction predictionFor(TensorId id) const;

    // Current memory pressure estimate: 0..1 based on recent eviction rate.
    double memoryPressure() const;

    // Update eviction counter (called by CapacityManager or TensorPlacementManager).
    void notifyEviction();

private:
    struct TensorStats {
        uint32_t lastLayer         = 0;
        uint32_t prevLayer         = 0;
        uint32_t observedReuse     = UINT32_MAX;
        uint64_t totalTransferNs   = 0;
        uint32_t accessCount       = 0;
        uint64_t totalBytes        = 0;
    };

    uint32_t computeScore(const TensorStats& s,
                          uint32_t currentLayer,
                          double pressure) const noexcept;

    mutable std::mutex                           m_mtx;
    std::unordered_map<TensorId, TensorStats>    m_stats;
    uint32_t                                     m_currentLayer   = 0;
    uint32_t                                     m_lookaheadDepth;
    uint32_t                                     m_evictionsRecent = 0;
    uint32_t                                     m_layersSinceReset = 0;

    static constexpr uint32_t kPressureWindow = 10;   // layers
};

} // namespace Memory
} // namespace RawrXD
