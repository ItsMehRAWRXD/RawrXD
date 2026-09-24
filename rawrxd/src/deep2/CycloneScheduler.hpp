#pragma once
// ============================================================================
// CycloneScheduler.hpp — Layer 0.2 real implementation
// Temporal scheduling provider for Deep2 GPU-forward.
// Schedules WHEN resources should be prepared, not WHAT or HOW.
// ============================================================================
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <chrono>

namespace Deep2 {

enum class CycloneLayerState : uint8_t {
    Idle = 0,
    Running,
    Complete,
    Aborted
};

struct CycloneLayerStats {
    uint64_t starts = 0;
    uint64_t completes = 0;
    uint64_t aborts = 0;

    uint64_t totalNs = 0;
    uint64_t minNs = UINT64_MAX;
    uint64_t maxNs = 0;

    double emaNs = 0.0;
    double emaAlpha = 0.3; // EMA smoothing factor

    uint64_t lastSeq = 0;
    uint64_t lastEpoch = 0;
};

struct CycloneStats {
    uint64_t layerStarts = 0;
    uint64_t layerEnds = 0;
    uint64_t layerAborts = 0;

    uint64_t schedulingDecisions = 0;
    uint64_t predictedPrefetches = 0;
    uint64_t deadlineMisses = 0;

    uint64_t invalidTransitions = 0;
};

struct CyclonePrefetchDecision {
    uint32_t layer = 0;
    uint64_t leadDistance = 0;    // how many layers ahead to prefetch
    uint64_t deadlineEpoch = 0;   // when it must be ready
    int priority = 0;             // urgency
    bool shouldPrefetch = false;
};

class CycloneScheduler {
public:
    CycloneScheduler();
    ~CycloneScheduler();

    CycloneScheduler(const CycloneScheduler&) = delete;
    CycloneScheduler& operator=(const CycloneScheduler&) = delete;

    // Lifecycle
    void reset();
    void onModelSwitch(uint32_t numLayers, uint64_t epoch);

    // Layer lifecycle — called from GPU-forward path
    void onLayerStart(uint32_t layer, uint64_t seq);
    void onLayerEnd(uint32_t layer, uint64_t seq, uint64_t durationNs);
    void onLayerAbort(uint32_t layer, uint64_t seq);

    // Scheduling decision — called before layer execution to plan prefetch
    CyclonePrefetchDecision decidePrefetch(uint32_t nextLayer, uint64_t seq) const;

    // Queries
    CycloneLayerState layerState(uint32_t layer) const;
    const CycloneStats& stats() const noexcept { return stats_; }
    uint32_t activeLayer() const noexcept { return activeLayer_; }
    bool hasActiveLayer() const noexcept { return activeLayer_ != UINT32_MAX; }
    uint64_t currentEpoch() const noexcept { return epoch_; }

    // Timing exposure
    double layerEmaNs(uint32_t layer) const;
    uint64_t layerMinNs(uint32_t layer) const;
    uint64_t layerMaxNs(uint32_t layer) const;

private:
    mutable std::mutex mtx_;
    std::unordered_map<uint32_t, CycloneLayerStats> perLayer_;
    CycloneStats stats_;
    uint32_t activeLayer_ = UINT32_MAX;
    uint64_t activeStartNs_ = 0;
    uint64_t seq_ = 0;
    uint64_t epoch_ = 1;
    uint32_t numLayers_ = 0;
    bool enabled_ = false;

    uint64_t nowNs() const noexcept;
    bool validateTransition(uint32_t layer, bool isStart);
    void updateEma(CycloneLayerStats& s, uint64_t durationNs);
};

} // namespace Deep2

