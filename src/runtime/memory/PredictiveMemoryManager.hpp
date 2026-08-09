// ============================================================================
// PredictiveMemoryManager.hpp
// Top-level orchestrator.  Owns all sub-components and exposes the
// execution-path API consumed by TensorExecutionRouter.
// ============================================================================
#pragma once

#include "PlacementPolicy.hpp"
#include "ResidencyTracker.hpp"
#include "WorkingSetPredictor.hpp"
#include "CapacityManager.hpp"
#include "TransferScheduler.hpp"
#include "TensorPlacementManager.hpp"
#include <memory>
#include <vector>
#include <string>
#include <ostream>

namespace RawrXD {
namespace Memory {

// Telemetry snapshot – populate from the dashboard subsystem.
struct MemoryTelemetry {
    struct PoolInfo {
        DeviceId  device;
        MemoryTier tier;
        uint64_t  usedBytes;
        uint64_t  capacityBytes;
        double    utilization;   // 0..1
    };

    std::vector<PoolInfo> pools;

    double   prefetchHitRate;    // 0..1
    double   prefetchWasteRate;  // 0..1
    double   pcieUtilization;    // 0..1
    double   evictionsPerSec;
    double   blockingTransfersPerSec;
    double   avgTransferLatencyMs;

    uint32_t lookaheadDepth;
    uint32_t activeTensors;
    uint32_t residentTensors;
};

struct PredictiveMemoryConfig {
    // Per-GPU VRAM pools.  Index = DeviceId (0-based).
    std::vector<DeviceMemoryPool> vramPools;

    // System RAM pool.
    uint64_t systemRAMBytes = 0;

    // Capacity policy knobs.
    CapacityPolicy capacityPolicy;

    // Lookahead depth (layers) for prefetch.
    uint32_t lookaheadDepth = 3;

    // Max concurrent DMA transfers.
    uint32_t maxConcurrentTransfers = 1;
};

class PredictiveMemoryManager {
public:
    explicit PredictiveMemoryManager(PredictiveMemoryConfig cfg = {});
    ~PredictiveMemoryManager() = default;

    // Non-copyable, non-movable (owns live threads).
    PredictiveMemoryManager(const PredictiveMemoryManager&)            = delete;
    PredictiveMemoryManager& operator=(const PredictiveMemoryManager&) = delete;

    // ── Execution-path API ───────────────────────────────────────────────────

    // Advance predictor and speculatively prefetch tensors for the next layers.
    // Call BEFORE executing a layer.
    void predict(uint32_t currentLayer);

    // Post speculative prefetch requests for the lookahead window.
    void prefetch(uint32_t currentLayer);

    // Return tensor IDs predicted for layers [currentLayer, currentLayer+depth).
    std::vector<TensorId> lookahead(uint32_t currentLayer, uint32_t depth = 3) const;

    // Ensure tensor is VRAM-resident on the given device.
    // Blocks if a blocking transfer is required.  Returns host/device VA.
    uint64_t ensureResident(TensorId id, DeviceId device);

    // Record that a tensor access completed (feeds predictor).
    void recordCompletion(TensorId id, uint32_t layer, uint64_t transferTimeNs = 0);

    // ── Registration ─────────────────────────────────────────────────────────

    // Register a new tensor.  Safe to call multiple times.
    void registerTensor(TensorId id, uint64_t bytes);

    // Install a custom DMA executor (optional; uses simulation if not set).
    void setTransferExecutor(TransferScheduler::TransferExecutor exec);

    // ── Telemetry ────────────────────────────────────────────────────────────

    MemoryTelemetry telemetry() const;
    void            printDashboard(std::ostream& out) const;

    // ── Sub-component access (for testing / advanced integration) ────────────

    ResidencyTracker&    residencyTracker()   noexcept { return m_tracker;   }
    WorkingSetPredictor& workingSetPredictor()noexcept { return m_predictor; }
    CapacityManager&     capacityManager()    noexcept { return m_capacity;  }
    TransferScheduler&   transferScheduler()  noexcept { return m_scheduler; }
    TensorPlacementManager& placementManager()noexcept { return m_placement; }

private:
    PredictiveMemoryConfig  m_cfg;

    ResidencyTracker        m_tracker;
    WorkingSetPredictor     m_predictor;
    CapacityManager         m_capacity;
    TransferScheduler       m_scheduler;
    TensorPlacementManager  m_placement;

    // Running stats for telemetry.
    mutable struct Stats {
        uint64_t prefetchHits   = 0;
        uint64_t prefetchMisses = 0;
        uint64_t prefetchWaste  = 0;  // speculative transfers that were never used
    } m_stats;
};

} // namespace Memory
} // namespace RawrXD
