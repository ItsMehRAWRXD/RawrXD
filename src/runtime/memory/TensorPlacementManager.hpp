// ============================================================================
// TensorPlacementManager.hpp
// Placement planning: decides where each tensor should live and triggers
// evictions when a tier is over budget.
// ============================================================================
#pragma once

#include "PlacementPolicy.hpp"
#include "ResidencyTracker.hpp"
#include "CapacityManager.hpp"
#include "WorkingSetPredictor.hpp"
#include "TransferScheduler.hpp"
#include <vector>
#include <memory>

namespace RawrXD {
namespace Memory {

// Describes a placement decision returned to the caller.
struct PlacementDecision {
    TensorId  id;
    MemoryTier targetTier;
    DeviceId   targetDevice;
    bool       needsTransfer;    // false if already in the right place
    bool       speculative;      // true if this is a prefetch, not a demand
};

class TensorPlacementManager {
public:
    TensorPlacementManager(ResidencyTracker&    tracker,
                           CapacityManager&     capacity,
                           WorkingSetPredictor& predictor,
                           TransferScheduler&   scheduler);
    ~TensorPlacementManager() = default;

    // Compute a placement decision for a single tensor given a target device.
    // Does NOT execute the transfer; caller passes result to TransferScheduler.
    PlacementDecision plan(TensorId id, DeviceId targetDevice) const;

    // Ensure tensor is resident on targetDevice (blocking path).
    // Returns the address of the resident tensor or 0 on failure.
    uint64_t ensureResident(TensorId id, DeviceId targetDevice);

    // Prefetch the tensors predicted for the next 'lookahead' layers.
    // Posts speculative TransferRequests; returns immediately.
    void prefetch(uint32_t currentLayer, uint32_t lookahead = 3);

    // Select eviction candidates on a device to free 'bytesNeeded'.
    // Applies eviction score; respects pinned / in-flight constraints.
    // Returns the list in eviction order (best first).
    std::vector<TensorResidency> selectEvictions(DeviceId       device,
                                                  MemoryTier    tier,
                                                  uint64_t      bytesNeeded) const;

    // Execute evictions selected above (updates tracker + capacity).
    void evict(const std::vector<TensorResidency>& candidates);

private:
    double transferCostMs(MemoryTier src, MemoryTier dst) const noexcept;

    ResidencyTracker&    m_tracker;
    CapacityManager&     m_capacity;
    WorkingSetPredictor& m_predictor;
    TransferScheduler&   m_scheduler;
};

} // namespace Memory
} // namespace RawrXD
