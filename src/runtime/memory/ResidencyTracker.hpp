// ============================================================================
// ResidencyTracker.hpp
// Records and queries the actual physical location of every known tensor.
// ============================================================================
#pragma once

#include "PlacementPolicy.hpp"
#include <unordered_map>
#include <mutex>
#include <vector>
#include <functional>

namespace RawrXD {
namespace Memory {

class ResidencyTracker {
public:
    ResidencyTracker()  = default;
    ~ResidencyTracker() = default;

    // Register a tensor for tracking.  Idempotent if already registered.
    void    track(TensorId id, uint64_t bytes);

    // Update the full residency record for a tensor.
    void    update(const TensorResidency& r);

    // Transition helpers – each acquires the lock internally.
    void    markPrefetching(TensorId id, MemoryTier dest);
    void    markResident   (TensorId id, MemoryTier tier, uint64_t address);
    void    markEvicting   (TensorId id);
    void    markCold       (TensorId id);
    void    markFailed     (TensorId id);
    void    markPinned     (TensorId id, bool pin);
    void    recordUse      (TensorId id, uint64_t timestampNs);

    // Query
    bool              known     (TensorId id) const;
    TensorResidency   get       (TensorId id) const;   // returns Cold record if unknown
    MemoryTier        tierOf    (TensorId id) const;
    ResidencyState    stateOf   (TensorId id) const;
    bool              isResident(TensorId id) const;
    bool              isPinned  (TensorId id) const;

    // Enumerate all tracked tensors in a given tier.
    std::vector<TensorResidency> byTier(MemoryTier tier) const;

    // Enumerate all tracked tensors (snapshot, safe to iterate after return).
    std::vector<TensorResidency> all() const;

    // Total byte count resident in a tier.
    uint64_t bytesInTier(MemoryTier tier) const;

private:
    mutable std::mutex                           m_mtx;
    std::unordered_map<TensorId, TensorResidency> m_map;
};

} // namespace Memory
} // namespace RawrXD
