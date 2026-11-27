// ReapPlacementRequest.hpp — RAWRXD immutable placement identity (PR-06 consumer)
// Request-scoped, immutable transformation identity for MoEPlaceGlobal /
// K2MoEPlaceAndExec. Carries checkpoint + selection fingerprint + mode; derives
// the cache identity via PR-06. No mutable global selection state. No RNG.
#pragma once
#include "reap/ReapSelectionIdentity.hpp"
#include <cstdint>

namespace RawrXD::Reap {

struct PlacementRequest {
    uint64_t checkpointId = 0;
    uint64_t selectionFingerprint = 0;
    uint32_t mode = 0;          // 0=Physical,1=Virtual,2=Streaming
    bool     selectionValid = false;

    // Immutable identity for cache lookup / placement (PR-06).
    uint64_t Identity() const {
        return CacheIdentity(checkpointId, selectionFingerprint, selectionValid);
    }
    bool SameAs(const PlacementRequest& o) const {
        return Identity() == o.Identity();
    }
};

} // namespace RawrXD::Reap