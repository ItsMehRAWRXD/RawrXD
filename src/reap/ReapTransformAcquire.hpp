// ReapTransformAcquire.hpp — RAWRXD S03.6 (inference-binding primitive)
// AcquireTransformed binds a transformed-expert acquisition to the immutable
// transformation identity (PR-06). The caller (inference dispatch) uses the
// returned identity to key the residency cache; the acquired bytes are the
// transformed expert. Storage-independent; no RNG.
#pragma once
#include "reap/ReapExpertProvider.hpp"
#include "reap/ReapSelectionIdentity.hpp"
#include <cstdint>

namespace RawrXD::Reap {

struct AcquireResult {
    bool ok = false;
    uint64_t identity = 0;   // PR-06 cache identity for the acquired expert
};

// Acquire one transformed expert and bind it to the transformation identity.
inline AcquireResult AcquireTransformed(ExpertProvider& provider, uint32_t layer, uint32_t expert,
                                        uint8_t* dst, size_t dstBytes,
                                        uint64_t checkpointId, uint64_t selectionFingerprint,
                                    bool selectionValid, uint32_t mode) {
    AcquireResult r;
    const uint64_t id = CacheIdentity(((uint64_t)layer << 32) | expert, selectionFingerprint, selectionValid);
    r.identity = id;
    if (!selectionValid) { r.ok = false; return r; }   // invalid selection fails closed (no execution)
    r.ok = provider.Acquire(layer, expert, dst, dstBytes);
    return r;
}

} // namespace RawrXD::Reap