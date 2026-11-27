// ReapMaterialize.hpp — RAWRXD S03.6F/G (transformed-expert materialization)
// Produces a transformed expert buffer bound to the PR-06 identity, using the
// request-scoped TransformContext + provider. The engine allocates/uploads the
// returned bytes to a Vulkan buffer. Storage-independent; no RNG; fail-closed.
#pragma once
#include "reap/ReapTransformContext.hpp"
#include <cstdint>
#include <vector>

namespace RawrXD::Reap {

struct MaterializedExpert {
    bool ok = false;
    uint64_t identity = 0;
    std::vector<uint8_t> bytes;   // transformed expert payload (engine uploads this)
};

// Materialize one transformed expert (post-admission). Fail-closed on invalid.
inline MaterializedExpert Materialize(ExpertProvider& prov, const PlacementRequest& req,
                                      uint32_t layer, uint32_t expert, uint32_t expertBytes) {
    MaterializedExpert m;
    m.identity = CacheIdentity(((uint64_t)layer << 32) | expert,
                               req.selectionFingerprint, req.selectionValid);
    if (!req.selectionValid) return m;                 // invalid selection: no materialization
    m.bytes.resize(expertBytes);
    if (!prov.Acquire(layer, expert, m.bytes.data(), m.bytes.size())) { m.bytes.clear(); return m; }
    m.ok = true;
    return m;
}

} // namespace RawrXD::Reap