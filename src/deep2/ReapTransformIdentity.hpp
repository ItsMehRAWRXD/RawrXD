#pragma once
// RAWRXD REAP V06.2: deterministic transformation identity.
//
// Binds a transformed-weight cache entry to: source checkpoint identity, logical
// tensor identity, the authoritative selection fingerprint (layer + retained expert
// ORDER), transformation mode, and quantization geometry. Different selections /
// expert ordering / mode / quant layout / source => distinct identity, so stale
// transformed weights are never reused. Storage-independent; no RNG.
#include "deep2/ReapExpertSelection.hpp"

#include <cstdint>
#include <string>

namespace RawrXD {
namespace Reap {

// FNV-1a style deterministic hash over the selection (order-sensitive).
inline uint64_t SelectionFingerprint(const Selection& selection) {
    uint64_t h = 1469598103934665603ULL;
    auto mix = [&h](uint64_t v) { h ^= v; h *= 1099511628211ULL; };
    mix(selection.size());
    for (const auto& entry : selection) {
        mix(static_cast<uint64_t>(entry.first));
        mix(entry.second.size());
        for (const uint32_t expert : entry.second) mix(expert);  // order-sensitive
    }
    return h;
}

struct TransformIdentity {
    uint64_t sourceId = 0;       // source checkpoint identity (e.g. first-shard digest)
    uint64_t tensorId = 0;       // logical tensor identity (host-pointer-independent)
    uint64_t selectionFp = 0;    // SelectionFingerprint(selection)
    uint64_t mode = 0;           // TransformMode (Physical/Virtual/Streaming)
    uint64_t quantLayout = 0;    // quantization geometry (block elems/bytes/type)
};

inline uint64_t TransformIdentityHash(const TransformIdentity& id) {
    uint64_t h = 1469598103934665603ULL;
    auto mix = [&h](uint64_t v) { h ^= v; h *= 1099511628211ULL; };
    mix(id.sourceId);
    mix(id.tensorId);
    mix(id.selectionFp);
    mix(id.mode);
    mix(id.quantLayout);
    return h;
}

}  // namespace Reap
}  // namespace RawrXD