// VwaNormalizePhysical.hpp — map landed PhysicalTensorRange → VwaLineageRange
// Observational only. No second resolver / mount / ownership.
#pragma once
#include "VirtualTensorRange.hpp"
#include "vwa/VwaRangeLineageAbi.hpp"
#include <cstring>

namespace Deep2 {

inline VwaLineageRange NormalizePhysicalToLineage(
    const PhysicalTensorRange& pr) noexcept {
    VwaLineageRange r{};
    r.tensorLo = static_cast<uint64_t>(pr.tensorId);
    r.tensorHi = 0; // TensorId is uint64_t on this tree
    r.mountGeneration = pr.mountGeneration;
    r.absoluteOffset = pr.absoluteFileOffset;
    r.byteCount = pr.byteCount;
    r.firstBlock = pr.firstBlock;
    r.blockCount = pr.blockCount;
    r.sourceId = pr.shardId;
    r.flags = 0;
    return r;
}

inline bool NormalizePhysicalSet(const PhysicalTensorRange* in, size_t n,
                                 VwaLineageRange* out) noexcept {
    if ((!in && n) || !out) return false;
    for (size_t i = 0; i < n; ++i)
        out[i] = NormalizePhysicalToLineage(in[i]);
    return true;
}

} // namespace Deep2
