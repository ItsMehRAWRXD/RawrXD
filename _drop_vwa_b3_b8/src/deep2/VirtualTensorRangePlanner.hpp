#pragma once
#include "VwaRangeAbi.hpp"

namespace Deep2 {

// In-place stable-ish range sort + adjacent coalescer.
// No allocator. No filesystem. No I/O. No residency FSM.
// Only merges exact adjacency within the same shard/generation/flags.
struct VwaCoalesceStats {
    unsigned long inputCount = 0;
    unsigned long outputCount = 0;
    unsigned long mergedCount = 0;
    unsigned long rejectedOverlap = 0;
};

inline bool VwaCanMergeAdjacent(const VwaPhysicalRange& a,
                                const VwaPhysicalRange& b) noexcept {
    return a.shardId == b.shardId &&
           a.mountGeneration == b.mountGeneration &&
           a.flags == b.flags &&
           a.absoluteFileOffset + a.byteCount == b.absoluteFileOffset &&
           a.tensorRelOffset + a.byteCount == b.tensorRelOffset &&
           a.firstBlock + a.blockCount == b.firstBlock;
}

inline bool VwaRangeLess(const VwaPhysicalRange& a,
                         const VwaPhysicalRange& b) noexcept {
    if (a.shardId != b.shardId) return a.shardId < b.shardId;
    if (a.mountGeneration != b.mountGeneration) return a.mountGeneration < b.mountGeneration;
    return a.absoluteFileOffset < b.absoluteFileOffset;
}

inline unsigned long VwaCoalesceInPlace(VwaPhysicalRange* ranges,
                                        unsigned long count,
                                        VwaCoalesceStats* stats) noexcept {
    if (stats) *stats = {};
    if (!ranges && count) return VWA_E_NULL;
    if (stats) stats->inputCount = count;
    if (count == 0) {
        if (stats) stats->outputCount = 0;
        return VWA_OK;
    }

    // Insertion sort: small range lists, deterministic, no allocation.
    for (unsigned long i = 1; i < count; ++i) {
        VwaPhysicalRange key = ranges[i];
        unsigned long j = i;
        while (j > 0 && VwaRangeLess(key, ranges[j - 1])) {
            ranges[j] = ranges[j - 1];
            --j;
        }
        ranges[j] = key;
    }

    unsigned long out = 0;
    for (unsigned long i = 1; i < count; ++i) {
        VwaPhysicalRange& cur = ranges[out];
        const VwaPhysicalRange& next = ranges[i];

        // Overlap is not coalescing. Reject because it means duplicate or
        // drifted physical requirements entered the range planner.
        if (cur.shardId == next.shardId &&
            cur.mountGeneration == next.mountGeneration &&
            cur.absoluteFileOffset < next.absoluteFileOffset &&
            cur.absoluteFileOffset + cur.byteCount > next.absoluteFileOffset) {
            if (stats) stats->rejectedOverlap++;
            return VWA_E_OUT_OF_RANGE;
        }

        if (VwaCanMergeAdjacent(cur, next)) {
            cur.byteCount += next.byteCount;
            cur.blockCount += next.blockCount;
            if (stats) stats->mergedCount++;
        } else {
            ++out;
            ranges[out] = next;
        }
    }

    if (stats) stats->outputCount = out + 1;
    return VWA_OK;
}

} // namespace Deep2
