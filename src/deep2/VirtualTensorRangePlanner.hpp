#pragma once
#include "VwaRangeAbi.hpp"
#include "VirtualTensorRange.hpp"
#include <algorithm>
#include <cstdint>
#include <vector>

namespace Deep2 {

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
    if (a.mountGeneration != b.mountGeneration)
        return a.mountGeneration < b.mountGeneration;
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

// Pure PhysicalTensorRange coalesce (abutting only when maxGapBytes==0).
inline std::vector<PhysicalTensorRange>
CoalescePhysicalRanges(const PhysicalTensorRange* ranges, size_t n,
                       uint64_t maxGapBytes, uint64_t maxMergedBytes) {
    std::vector<PhysicalTensorRange> out;
    if (!ranges || n == 0) return out;
    out.assign(ranges, ranges + n);
    std::sort(out.begin(), out.end(),
              [](const PhysicalTensorRange& a, const PhysicalTensorRange& b) {
                  if (a.shardId != b.shardId) return a.shardId < b.shardId;
                  if (a.tensorId != b.tensorId) return a.tensorId < b.tensorId;
                  if (a.mountGeneration != b.mountGeneration)
                      return a.mountGeneration < b.mountGeneration;
                  return a.absoluteFileOffset < b.absoluteFileOffset;
              });
    std::vector<PhysicalTensorRange> m;
    m.reserve(out.size());
    m.push_back(out[0]);
    for (size_t i = 1; i < out.size(); ++i) {
        auto& L = m.back();
        const auto& C = out[i];
        if (L.tensorId != C.tensorId || L.shardId != C.shardId ||
            L.mountGeneration != C.mountGeneration) {
            m.push_back(C);
            continue;
        }
        uint64_t Lend = 0;
        if (!CheckedAddU64(L.absoluteFileOffset, L.byteCount, Lend)) {
            m.push_back(C);
            continue;
        }
        if (C.absoluteFileOffset < Lend) {
            m.push_back(C);
            continue;
        }
        const uint64_t gap = C.absoluteFileOffset - Lend;
        if (gap > maxGapBytes || gap != 0) {
            m.push_back(C);
            continue;
        }
        uint64_t newLen = 0;
        if (!CheckedAddU64(L.byteCount, C.byteCount, newLen) ||
            newLen > maxMergedBytes) {
            m.push_back(C);
            continue;
        }
        L.byteCount = newLen;
        L.blockCount += C.blockCount;
    }
    return m;
}

} // namespace Deep2
