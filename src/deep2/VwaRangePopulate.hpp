#pragma once
#include "VwaRangeAbi.hpp"
#include "VirtualTensorDesc.hpp"

// Population helpers only. These functions do not invent RMV facts.

namespace Deep2 {

inline unsigned long VwaPopulateMountedPhysicalFromRmvFacts(
    unsigned __int64 dataAbsOffset,
    unsigned __int64 tensorByteSize,
    unsigned long blockBytes,
    unsigned long shardId,
    unsigned __int64 mountGeneration,
    bool fileBacked,
    VwaMountedPhysical& out) noexcept {
    out = {};
    if (!fileBacked) return VWA_E_NOT_FILE_BACKED;
    if (tensorByteSize == 0 || blockBytes == 0) return VWA_E_BAD_GEOMETRY;

    out.dataAbsOffset = dataAbsOffset;
    out.tensorByteSize = tensorByteSize;
    out.blockBytes = blockBytes;
    out.flags = VWA_PHYS_FILE_BACKED;
    out.shardId = shardId;
    out.mountGeneration = mountGeneration;
    return VWA_OK;
}

// Convenience: audited VirtualTensorDesc → VwaMountedPhysical (still no layout mirror).
inline bool PopulateVwaMounted(const VirtualTensorDesc& d,
                               uint32_t blockBytes,
                               uint64_t mountGeneration,
                               VwaMountedPhysical& out) {
    return VwaPopulateMountedPhysicalFromRmvFacts(
               d.fileOffset, d.byteLength, blockBytes, d.shard,
               mountGeneration, d.addressed, out) == VWA_OK;
}

inline bool VwaPhysicalSameIdentity(
    const VwaPhysicalRange& a,
    const VwaPhysicalRange& b) noexcept {
    return a.absoluteFileOffset == b.absoluteFileOffset &&
           a.byteCount == b.byteCount &&
           a.tensorRelOffset == b.tensorRelOffset &&
           a.firstBlock == b.firstBlock &&
           a.blockCount == b.blockCount &&
           a.mountGeneration == b.mountGeneration &&
           a.shardId == b.shardId &&
           a.flags == b.flags;
}

} // namespace Deep2
