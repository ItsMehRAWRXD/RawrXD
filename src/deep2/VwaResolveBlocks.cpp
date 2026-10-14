// ============================================================================
// VwaResolveBlocks.cpp
// ============================================================================
// The pure physical-range resolver declared by VwaRangeAbi.hpp
// ("Pure resolver. No I/O. No residency. No tensor lookup.").
//
// This symbol was declared in the ABI header and called from
// ElasticResidencyManager::ExecuteNvmeToRam, but had no definition anywhere in
// the tree, so every target that compiled ElasticResidencyManager.cpp failed at
// link time with LNK2019 on VwaResolveBlocks. This is that implementation.
//
// Contract (from VwaRangeAbi.hpp):
//   * No I/O and no tensor lookup — it computes a byte span from geometry that
//     was already audited by VwaPopulateMountedPhysicalFromRmvFacts.
//   * The resolved range must satisfy, for the caller's own verification in
//     ExecuteNvmeToRam:
//         absoluteFileOffset == mounted dataAbsOffset + firstBlock * blockBytes
//         byteCount          == blockCount  * blockBytes
//   * Geometry is validated strictly: a request that does not tile the mounted
//     tensor exactly is rejected rather than silently clamped, because a
//     clamped range would read bytes belonging to a different tensor.
//
// No STL, no CRT dependency, fixed ABI for x64 MASM interop.
// ============================================================================

#include "VwaRangeAbi.hpp"

extern "C" unsigned long VwaResolveBlocks(
    const VwaMountedPhysical* mounted,
    const VwaBlockRange* requested,
    VwaPhysicalRange* resolved)
{
    if (!mounted || !requested || !resolved) {
        return VWA_E_NULL;
    }

    const unsigned __int64 dataAbsOffset = mounted->dataAbsOffset;
    const unsigned __int64 tensorByteSize = mounted->tensorByteSize;
    const unsigned __int64 blockBytes = mounted->blockBytes;

    if (blockBytes == 0 || tensorByteSize == 0) {
        return VWA_E_BAD_GEOMETRY;
    }

    const unsigned __int64 firstBlock = requested->firstBlock;
    const unsigned __int64 blockCount = requested->blockCount;

    if (blockCount == 0) {
        return VWA_E_EMPTY_REQUEST;
    }

    // The mounted tensor must be an exact whole number of blocks. A partial
    // trailing block means the mount does not describe this tensor's geometry
    // and resolving it would hand back a range that spans two tensors.
    if ((tensorByteSize % blockBytes) != 0) {
        return VWA_E_BAD_GEOMETRY;
    }

    const unsigned __int64 totalBlocks = tensorByteSize / blockBytes;

    // Range check without overflow: refuse if firstBlock or the end exceeds the
    // mounted block count. Sum is checked before it can wrap.
    if (firstBlock > totalBlocks) {
        return VWA_E_OUT_OF_RANGE;
    }
    if (blockCount > totalBlocks - firstBlock) {
        return VWA_E_OUT_OF_RANGE;
    }

    // byte arithmetic, overflow-checked.
    const unsigned __int64 relOffset = firstBlock * blockBytes;
    const unsigned __int64 absOffset = dataAbsOffset + relOffset;
    if (absOffset < dataAbsOffset) {  // wrapped
        return VWA_E_INTEGER_OVERFLOW;
    }

    const unsigned __int64 byteCount = blockCount * blockBytes;
    if (byteCount / blockCount != blockCount) {  // caught by mul overflow
        return VWA_E_INTEGER_OVERFLOW;
    }
    if (byteCount > tensorByteSize - relOffset) {
        return VWA_E_OUT_OF_RANGE;
    }

    resolved->absoluteFileOffset = absOffset;
    resolved->byteCount = byteCount;
    resolved->tensorRelOffset = relOffset;
    resolved->firstBlock = firstBlock;
    resolved->blockCount = blockCount;
    resolved->mountGeneration = mounted->mountGeneration;
    resolved->shardId = mounted->shardId;
    resolved->flags = mounted->flags;

    return VWA_OK;
}
