#pragma once
#include "VwaRangeAbi.hpp"

namespace Deep2 {

enum VwaExpertProjection : unsigned long {
    VWA_EXPERT_GATE = 0,
    VWA_EXPERT_UP   = 1,
    VWA_EXPERT_DOWN = 2
};

struct VwaExpertDemand {
    unsigned long layer = 0;
    unsigned long expertId = 0;
    VwaExpertProjection projection = VWA_EXPERT_GATE;
};

struct VwaExpertSlice {
    unsigned __int64 expertRelativeOffset = 0; // relative to stacked tensor
    unsigned __int64 expertByteCount = 0;
    unsigned long blockBytes = 0;
};

inline unsigned long VwaExpertSliceToBlockRange(
    const VwaExpertSlice& slice,
    VwaBlockRange& out) noexcept {
    out = {};
    if (slice.blockBytes == 0 || slice.expertByteCount == 0)
        return VWA_E_BAD_GEOMETRY;

    const unsigned __int64 bb = slice.blockBytes;
    if ((slice.expertRelativeOffset % bb) != 0 ||
        (slice.expertByteCount % bb) != 0) {
        return VWA_E_OUT_OF_RANGE;
    }

    out.firstBlock = slice.expertRelativeOffset / bb;
    out.blockCount = slice.expertByteCount / bb;
    if (out.blockCount == 0) return VWA_E_EMPTY_REQUEST;
    return VWA_OK;
}

} // namespace Deep2
