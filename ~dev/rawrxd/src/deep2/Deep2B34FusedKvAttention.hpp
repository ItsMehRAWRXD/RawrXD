#pragma once
#include <cstdint>

namespace Deep2 {

struct B34KvAttnShape {
    uint32_t context = 0;
    uint32_t heads = 0;
    uint32_t kvHeads = 0;
    uint32_t headDim = 0;
    uint32_t scalarBytes = 2;
    bool useMLA = false;
    uint32_t compressedRank = 0;
};

struct B34KvAttnPlan {
    uint32_t tokenTile = 128;
    uint32_t headsPerGroup = 2;
    bool fuseKvWrite = true;
    bool fuseAttentionRead = true;
    bool kvWriteThrough = true;
    bool noHostKvTouch = true;
    bool noIntermediateScoreBuffer = true;
};

class B34FusedKvAttention {
public:
    static B34KvAttnPlan make(const B34KvAttnShape&) noexcept;
    static uint64_t avoidedKvRoundtripBytes(const B34KvAttnShape&) noexcept;
};

} // namespace Deep2
