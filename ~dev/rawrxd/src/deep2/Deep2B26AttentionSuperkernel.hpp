#pragma once
#include <cstdint>
#include <cstddef>

namespace Deep2 {

struct B26AttentionShape {
    uint32_t hidden = 0;
    uint32_t heads = 0;
    uint32_t kvHeads = 0;
    uint32_t headDim = 0;
    uint32_t qLoraRank = 0;
    uint32_t kvLoraRank = 0;
    uint32_t qkRopeDim = 0;
    bool useMLA = false;
};

struct B26AttentionPlan {
    uint32_t workgroup = 256;
    uint32_t vectorWidth = 4;
    uint32_t headsPerGroup = 1;
    uint32_t qkvTile = 256;
    bool fuseRmsNorm = true;
    bool fuseQkv = true;
    bool fuseRope = true;
    bool keepQkvOnDevice = true;
    bool mlaCompressedPath = false;
    bool singleSubmitRegion = true;
};

class B26AttentionSuperkernel {
public:
    static B26AttentionPlan make(const B26AttentionShape&) noexcept;
    static uint64_t eliminatedIntermediateBytes(const B26AttentionShape&,
                                                uint32_t scalarBytes = 2) noexcept;
};

} // namespace Deep2
