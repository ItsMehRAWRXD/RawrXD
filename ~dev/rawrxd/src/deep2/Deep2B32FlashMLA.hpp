#pragma once
#include <cstdint>
#include <cstddef>

namespace Deep2 {

struct B32FlashMlaShape {
    uint32_t context = 0;
    uint32_t heads = 0;
    uint32_t kvLoraRank = 0;
    uint32_t qkNopeDim = 0;
    uint32_t qkRopeDim = 0;
    uint32_t vDim = 0;
    uint32_t scalarBytes = 2;
};

struct B32FlashMlaPlan {
    uint32_t tokenTile = 128;
    uint32_t headsPerGroup = 2;
    uint32_t rankTile = 128;
    bool onlineSoftmax = true;
    bool noScoreMatrix = true;
    bool compressedKvResident = true;
    bool fusedScoreValue = true;
    bool blockwiseRescale = true;
};

class B32FlashMLA {
public:
    static B32FlashMlaPlan make(const B32FlashMlaShape&) noexcept;
    static uint64_t avoidedScoreBytes(const B32FlashMlaShape&) noexcept;
    static uint64_t compressedKvReadBytes(const B32FlashMlaShape&) noexcept;
};

} // namespace Deep2
