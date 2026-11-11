#pragma once
#include <cstdint>

namespace Deep2 {

struct B38CoopShape {
    uint32_t rows = 0;
    uint32_t cols = 0;
    uint32_t waveWidth = 64;
    uint32_t numWaves = 2;
    uint32_t bitsPerWeight = 4;
};

struct B38CoopPlan {
    uint32_t wavesCooperating = 2;
    uint32_t rowsPerWave = 0;
    uint32_t sharedLdsBytes = 0;
    uint32_t barrierCount = 0;
    bool cooperativeGemv = true;
    bool ldsReduction = true;
    bool noHostReduce = true;
    bool waveSpecialization = true;
};

class B38CoopGemv {
public:
    static B38CoopPlan make(const B38CoopShape&) noexcept;
    static uint64_t ldsFootprint(const B38CoopShape&) noexcept;
};

} // namespace Deep2