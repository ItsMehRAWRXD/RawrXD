#pragma once
#include <cstdint>

namespace Deep2 {

struct B37RegisterShape {
    uint32_t cols = 0;
    uint32_t waveWidth = 64;
    uint32_t bitsPerWeight = 4;
    uint32_t targetRegsPerLane = 64;
    uint32_t ldsBytesAvailable = 65536;
};

struct B37RegisterPlan {
    uint32_t regsPerLane = 64;
    uint32_t vectorRegs = 4;
    uint32_t accumulatorRegs = 8;
    uint32_t weightRegs = 16;
    uint32_t spillToLds = 0;
    uint32_t tileCols = 256;
    bool registerTiled = true;
    bool noSpill = true;
    bool fusedAccumulate = true;
};

class B37RegisterTune {
public:
    static B37RegisterPlan make(const B37RegisterShape&) noexcept;
    static uint32_t totalRegsUsed(const B37RegisterPlan&) noexcept;
};

} // namespace Deep2