#include "Deep2B37RegisterTune.hpp"

namespace Deep2 {

B37RegisterPlan B37RegisterTune::make(const B37RegisterShape& s) noexcept {
    B37RegisterPlan p{};
    p.vectorRegs = s.cols >= 8192 ? 8u : 4u;
    p.accumulatorRegs = s.cols >= 8192 ? 8u : 4u;
    p.weightRegs = s.bitsPerWeight <= 4 ? 16u : (s.bitsPerWeight <= 6 ? 12u : 8u);
    p.tileCols = s.waveWidth * 4u;
    p.regsPerLane = p.vectorRegs + p.accumulatorRegs + p.weightRegs;
    if (p.regsPerLane > s.targetRegsPerLane) {
        p.spillToLds = p.regsPerLane - s.targetRegsPerLane;
        p.noSpill = false;
        p.regsPerLane = s.targetRegsPerLane;
    }
    return p;
}

uint32_t B37RegisterTune::totalRegsUsed(const B37RegisterPlan& p) noexcept {
    return p.vectorRegs + p.accumulatorRegs + p.weightRegs;
}

} // namespace Deep2
