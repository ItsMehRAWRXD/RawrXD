#include "Deep2B38CoopGemv.hpp"

namespace Deep2 {

B38CoopPlan B38CoopGemv::make(const B38CoopShape& s) noexcept {
    B38CoopPlan p{};
    p.wavesCooperating = s.numWaves > 0 ? s.numWaves : 2u;
    p.rowsPerWave = s.rows / p.wavesCooperating;
    if (p.rowsPerWave == 0) p.rowsPerWave = 1;
    p.sharedLdsBytes = static_cast<uint32_t>(
        (uint64_t(s.cols) * 4ull * p.wavesCooperating + 255ull) & ~255ull);
    p.barrierCount = p.wavesCooperating;
    return p;
}

uint64_t B38CoopGemv::ldsFootprint(const B38CoopShape& s) noexcept {
    const uint32_t waves = s.numWaves > 0 ? s.numWaves : 2u;
    return (uint64_t(s.cols) * 4ull * waves + 255ull) & ~255ull;
}

} // namespace Deep2
