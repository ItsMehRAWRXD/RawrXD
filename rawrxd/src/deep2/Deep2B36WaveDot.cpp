#include "Deep2B36WaveDot.hpp"

namespace Deep2 {

B36WaveDotPlan B36WaveDot::make(const B36WaveDotShape& s) noexcept {
    B36WaveDotPlan p{};
    p.waveWidth = static_cast<uint32_t>(s.wave);
    p.lanesPerWave = p.waveWidth;
    p.dotOpsPerLane = s.bitsPerWeight <= 4 ? 8u : (s.bitsPerWeight <= 6 ? 4u : 4u);
    p.accumulatorsPerWave = s.cols >= 8192 ? 8u : 4u;
    p.rowsPerWavePass = s.rows >= 16384 ? 8u : (s.rows >= 8192 ? 4u : 2u);
    return p;
}

uint64_t B36WaveDot::packedBytes(const B36WaveDotShape& s) noexcept {
    return (uint64_t(s.rows) * uint64_t(s.cols) * s.bitsPerWeight + 7ull) / 8ull;
}

double B36WaveDot::dotOpsPerCycle(const B36WaveDotShape& s) noexcept {
    const uint32_t wave = static_cast<uint32_t>(s.wave);
    const uint32_t dotPerLane = s.bitsPerWeight <= 4 ? 8u : 4u;
    return double(wave) * double(dotPerLane);
}

} // namespace Deep2
