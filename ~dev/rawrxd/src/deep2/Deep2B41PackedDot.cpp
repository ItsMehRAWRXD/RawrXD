#include "Deep2B41PackedDot.hpp"

namespace Deep2 {

B41PackedDotPlan B41PackedDot::make(const B41PackedDotShape& s) noexcept {
    B41PackedDotPlan p{};
    const uint32_t bits = static_cast<uint32_t>(s.quant);
    p.workgroup = s.cols >= 4096 ? 256u : 128u;
    p.packedValuesPerWord = bits <= 4 ? 8u : (bits <= 6 ? 4u : 4u);
    p.wordsPerLane = s.cols >= 8192 ? 8u : 4u;
    p.accumulatorsPerLane = s.cols >= 8192 ? 8u : 4u;
    p.rowsPerGroup = s.rows >= 16384 ? 8u : (s.rows >= 8192 ? 4u : 2u);
    p.subgroupWidth = s.waveWidth ? s.waveWidth : 64u;
    return p;
}

uint64_t B41PackedDot::packedBytes(const B41PackedDotShape& s) noexcept {
    const uint64_t bits = static_cast<uint32_t>(s.quant);
    return (uint64_t(s.rows) * uint64_t(s.cols) * bits + 7ull) / 8ull;
}

double B41PackedDot::idealDotOpsPerByte(const B41PackedDotShape& s) noexcept {
    const double bytes = double(packedBytes(s));
    if (bytes <= 0.0) return 0.0;
    const double ops = 2.0 * double(s.rows) * double(s.cols);
    return ops / bytes;
}

}
