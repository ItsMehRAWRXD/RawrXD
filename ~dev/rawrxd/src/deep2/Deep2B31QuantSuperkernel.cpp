#include "Deep2B31QuantSuperkernel.hpp"
#include <algorithm>

namespace Deep2 {

B31QuantPlan B31QuantSuperkernel::make(const B31QuantShape& s) noexcept {
    B31QuantPlan p{};
    p.workgroup = s.cols >= 4096 ? 256u : 128u;
    p.rowsPerGroup = s.rows >= 8192 ? 4u : (s.rows >= 2048 ? 2u : 1u);
    p.vectorBytes = static_cast<uint32_t>(s.type) <= 4 ? 16u : 32u;
    p.blocksPerPrefetch = s.cols >= 8192 ? 8u : (s.cols >= 4096 ? 4u : 2u);
    p.unpackLanes = s.wave >= 64 ? 8u : 4u;
    return p;
}

double B31QuantSuperkernel::bytesPerWeight(const B31QuantShape& s) noexcept {
    return double(static_cast<uint32_t>(s.type)) / 8.0;
}

uint64_t B31QuantSuperkernel::estimatedWeightBytes(const B31QuantShape& s) noexcept {
    const uint64_t bits = static_cast<uint32_t>(s.type);
    const uint64_t raw = (uint64_t(s.rows) * uint64_t(s.cols) * bits + 7ull) / 8ull;
    const uint64_t groups = (uint64_t(s.cols) + s.block - 1ull) / s.block;
    const uint64_t scales = uint64_t(s.rows) * groups * 4ull;
    return raw + scales;
}

} // namespace Deep2
