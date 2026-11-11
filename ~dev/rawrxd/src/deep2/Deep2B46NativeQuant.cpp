#include "Deep2B46NativeQuant.hpp"

namespace Deep2 {

B46NativeQuantPlan B46NativeQuant::make(const B46QuantGeometry& g) noexcept {
    B46NativeQuantPlan p{};
    p.workgroup = g.cols >= 4096 ? 256u : 128u;
    p.rowsPerGroup = g.rows >= 16384 ? 8u : (g.rows >= 8192 ? 4u : 2u);

    const uint32_t bits = static_cast<uint32_t>(g.format);
    p.valuesPerDecode = bits <= 4 ? 8u : 4u;
    p.packedLoadsPerLane = g.cols >= 8192 ? 8u : 4u;
    p.accumulatorsPerLane = g.cols >= 8192 ? 8u : 4u;
    p.scaleCacheEntries = g.blockSize >= 64 ? 16u : 8u;
    return p;
}

uint64_t B46NativeQuant::packedPayloadBytes(const B46QuantGeometry& g) noexcept {
    const uint64_t bits = static_cast<uint32_t>(g.format);
    const uint64_t q = (uint64_t(g.rows) * uint64_t(g.cols) * bits + 7ull) / 8ull;
    const uint64_t groups =
        (uint64_t(g.cols) + uint64_t(g.blockSize) - 1ull) / uint64_t(g.blockSize);
    const uint64_t scales = uint64_t(g.rows) * groups * 4ull;
    return q + scales;
}

}
