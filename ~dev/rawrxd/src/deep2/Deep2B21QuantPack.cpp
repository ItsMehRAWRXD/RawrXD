#include "Deep2B21QuantPack.hpp"
#include <algorithm>

namespace Deep2 {

QuantPackPlan B21QuantPack::make(const QuantPackInput& in) noexcept {
    QuantPackPlan p{};
    const uint32_t bits = static_cast<uint32_t>(in.kind);
    p.tileCols = in.cols >= 8192 ? 1024u : (in.cols >= 4096 ? 512u : 256u);
    p.tileRows = in.rows >= 8192 ? 4u : (in.rows >= 2048 ? 2u : 1u);
    p.vectorBytes = bits <= 4 ? 16u : (bits <= 6 ? 16u : 32u);
    p.swizzle = (in.waveWidth >= 64) ? 2u : 1u;
    p.groupsPerTile = std::max(1u, p.tileCols / std::max(1u, in.groupSize));
    p.prepackAtLoad = true;
    p.dequantInRegisters = true;
    return p;
}

uint64_t B21QuantPack::packedWeightBytes(const QuantPackInput& in) noexcept {
    const uint64_t bits = static_cast<uint32_t>(in.kind);
    return (uint64_t(in.rows) * uint64_t(in.cols) * bits + 7ull) / 8ull;
}

uint64_t B21QuantPack::scaleBytes(const QuantPackInput& in) noexcept {
    const uint64_t groups = (uint64_t(in.cols) + in.groupSize - 1ull) / in.groupSize;
    return uint64_t(in.rows) * groups * 4ull;
}

}
