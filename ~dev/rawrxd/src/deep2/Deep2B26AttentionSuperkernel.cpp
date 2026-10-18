#include "Deep2B26AttentionSuperkernel.hpp"
#include <algorithm>

namespace Deep2 {

B26AttentionPlan B26AttentionSuperkernel::make(const B26AttentionShape& s) noexcept {
    B26AttentionPlan p{};
    p.workgroup = s.hidden >= 4096 ? 256u : 128u;
    p.vectorWidth = (s.hidden % 8u == 0u) ? 8u : 4u;
    p.headsPerGroup = s.heads >= 64 ? 4u : (s.heads >= 32 ? 2u : 1u);
    p.qkvTile = s.hidden >= 8192 ? 1024u : (s.hidden >= 4096 ? 512u : 256u);
    p.mlaCompressedPath = s.useMLA && s.kvLoraRank != 0;
    return p;
}

uint64_t B26AttentionSuperkernel::eliminatedIntermediateBytes(
    const B26AttentionShape& s, uint32_t scalarBytes) noexcept {
    if (!s.hidden) return 0;
    uint64_t elems = 0;
    if (s.useMLA && s.qLoraRank && s.kvLoraRank) {
        elems = uint64_t(s.qLoraRank) +
                uint64_t(s.kvLoraRank + s.qkRopeDim) +
                uint64_t(s.heads) * uint64_t(s.headDim);
    } else {
        const uint64_t kvDim = uint64_t(s.kvHeads ? s.kvHeads : s.heads) * s.headDim;
        elems = uint64_t(s.hidden) + 2ull * kvDim;
    }
    // write + later read avoided by keeping the region device-local.
    return elems * scalarBytes * 2ull;
}

} // namespace Deep2
