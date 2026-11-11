#include "Deep2B34FusedKvAttention.hpp"

namespace Deep2 {

B34KvAttnPlan B34FusedKvAttention::make(const B34KvAttnShape& s) noexcept {
    B34KvAttnPlan p{};
    p.tokenTile = s.context >= 65536 ? 256u :
                  (s.context >= 16384 ? 128u : 64u);
    p.headsPerGroup = s.heads >= 64 ? 4u : (s.heads >= 32 ? 2u : 1u);
    return p;
}

uint64_t B34FusedKvAttention::avoidedKvRoundtripBytes(const B34KvAttnShape& s) noexcept {
    if (s.useMLA && s.compressedRank) {
        return uint64_t(s.compressedRank) *
               uint64_t(s.scalarBytes) * 2ull;
    }
    const uint64_t kvh = s.kvHeads ? s.kvHeads : s.heads;
    return kvh * uint64_t(s.headDim) *
           uint64_t(s.scalarBytes) * 4ull;
}

} // namespace Deep2
