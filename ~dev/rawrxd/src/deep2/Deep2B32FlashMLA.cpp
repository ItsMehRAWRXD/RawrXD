#include "Deep2B32FlashMLA.hpp"

namespace Deep2 {

B32FlashMlaPlan B32FlashMLA::make(const B32FlashMlaShape& s) noexcept {
    B32FlashMlaPlan p{};
    p.tokenTile = s.context >= 131072 ? 256u :
                  (s.context >= 32768 ? 128u : 64u);
    p.headsPerGroup = s.heads >= 64 ? 4u : (s.heads >= 32 ? 2u : 1u);
    p.rankTile = s.kvLoraRank >= 512 ? 128u : 64u;
    return p;
}

uint64_t B32FlashMLA::avoidedScoreBytes(const B32FlashMlaShape& s) noexcept {
    return uint64_t(s.context) * uint64_t(s.heads) * sizeof(float);
}

uint64_t B32FlashMLA::compressedKvReadBytes(const B32FlashMlaShape& s) noexcept {
    return uint64_t(s.context) *
           uint64_t(s.kvLoraRank + s.qkRopeDim) *
           uint64_t(s.scalarBytes);
}

} // namespace Deep2
