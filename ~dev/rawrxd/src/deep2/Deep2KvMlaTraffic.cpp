#include "Deep2KvMlaTraffic.hpp"
#include <algorithm>

namespace Deep2 {

KvMlaPlan KvMlaTrafficReducer::plan(const KvMlaInput& in) noexcept {
    KvMlaPlan p{};
    p.tileTokens = in.context >= 65536 ? 256u :
                   (in.context >= 16384 ? 128u : 64u);
    p.headsPerGroup = in.heads >= 64 ? 4u : (in.heads >= 32 ? 2u : 1u);

    if (in.useMLA && in.kvLoraRank) {
        p.keepCompressedKv = true;
        p.fuseGatherDot = true;
        p.fuseSoftmaxValue = true;
        const uint64_t compressed =
            uint64_t(in.context) * uint64_t(in.kvLoraRank + in.qkRopeDim) *
            uint64_t(in.bytesPerScalar);
        const uint64_t query = uint64_t(in.heads) *
            uint64_t(in.qkNopeDim + in.qkRopeDim) * uint64_t(in.bytesPerScalar);
        p.estimatedBytesPerToken = compressed + query;
    } else {
        const uint64_t kv =
            uint64_t(in.context) * uint64_t(in.heads) *
            uint64_t(in.qkNopeDim + in.qkRopeDim + in.vDim) *
            uint64_t(in.bytesPerScalar);
        p.estimatedBytesPerToken = kv;
    }
    return p;
}

} // namespace Deep2
