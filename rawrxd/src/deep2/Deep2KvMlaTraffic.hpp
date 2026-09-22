#pragma once
#include <cstdint>
#include <cstddef>

namespace Deep2 {

struct KvMlaInput {
    uint32_t context = 0;
    uint32_t heads = 0;
    uint32_t qkNopeDim = 0;
    uint32_t qkRopeDim = 0;
    uint32_t vDim = 0;
    uint32_t kvLoraRank = 0;
    uint32_t bytesPerScalar = 2;
    bool useMLA = false;
};

struct KvMlaPlan {
    uint32_t tileTokens = 64;
    uint32_t headsPerGroup = 1;
    bool keepCompressedKv = false;
    bool fuseGatherDot = false;
    bool fuseSoftmaxValue = false;
    uint64_t estimatedBytesPerToken = 0;
};

class KvMlaTrafficReducer {
public:
    static KvMlaPlan plan(const KvMlaInput& in) noexcept;
};

} // namespace Deep2
