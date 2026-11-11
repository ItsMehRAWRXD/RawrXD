#include "KVCache.h"

#include <cmath>
#include <cstdio>
#include <limits>
#include <vector>

int main()
{
    Deep2::KVCache cache;
    Deep2::KVCacheConfig cfg{};
    cfg.numLayers = 2;
    cfg.maxSeqLen = 8;
    cfg.numHeads = 2;
    cfg.headDim = 4;
    if (!cache.initialize(cfg)) return 1;

    for (size_t h = 0; h < cfg.numHeads; ++h)
    {
        float* k = cache.keyPtr(0, h, 0);
        float* v = cache.valuePtr(0, h, 0);
        if (!k || !v) return 2;
        for (size_t i = 0; i < cfg.headDim; ++i)
        {
            k[i] = 0.25f * static_cast<float>(i + 1);
            v[i] = static_cast<float>(i + 1);
        }
    }
    if (!cache.advanceBy(1)) return 3;

    const float query[4] = {1.f, 0.f, 0.f, 0.f};
    float output[4]{};
    if (!Deep2::AttentionWithCache(query, cache, 0, 0, output, 1)) return 4;
    for (float v : output)
        if (!std::isfinite(v)) return 5;

    float* badValue = cache.valuePtr(0, 0, 0);
    badValue[2] = std::numeric_limits<float>::quiet_NaN();
    if (Deep2::AttentionWithCache(query, cache, 0, 0, output, 1)) return 6;
    bool sawNaN = false;
    for (float v : output) sawNaN = sawNaN || std::isnan(v);
    if (!sawNaN) return 7;

    std::printf("ATTN_GEOMETRY layers=%zu positions=%zu kvHeads=%zu headDim=%zu\n",
                cache.numLayers(), cache.maxSeqLen(), cache.headCount(), cache.headDimSize());
    std::printf("ATTN_FINITE_VALID=1 ATTN_NAN_REJECTED=1\n");
    return 0;
}
