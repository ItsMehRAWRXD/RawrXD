// ============================================================================
// LegacyKVCacheAdapter.hpp — Adapter: existing KVCache.cpp → IKVCacheBackend
// ============================================================================

#pragma once

#include "IKVCacheBackend.hpp"
#include "KVCache.h"
#include <memory>

namespace Deep2 {

class LegacyKVCacheAdapter : public IKVCacheBackend {
public:
    LegacyKVCacheAdapter() = default;
    ~LegacyKVCacheAdapter() override = default;

    bool initialize(size_t numLayers, size_t maxSeqLen,
                    size_t numHeads, size_t headDim) override;

    void reset() override;

    bool writeKV(size_t layer, size_t head,
                 const float* keyData, const float* valueData) override;

    void advance() override;

    size_t querySpans(size_t layer, size_t head,
                      size_t startPos, size_t endPos,
                      KVSpan& span0, KVSpan& span1) const override;

    size_t currentLength() const override;
    size_t maxLength()     const override;
    size_t headDimSize()   const override;
    size_t memoryBytes()   const override;
    bool   isFull()        const override;

    // Access underlying legacy cache (for migration / debugging)
    KVCache* underlying() const { return cache_.get(); }

private:
    std::unique_ptr<KVCache> cache_;
    size_t headDim_ = 0;
    size_t numHeads_ = 0;
};

} // namespace Deep2
