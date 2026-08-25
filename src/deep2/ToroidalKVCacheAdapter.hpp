// ============================================================================
// ToroidalKVCacheAdapter.hpp — Adapter: ToroidalKVCache → IKVCacheBackend
// ============================================================================

#pragma once

#include "IKVCacheBackend.hpp"
#include "ToroidalKVCache.hpp"
#include <memory>

namespace Deep2 {

class ToroidalKVCacheAdapter : public IKVCacheBackend {
public:
    ToroidalKVCacheAdapter() = default;
    ~ToroidalKVCacheAdapter() override = default;

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

    // Access underlying toroidal cache (for diagnostics / Chamber integration)
    rawrxd::ToroidalKVCache* underlying() const { return cache_.get(); }

private:
    std::unique_ptr<rawrxd::ToroidalKVCache> cache_;
    size_t numLayers_  = 0;
    size_t numHeads_   = 0;
    size_t headDim_    = 0;
    size_t maxSeqLen_  = 0;

    // Flattened scratch buffer for layer-wise K/V injection
    std::vector<float> layerKeys_;
    std::vector<float> layerValues_;
    size_t tokenStride_ = 0;
    size_t layerStride_ = 0;

    // Per-layer write tracking
    std::vector<bool> layerWritten_;
};

} // namespace Deep2
