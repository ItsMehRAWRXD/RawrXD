// ============================================================================
// LegacyKVCacheAdapter.cpp — Adapter for existing KVCache.cpp
// ============================================================================

#include "LegacyKVCacheAdapter.hpp"
#include <cstring>

namespace Deep2 {

bool LegacyKVCacheAdapter::initialize(size_t numLayers, size_t maxSeqLen,
                                       size_t numHeads, size_t headDim) {
    cache_ = std::make_unique<KVCache>();
    headDim_  = headDim;
    numHeads_ = numHeads;

    KVCacheConfig cfg;
    cfg.numLayers  = numLayers;
    cfg.maxSeqLen  = maxSeqLen;
    cfg.numHeads   = numHeads;
    cfg.headDim    = headDim;
    cfg.batchSize  = 1;
    return cache_&& cache_->initialize(cfg);
}

void LegacyKVCacheAdapter::reset() {
    if (cache_) cache_->reset();
}

bool LegacyKVCacheAdapter::writeKV(size_t layer, size_t head,
                                    const float* keyData, const float* valueData) {
    if (!cache_ || !keyData || !valueData) return false;

    float* kPtr = nullptr;
    float* vPtr = nullptr;
    cache_->getKVPointers(layer, head, &kPtr, &vPtr);
    if (!kPtr || !vPtr) return false;

    std::memcpy(kPtr, keyData, headDim_ * sizeof(float));
    std::memcpy(vPtr, valueData, headDim_ * sizeof(float));
    return true;
}

void LegacyKVCacheAdapter::advance() {
    if (cache_) cache_->advance();
}

size_t LegacyKVCacheAdapter::querySpans(size_t layer, size_t head,
                                         size_t startPos, size_t endPos,
                                         KVSpan& span0, KVSpan& span1) const {
    span0 = KVSpan{};
    span1 = KVSpan{};

    if (!cache_ || startPos >= endPos) return 0;

    size_t avail = cache_->currentLength();
    if (startPos >= avail) return 0;
    if (endPos > avail) endPos = avail;

    size_t count = endPos - startPos;
    if (count == 0) return 0;

    // Legacy cache stores K/V per-position; we return a single span
    // pointing to the first requested position. The caller must know
    // that legacy layout is fully contiguous across positions.
    const float* k = cache_->getK(layer, head, startPos);
    const float* v = cache_->getV(layer, head, startPos);
    if (!k || !v) return 0;

    span0.keys   = k;
    span0.values = v;
    span0.count  = count;
    span0.physicalSlot = startPos;
    span0.stride = numHeads_ * headDim_;  // Legacy layout: [pos][head][dim]
    return 1;
}

size_t LegacyKVCacheAdapter::currentLength() const {
    return cache_ ? cache_->currentLength() : 0;
}

size_t LegacyKVCacheAdapter::maxLength() const {
    return cache_ ? cache_->maxLength() : 0;
}

size_t LegacyKVCacheAdapter::headDimSize() const {
    return headDim_;
}

size_t LegacyKVCacheAdapter::memoryBytes() const {
    return cache_ ? cache_->memoryUsed() : 0;
}

bool LegacyKVCacheAdapter::isFull() const {
    return cache_ ? cache_->isFull() : false;
}

} // namespace Deep2
