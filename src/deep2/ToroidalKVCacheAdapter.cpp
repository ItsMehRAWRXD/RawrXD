// ============================================================================
// ToroidalKVCacheAdapter.cpp — Adapter for ToroidalKVCache ring buffer
// ============================================================================

#include "ToroidalKVCacheAdapter.hpp"
#include <cstring>

namespace Deep2 {

bool ToroidalKVCacheAdapter::initialize(size_t numLayers, size_t maxSeqLen,
                                           size_t numHeads, size_t headDim) {
    numLayers_ = numLayers;
    numHeads_  = numHeads;
    headDim_   = headDim;
    maxSeqLen_ = maxSeqLen;

    tokenStride_ = numHeads_ * headDim_;
    layerStride_ = tokenStride_;

    try {
        cache_ = std::make_unique<rawrxd::ToroidalKVCache>(
            headDim_, numHeads_, maxSeqLen_, numLayers_);
    } catch (const std::exception&) {
        return false;
    }

    layerKeys_.resize(numLayers_ * tokenStride_);
    layerValues_.resize(numLayers_ * tokenStride_);
    layerWritten_.assign(numLayers_, false);
    return true;
}

void ToroidalKVCacheAdapter::reset() {
    if (cache_) cache_->magneticReconnection();
    std::fill(layerWritten_.begin(), layerWritten_.end(), false);
}

bool ToroidalKVCacheAdapter::writeKV(size_t layer, size_t head,
                                        const float* keyData, const float* valueData) {
    if (!cache_ || !keyData || !valueData) return false;
    if (layer >= numLayers_ || head >= numHeads_) return false;

    // Copy into the flattened layer buffer at the correct head offset
    size_t offset = layer * layerStride_ + head * headDim_;
    std::memcpy(layerKeys_.data()   + offset, keyData, headDim_ * sizeof(float));
    std::memcpy(layerValues_.data() + offset, valueData, headDim_ * sizeof(float));
    layerWritten_[layer] = true;
    return true;
}

void ToroidalKVCacheAdapter::advance() {
    if (!cache_) return;

    // Inject the fully assembled layer K/V into the toroidal cache
    rawrxd::PlasmaToken token{};
    token.seq_pos = cache_->writeHead();

    cache_->injectToken(token, layerKeys_.data(), layerValues_.data());

    // Reset write tracking for next token
    std::fill(layerWritten_.begin(), layerWritten_.end(), false);
}

size_t ToroidalKVCacheAdapter::querySpans(size_t layer, size_t head,
                                           size_t startPos, size_t endPos,
                                           KVSpan& span0, KVSpan& span1) const {
    span0 = KVSpan{};
    span1 = KVSpan{};

    if (!cache_ || startPos >= endPos) return 0;

    // Map to toroidal sequence numbers
    uint64_t oldest = cache_->oldestSequence();
    uint64_t wh     = cache_->writeHead();

    if (startPos >= static_cast<size_t>(wh)) return 0;

    uint64_t startSeq = oldest + startPos;
    uint64_t endSeq   = oldest + endPos;
    if (endSeq > wh) endSeq = wh;

    rawrxd::KVCacheSpan t0{}, t1{};
    if (!cache_->queryTokenRange(startSeq, endSeq, t0, t1)) {
        return 0;
    }

    // The toroidal cache stores [slot][layer][head][dim].
    // We need to stride into the correct layer/head within each span.
    size_t headOffset = layer * layerStride_ + head * headDim_;

    if (t0.count > 0 && t0.keys) {
        span0.keys   = t0.keys   + headOffset;
        span0.values = t0.values + headOffset;
        span0.count  = t0.count;
        span0.physicalSlot = t0.physical_slot;
        span0.stride = numLayers_ * layerStride_;  // [slot][layer][head][dim]
    }

    if (t1.count > 0 && t1.keys) {
        span1.keys   = t1.keys   + headOffset;
        span1.values = t1.values + headOffset;
        span1.count  = t1.count;
        span1.physicalSlot = t1.physical_slot;
        span1.stride = numLayers_ * layerStride_;  // [slot][layer][head][dim]
    }

    return (span0.count > 0 ? 1 : 0) + (span1.count > 0 ? 1 : 0);
}

size_t ToroidalKVCacheAdapter::currentLength() const {
    return cache_ ? cache_->tokenCount() : 0;
}

size_t ToroidalKVCacheAdapter::maxLength() const {
    return maxSeqLen_;
}

size_t ToroidalKVCacheAdapter::headDimSize() const {
    return headDim_;
}

size_t ToroidalKVCacheAdapter::memoryBytes() const {
    return cache_ ? cache_->memoryBytes() : 0;
}

bool ToroidalKVCacheAdapter::isFull() const {
    return cache_ ? (cache_->tokenCount() >= maxSeqLen_) : false;
}

} // namespace Deep2
