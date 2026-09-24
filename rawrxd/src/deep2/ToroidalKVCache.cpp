/* ToroidalKVCache — infinite-context ring buffer KV cache implementation */
#include "ToroidalKVCache.hpp"
#include <algorithm>
#include <cstring>

namespace Deep2 {

ToroidalKVCache::ToroidalKVCache(size_t numLayers, size_t numHeads,
                                  size_t headDim, size_t maxTokens)
    : numLayers_(numLayers)
    , numHeads_(numHeads)
    , headDim_(headDim)
    , maxTokens_(maxTokens)
    , initialized_(false)
    , ringHead_(0)
    , ringCount_(0)
    , nextSeqPos_(0) {}

ToroidalKVCache::~ToroidalKVCache() = default;

bool ToroidalKVCache::initialize() {
    if (numLayers_ == 0 || numHeads_ == 0 || headDim_ == 0 || maxTokens_ == 0)
        return false;

    const size_t perToken = elementsPerToken();
    const size_t floatsPerLayer = maxTokens_ * perToken;

    kBuffers_.resize(numLayers_);
    vBuffers_.resize(numLayers_);
    for (size_t l = 0; l < numLayers_; ++l) {
        kBuffers_[l] = std::make_unique<float[]>(floatsPerLayer);
        vBuffers_[l] = std::make_unique<float[]>(floatsPerLayer);
        std::fill_n(kBuffers_[l].get(), floatsPerLayer, 0.0f);
        std::fill_n(vBuffers_[l].get(), floatsPerLayer, 0.0f);
    }

    valid_.resize(maxTokens_, false);
    seqPositions_.resize(maxTokens_, 0);
    ringHead_ = 0;
    ringCount_ = 0;
    nextSeqPos_ = 0;
    initialized_ = true;
    return true;
}

bool ToroidalKVCache::writeLayer(size_t layer, const float* k,
                                   const float* v, size_t len) {
    if (!initialized_ || layer >= numLayers_) return false;
    if (!k || !v || len != elementsPerToken()) return false;

    const size_t perToken = elementsPerToken();
    float* kDst = kBuffers_[layer].get() + ringHead_ * perToken;
    float* vDst = vBuffers_[layer].get() + ringHead_ * perToken;
    std::memcpy(kDst, k, len * sizeof(float));
    std::memcpy(vDst, v, len * sizeof(float));
    valid_[ringHead_] = true;
    seqPositions_[ringHead_] = nextSeqPos_;
    return true;
}

size_t ToroidalKVCache::readLayer(size_t layer, float* kOut, float* vOut,
                                   size_t maxLen) const {
    if (!initialized_ || layer >= numLayers_ || ringCount_ == 0) return 0;
    if (!kOut || !vOut) return 0;

    const size_t perToken = elementsPerToken();
    const size_t tokensToRead = std::min(ringCount_, maxLen / perToken);
    if (tokensToRead == 0) return 0;

    // Oldest to newest ordering
    size_t readIdx = (ringHead_ + maxTokens_ - ringCount_) % maxTokens_;
    for (size_t t = 0; t < tokensToRead; ++t) {
        if (!valid_[readIdx]) continue;
        std::memcpy(kOut + t * perToken,
                    kBuffers_[layer].get() + readIdx * perToken,
                    perToken * sizeof(float));
        std::memcpy(vOut + t * perToken,
                    vBuffers_[layer].get() + readIdx * perToken,
                    perToken * sizeof(float));
        readIdx = (readIdx + 1) % maxTokens_;
    }
    return tokensToRead;
}

bool ToroidalKVCache::advance() {
    if (!initialized_) return false;
    ++nextSeqPos_;
    ringHead_ = (ringHead_ + 1) % maxTokens_;
    if (ringCount_ < maxTokens_) ++ringCount_;
    return true;
}

void ToroidalKVCache::clear() {
    ringHead_ = 0;
    ringCount_ = 0;
    nextSeqPos_ = 0;
    std::fill(valid_.begin(), valid_.end(), false);
    std::fill(seqPositions_.begin(), seqPositions_.end(), 0);
}

} // namespace Deep2
