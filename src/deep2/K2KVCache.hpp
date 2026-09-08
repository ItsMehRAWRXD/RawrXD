// ============================================================================
// K2KVCache.hpp — Bounded autoregressive KV cache for DeepSeek2/K2
// ============================================================================

#pragma once

#include <cstddef>
#include <vector>
#include <stdexcept>
#include <algorithm>
#include <cstring>

namespace rawrxd::deep2 {

class K2KVCache {
public:
    K2KVCache() = default;

    K2KVCache(std::size_t numLayers,
              std::size_t maxSeqLen,
              std::size_t kvDim)
    {
        Reset(numLayers, maxSeqLen, kvDim);
    }

    void Reset(std::size_t numLayers,
               std::size_t maxSeqLen,
               std::size_t kvDim)
    {
        if (numLayers == 0 || maxSeqLen == 0 || kvDim == 0)
            throw std::invalid_argument("K2KVCache: invalid dimensions");
        numLayers_ = numLayers;
        maxSeqLen_ = maxSeqLen;
        kvDim_ = kvDim;
        currentLength_ = 0;
        allocatedSeq_ = (std::min)(kPageTok_, maxSeqLen_);
        keys_.assign(numLayers_ * allocatedSeq_ * kvDim_, 0.0f);
        values_.assign(numLayers_ * allocatedSeq_ * kvDim_, 0.0f);
    }

    std::size_t liveBytes() const noexcept {
        return (keys_.size() + values_.size()) * sizeof(float);
    }

    std::size_t evictColdPages() {
        const std::size_t keep = (std::max)(kPageTok_, currentLength_);
        if (keep >= allocatedSeq_) return 0;
        const std::size_t before = liveBytes();
        GrowAllocated(keep);
        return before > liveBytes() ? before - liveBytes() : 0;
    }

    void Clear()
    {
        std::fill(keys_.begin(), keys_.end(), 0.0f);
        std::fill(values_.begin(), values_.end(), 0.0f);
        currentLength_ = 0;
    }

    std::size_t numLayers() const noexcept
    {
        return numLayers_;
    }

    std::size_t maxSeqLen() const noexcept
    {
        return maxSeqLen_;
    }

    std::size_t kvDim() const noexcept
    {
        return kvDim_;
    }

    std::size_t currentLength() const noexcept
    {
        return currentLength_;
    }

    bool CanAppend() const noexcept
    {
        return currentLength_ < maxSeqLen_;
    }

    const float* Key(std::size_t layer, std::size_t position) const
    {
        return At(keys_, layer, position);
    }

    const float* Value(std::size_t layer, std::size_t position) const
    {
        return At(values_, layer, position);
    }

    void Write(std::size_t layer,
               const float* key,
               const float* value)
    {
        if (layer >= numLayers_)
            throw std::out_of_range("K2KVCache: layer");

        if (!CanAppend())
            throw std::out_of_range("K2KVCache: sequence length exceeded");
        EnsureHot(currentLength_);

        float* dstK = MutableAt(keys_, layer, currentLength_);
        float* dstV = MutableAt(values_, layer, currentLength_);

        std::memcpy(dstK, key, kvDim_ * sizeof(float));
        std::memcpy(dstV, value, kvDim_ * sizeof(float));
    }

    void CommitPosition()
    {
        if (!CanAppend())
            throw std::out_of_range("K2KVCache: sequence length exceeded");

        ++currentLength_;
    }

private:
    float* MutableAt(std::vector<float>& storage,
                     std::size_t layer,
                     std::size_t position)
    {
        if (layer >= numLayers_ || position >= allocatedSeq_)
            throw std::out_of_range("K2KVCache: index");

        const std::size_t offset =
            ((layer * allocatedSeq_) + position) * kvDim_;
        return storage.data() + offset;
    }

    const float* At(const std::vector<float>& storage,
                    std::size_t layer,
                    std::size_t position) const
    {
        if (layer >= numLayers_ || position >= allocatedSeq_)
            throw std::out_of_range("K2KVCache: index");
        const std::size_t offset =
            ((layer * allocatedSeq_) + position) * kvDim_;
        return storage.data() + offset;
    }

    void EnsureHot(std::size_t pos) {
        if (pos < allocatedSeq_) return;
        std::size_t neu = allocatedSeq_ + kPageTok_;
        if (neu > maxSeqLen_) neu = maxSeqLen_;
        if (neu <= allocatedSeq_)
            throw std::out_of_range("K2KVCache: sequence length exceeded");
        GrowAllocated(neu);
    }

    void GrowAllocated(std::size_t neu) {
        std::vector<float> nk(numLayers_ * neu * kvDim_, 0.0f);
        std::vector<float> nv(numLayers_ * neu * kvDim_, 0.0f);
        const std::size_t copyPos = (std::min)(currentLength_, allocatedSeq_);
        for (std::size_t L = 0; L < numLayers_; ++L) {
            for (std::size_t p = 0; p < copyPos && p < neu; ++p) {
                std::memcpy(nk.data() + (L * neu + p) * kvDim_,
                            keys_.data() + (L * allocatedSeq_ + p) * kvDim_,
                            kvDim_ * sizeof(float));
                std::memcpy(nv.data() + (L * neu + p) * kvDim_,
                            values_.data() + (L * allocatedSeq_ + p) * kvDim_,
                            kvDim_ * sizeof(float));
            }
        }
        keys_.swap(nk);
        values_.swap(nv);
        allocatedSeq_ = neu;
    }

private:
    static constexpr std::size_t kPageTok_ = 128; // was 8 — cut O(n²) grow thrash on long decode

    std::size_t numLayers_ = 0;
    std::size_t maxSeqLen_ = 0;
    std::size_t kvDim_ = 0;
    std::size_t currentLength_ = 0;
    std::size_t allocatedSeq_ = 0;

    std::vector<float> keys_;
    std::vector<float> values_;
};

} // namespace rawrxd::deep2
