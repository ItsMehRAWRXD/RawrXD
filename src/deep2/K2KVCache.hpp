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

        const std::size_t layerSize = maxSeqLen_ * kvDim_;

        keys_.assign(numLayers_ * layerSize, 0.0f);
        values_.assign(numLayers_ * layerSize, 0.0f);
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
        if (layer >= numLayers_ || position >= maxSeqLen_)
            throw std::out_of_range("K2KVCache: index");

        const std::size_t offset =
            ((layer * maxSeqLen_) + position) * kvDim_;

        return storage.data() + offset;
    }

    const float* At(const std::vector<float>& storage,
                    std::size_t layer,
                    std::size_t position) const
    {
        if (layer >= numLayers_ || position >= maxSeqLen_)
            throw std::out_of_range("K2KVCache: index");

        const std::size_t offset =
            ((layer * maxSeqLen_) + position) * kvDim_;

        return storage.data() + offset;
    }

private:
    std::size_t numLayers_ = 0;
    std::size_t maxSeqLen_ = 0;
    std::size_t kvDim_ = 0;
    std::size_t currentLength_ = 0;

    std::vector<float> keys_;
    std::vector<float> values_;
};

} // namespace rawrxd::deep2
