// ============================================================================
// K2KVCache.hpp — Bounded autoregressive KV cache for DeepSeek2/K2
// ============================================================================

#pragma once

#include <cstddef>
#include <limits>
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
        const std::size_t initial = (std::min)(kPageTok_, maxSeqLen);
        const std::size_t count = CheckedElements(numLayers, initial, kvDim);
        std::vector<float> nk(count, 0.0f), nv(count, 0.0f);
        keys_.swap(nk); values_.swap(nv);
        numLayers_ = numLayers;
        maxSeqLen_ = maxSeqLen;
        kvDim_ = kvDim;
        currentLength_ = 0;
        written_.assign(numLayers_, 0);
        allocatedSeq_ = initial;
    }

    std::size_t liveBytes() const noexcept {
        return (keys_.size() + values_.size()) * sizeof(float);
    }

    std::size_t evictColdPages() {
        const std::size_t keep = (std::max)((std::min)(kPageTok_, maxSeqLen_), currentLength_);
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

    // Explicit geometry and allocation introspection for admission receipts.
    std::size_t allocatedPositions() const noexcept { return allocatedSeq_; }
    std::size_t committedBytes() const noexcept {
        return 2 * numLayers_ * currentLength_ * kvDim_ * sizeof(float);
    }
    std::size_t reservedBytes() const noexcept { return liveBytes(); }

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
        if (key == nullptr || value == nullptr)
            throw std::invalid_argument("K2KVCache: null KV input");
        EnsureHot(currentLength_);

        float* dstK = MutableAt(keys_, layer, currentLength_);
        float* dstV = MutableAt(values_, layer, currentLength_);


        std::memcpy(dstK, key, kvDim_ * sizeof(float));
        std::memcpy(dstV, value, kvDim_ * sizeof(float));
        written_[layer] = 1;
    }

    // Discard any speculative writes at the current decode position.
    // Does not modify previously committed positions.
    void RollbackPosition()
    {
        std::fill(written_.begin(), written_.end(), 0);
        if (currentLength_ >= allocatedSeq_) return;
        for (std::size_t layer = 0; layer < numLayers_; ++layer) {
            float* k = MutableAt(keys_, layer, currentLength_);
            float* v = MutableAt(values_, layer, currentLength_);
            std::fill_n(k, kvDim_, 0.0f);
            std::fill_n(v, kvDim_, 0.0f);
        }
    }

    // Drop all positions after the specified committed prefix. Used for
    // decode cancellation and prefill rollback without changing geometry.
    void Truncate(std::size_t committedPrefix)
    {
        if (committedPrefix > currentLength_)
            throw std::out_of_range("K2KVCache: truncate beyond committed length");
        // Only clear discarded committed positions and the speculative slot.
        // Untouched capacity is already zero-initialized by GrowAllocated.
        const std::size_t clearEnd = (std::min)(allocatedSeq_, currentLength_ + (currentLength_ < allocatedSeq_ ? 1u : 0u));
        const std::size_t clearFloats = (clearEnd - committedPrefix) * kvDim_;
        if (clearFloats == 0) { currentLength_ = committedPrefix; std::fill(written_.begin(), written_.end(), 0); return; }
        for (std::size_t layer = 0; layer < numLayers_; ++layer) {
            std::fill_n(MutableAt(keys_, layer, committedPrefix), clearFloats, 0.0f);
            std::fill_n(MutableAt(values_, layer, committedPrefix), clearFloats, 0.0f);
        }
        currentLength_ = committedPrefix;
        std::fill(written_.begin(), written_.end(), 0);
    }

    // Fail-closed transactional commit: a complete layer set is required.
    // Existing Write/CommitPosition remain available for sparse-layer callers.
    void CommitCompletePosition()
    {
        if (written_.size() != numLayers_)
            throw std::logic_error("K2KVCache: invalid layer completion state");
        for (unsigned char written : written_)
            if (!written)
                throw std::invalid_argument("K2KVCache: incomplete KV position");
        CommitPosition();
    }

    void CommitPosition()
    {
        if (!CanAppend())
            throw std::out_of_range("K2KVCache: sequence length exceeded");

        EnsureHot(currentLength_); // committed positions must remain addressable
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
        const std::size_t remaining = maxSeqLen_ - allocatedSeq_;
        // Geometric growth bounds reallocations to O(log context) while
        // retaining the eight-token initial footprint for short replays.
        const std::size_t increment = (std::min)((std::max)(allocatedSeq_, kPageTok_), remaining);
        const std::size_t neu = allocatedSeq_ + increment;
        if (neu <= allocatedSeq_)
            throw std::out_of_range("K2KVCache: sequence length exceeded");
        GrowAllocated(neu);
    }

    void GrowAllocated(std::size_t neu) {
        const std::size_t count = CheckedElements(numLayers_, neu, kvDim_);
        std::vector<float> nk(count, 0.0f), nv(count, 0.0f);
        const std::size_t copyPos = (std::min)(allocatedSeq_, neu);
        // Each layer owns a contiguous token slab; copy once per layer.
        const std::size_t copyBytes = copyPos * kvDim_ * sizeof(float);
        for (std::size_t L = 0; L < numLayers_; ++L) {
            std::memcpy(nk.data() + L * neu * kvDim_,
                        keys_.data() + L * allocatedSeq_ * kvDim_, copyBytes);
            std::memcpy(nv.data() + L * neu * kvDim_,
                        values_.data() + L * allocatedSeq_ * kvDim_, copyBytes);
        }
        keys_.swap(nk);
        values_.swap(nv);
        allocatedSeq_ = neu;
    }

private:
    static std::size_t CheckedElements(std::size_t layers, std::size_t seq, std::size_t dim) {
        const std::size_t max = (std::numeric_limits<std::size_t>::max)() / sizeof(float);
        if (!layers || !seq || !dim || layers > max / seq || layers * seq > max / dim)
            throw std::length_error("K2KVCache: dimension overflow");
        return layers * seq * dim;
    }
    static constexpr std::size_t kPageTok_ = 8; // avoid 128-token eager allocation

    std::size_t numLayers_ = 0;
    std::size_t maxSeqLen_ = 0;
    std::size_t kvDim_ = 0;
    std::size_t currentLength_ = 0;
    std::size_t allocatedSeq_ = 0;

    std::vector<float> keys_;
    std::vector<float> values_;
    std::vector<unsigned char> written_;
};

} // namespace rawrxd::deep2
