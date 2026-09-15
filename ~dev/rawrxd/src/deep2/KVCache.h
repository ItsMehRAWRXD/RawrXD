#pragma once
// ============================================================================
// KVCache.h — Batch 6 real causal KV cache
// Layout: [layer][kv_head][position][head_dim]
// - checked allocation arithmetic
// - checked addressing
// - reset/rewind/advance semantics
// - growth preserving committed prefix
// ============================================================================
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <new>
#include <utility>
#include <vector>

namespace Deep2 {

struct KVCacheConfig {
    size_t numLayers = 0;
    size_t numHeads = 0;      // KV heads, not query heads
    size_t headDim = 0;
    size_t maxSeqLen = 0;
};

class KVCache {
public:
    KVCache() = default;
    KVCache(const KVCache&) = delete;
    KVCache& operator=(const KVCache&) = delete;
    KVCache(KVCache&&) noexcept = default;
    KVCache& operator=(KVCache&&) noexcept = default;

    bool allocate(const KVCacheConfig& cfg) {
        size_t perHead = 0, perLayer = 0, total = 0;
        if (!validConfig(cfg) ||
            mulOverflow(cfg.maxSeqLen, cfg.headDim, perHead) ||
            mulOverflow(cfg.numHeads, perHead, perLayer) ||
            mulOverflow(cfg.numLayers, perLayer, total)) {
            return false;
        }

        try {
            std::vector<float> newKeys(total, 0.0f);
            std::vector<float> newValues(total, 0.0f);
            keys_.swap(newKeys);
            values_.swap(newValues);
        } catch (const std::bad_alloc&) {
            return false;
        }

        config_ = cfg;
        perHeadStride_ = perHead;
        perLayerStride_ = perLayer;
        currentLen_ = 0;
        allocated_ = true;
        return true;
    }

    bool clear(bool zeroMemory = false) {
        if (!allocated_) {
            currentLen_ = 0;
            return true;
        }
        currentLen_ = 0;
        if (zeroMemory) {
            std::fill(keys_.begin(), keys_.end(), 0.0f);
            std::fill(values_.begin(), values_.end(), 0.0f);
        }
        return true;
    }

    bool reset() { return clear(false); }

    bool advance() {
        if (!allocated_ || currentLen_ >= config_.maxSeqLen) return false;
        ++currentLen_;
        return true;
    }

    bool advanceBy(size_t count) {
        if(!allocated_||count>config_.maxSeqLen-currentLen_) return false;
        currentLen_+=count;
        return true;
    }

    size_t checkpoint() const noexcept { return currentLen_; }

    bool rewind(size_t newLength, bool zeroDiscarded = false) {
        if (!allocated_ || newLength > currentLen_) return false;
        if (zeroDiscarded && newLength < currentLen_) {
            for (size_t layer = 0; layer < config_.numLayers; ++layer) {
                for (size_t head = 0; head < config_.numHeads; ++head) {
                    for (size_t pos = newLength; pos < currentLen_; ++pos) {
                        float* k = keyPtr(layer, head, pos);
                        float* v = valuePtr(layer, head, pos);
                        if (k) std::fill(k, k + config_.headDim, 0.0f);
                        if (v) std::fill(v, v + config_.headDim, 0.0f);
                    }
                }
            }
        }
        currentLen_ = newLength;
        return true;
    }

    bool grow(size_t newMaxSeqLen) {
        if (!allocated_ || newMaxSeqLen == 0) return false;
        if (newMaxSeqLen <= config_.maxSeqLen) return true;

        KVCacheConfig nextCfg = config_;
        nextCfg.maxSeqLen = newMaxSeqLen;

        size_t newPerHead = 0, newPerLayer = 0, newTotal = 0;
        if (mulOverflow(nextCfg.maxSeqLen, nextCfg.headDim, newPerHead) ||
            mulOverflow(nextCfg.numHeads, newPerHead, newPerLayer) ||
            mulOverflow(nextCfg.numLayers, newPerLayer, newTotal)) {
            return false;
        }

        std::vector<float> newKeys;
        std::vector<float> newValues;
        try {
            newKeys.assign(newTotal, 0.0f);
            newValues.assign(newTotal, 0.0f);
        } catch (const std::bad_alloc&) {
            return false;
        }

        const size_t committed = currentLen_;
        for (size_t layer = 0; layer < config_.numLayers; ++layer) {
            for (size_t head = 0; head < config_.numHeads; ++head) {
                const size_t oldBase =
                    layer * perLayerStride_ + head * perHeadStride_;
                const size_t newBase =
                    layer * newPerLayer + head * newPerHead;
                const size_t elems = committed * config_.headDim;

                std::copy_n(keys_.data() + oldBase, elems,
                            newKeys.data() + newBase);
                std::copy_n(values_.data() + oldBase, elems,
                            newValues.data() + newBase);
            }
        }

        keys_.swap(newKeys);
        values_.swap(newValues);
        config_ = nextCfg;
        perHeadStride_ = newPerHead;
        perLayerStride_ = newPerLayer;
        return true;
    }

    float* keyPtr(size_t layer, size_t head, size_t pos) {
        size_t idx = 0;
        return indexOf(layer, head, pos, idx) ? keys_.data() + idx : nullptr;
    }

    const float* keyPtr(size_t layer, size_t head, size_t pos) const {
        size_t idx = 0;
        return indexOf(layer, head, pos, idx) ? keys_.data() + idx : nullptr;
    }

    float* valuePtr(size_t layer, size_t head, size_t pos) {
        size_t idx = 0;
        return indexOf(layer, head, pos, idx) ? values_.data() + idx : nullptr;
    }

    const float* valuePtr(size_t layer, size_t head, size_t pos) const {
        size_t idx = 0;
        return indexOf(layer, head, pos, idx) ? values_.data() + idx : nullptr;
    }

    // Compatibility helper: returns pointers for the current uncommitted
    // position. Caller advances only after the full token transaction commits.
    bool getKVPointers(size_t layer, size_t head, float** k, float** v) {
        if (k) *k = nullptr;
        if (v) *v = nullptr;
        if (!allocated_ || currentLen_ >= config_.maxSeqLen) return false;
        float* kp = keyPtr(layer, head, currentLen_);
        float* vp = valuePtr(layer, head, currentLen_);
        if (!kp || !vp) return false;
        if (k) *k = kp;
        if (v) *v = vp;
        return true;
    }

    size_t currentLength() const { return currentLen_; }
    size_t capacity() const { return config_.maxSeqLen; }
    bool allocated() const { return allocated_; }
    const KVCacheConfig& config() const { return config_; }

    size_t elementCount() const { return keys_.size(); }

    size_t bytes() const {
        if (keys_.size() >
            std::numeric_limits<size_t>::max() / (2 * sizeof(float))) {
            return std::numeric_limits<size_t>::max();
        }
        return keys_.size() * 2 * sizeof(float);
    }

private:
    static bool validConfig(const KVCacheConfig& c) {
        return c.numLayers > 0 && c.numHeads > 0 &&
               c.headDim > 0 && c.maxSeqLen > 0;
    }

    static bool mulOverflow(size_t a, size_t b, size_t& out) {
        if (a != 0 && b > std::numeric_limits<size_t>::max() / a)
            return true;
        out = a * b;
        return false;
    }

    bool indexOf(size_t layer, size_t head, size_t pos, size_t& idx) const {
        if (!allocated_ ||
            layer >= config_.numLayers ||
            head >= config_.numHeads ||
            pos >= config_.maxSeqLen) {
            return false;
        }

        // Strides were overflow-checked at allocation/growth.
        idx = layer * perLayerStride_ +
              head * perHeadStride_ +
              pos * config_.headDim;
        return idx <= keys_.size() &&
               config_.headDim <= keys_.size() - idx;
    }

    KVCacheConfig config_{};
    std::vector<float> keys_;
    std::vector<float> values_;
    size_t perHeadStride_ = 0;
    size_t perLayerStride_ = 0;
    size_t currentLen_ = 0;
    bool allocated_ = false;
};

} // namespace Deep2
