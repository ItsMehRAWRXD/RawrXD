#pragma once
// Stub: KVCache (Deep2 namespace)
#include <cstddef>
#include <cstdint>
#include <vector>
namespace Deep2 {
struct KVCacheConfig {
    size_t numLayers = 0;
    size_t numHeads = 0;
    size_t headDim = 0;
    size_t maxSeqLen = 0;
};
class KVCache {
public:
    KVCache() = default;
    bool allocate(const KVCacheConfig& cfg) {
        config_ = cfg;
        size_t total = cfg.numLayers * cfg.numHeads * cfg.maxSeqLen * cfg.headDim;
        keys_.assign(total, 0.0f);
        values_.assign(total, 0.0f);
        return true;
    }
    bool clear() { return true; }
    float* keyPtr(size_t layer, size_t head, size_t pos) {
        size_t stride = config_.numHeads * config_.maxSeqLen * config_.headDim;
        size_t hstride = config_.maxSeqLen * config_.headDim;
        return keys_.data() + layer * stride + head * hstride + pos * config_.headDim;
    }
    float* valuePtr(size_t layer, size_t head, size_t pos) {
        size_t stride = config_.numHeads * config_.maxSeqLen * config_.headDim;
        size_t hstride = config_.maxSeqLen * config_.headDim;
        return values_.data() + layer * stride + head * hstride + pos * config_.headDim;
    }
    void advance() { if (currentLen_ < config_.maxSeqLen) ++currentLen_; }
    size_t currentLength() const { return currentLen_; }
private:
    KVCacheConfig config_{};
    std::vector<float> keys_;
    std::vector<float> values_;
    size_t currentLen_ = 0;
};
} // namespace Deep2
