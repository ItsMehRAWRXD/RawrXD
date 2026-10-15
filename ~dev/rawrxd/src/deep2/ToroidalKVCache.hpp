#pragma once
/* ToroidalKVCache — Infinite-context ring buffer for long-sequence inference
 * Provides circular KV cache with configurable capacity and position tracking.
 * Supports seamless context growth beyond initial maxSeqLen.
 */
#include <cstdint>
#include <vector>
#include <algorithm>
#include <cstring>

namespace Deep2 {

struct ToroidalKVCacheConfig {
    size_t numLayers = 0;
    size_t numHeads = 0;
    size_t headDim = 0;
    size_t maxTokens = 131072;  // 128K default
};

class ToroidalKVCache {
public:
    ToroidalKVCache() = default;
    ~ToroidalKVCache() = default;

    // Non-copyable, movable
    ToroidalKVCache(const ToroidalKVCache&) = delete;
    ToroidalKVCache& operator=(const ToroidalKVCache&) = delete;
    ToroidalKVCache(ToroidalKVCache&&) = default;
    ToroidalKVCache& operator=(ToroidalKVCache&&) = default;

    // Initialize with configuration
    bool initialize(const ToroidalKVCacheConfig& cfg) {
        if (cfg.numLayers == 0 || cfg.numHeads == 0 || cfg.headDim == 0 || cfg.maxTokens == 0)
            return false;
        
        config_ = cfg;
        allocated_ = false;
        return allocate();
    }

    // Get pointer to K buffer at (layer, head, pos)
    float* keyPtr(size_t layer, size_t head, size_t pos) {
        if (!allocated_) return nullptr;
        if (layer >= config_.numLayers || head >= config_.numHeads) return nullptr;
        size_t idx = computeIndex(layer, head, pos);
        if (idx >= keys_.size() / (config_.numLayers * config_.numHeads)) return nullptr;
        return &keys_[idx * config_.headDim];
    }

    // Get pointer to V buffer at (layer, head, pos)
    float* valuePtr(size_t layer, size_t head, size_t pos) {
        if (!allocated_) return nullptr;
        if (layer >= config_.numLayers || head >= config_.numHeads) return nullptr;
        size_t idx = computeIndex(layer, head, pos);
        if (idx >= values_.size() / (config_.numLayers * config_.numHeads)) return nullptr;
        return &values_[idx * config_.headDim];
    }

    // Const versions
    const float* keyPtr(size_t layer, size_t head, size_t pos) const {
        if (!allocated_) return nullptr;
        if (layer >= config_.numLayers || head >= config_.numHeads) return nullptr;
        size_t idx = computeIndex(layer, head, pos);
        if (idx >= keys_.size() / (config_.numLayers * config_.numHeads)) return nullptr;
        return &keys_[idx * config_.headDim];
    }

    const float* valuePtr(size_t layer, size_t head, size_t pos) const {
        if (!allocated_) return nullptr;
        if (layer >= config_.numLayers || head >= config_.numHeads) return nullptr;
        size_t idx = computeIndex(layer, head, pos);
        if (idx >= values_.size() / (config_.numLayers * config_.numHeads)) return nullptr;
        return &values_[idx * config_.headDim];
    }

    // Advance position by one token (circular)
    bool advance() {
        if (!allocated_) return false;
        writePos_ = (writePos_ + 1) % config_.maxTokens;
        if (currentLen_ < config_.maxTokens) {
            currentLen_++;
        } else {
            // Overwriting oldest: effectively advancing readPos too
            readPos_ = (readPos_ + 1) % config_.maxTokens;
        }
        return true;
    }

    // Get current sequence length (committed tokens)
    size_t currentLength() const { return currentLen_; }

    // Get maximum capacity
    size_t capacity() const { return config_.maxTokens; }

    // Check if initialized
    bool isInitialized() const { return allocated_; }

    // Get configuration
    const ToroidalKVCacheConfig& config() const { return config_; }

    // Reset to empty state (preserves allocation)
    void reset() {
        writePos_ = 0;
        readPos_ = 0;
        currentLen_ = 0;
        // Clear buffers (optional, for determinism)
        if (allocated_) {
            std::fill(keys_.begin(), keys_.end(), 0.0f);
            std::fill(values_.begin(), values_.end(), 0.0f);
        }
    }

    // Grow capacity (reallocates)
    bool grow(size_t newMaxTokens) {
        if (newMaxTokens <= config_.maxTokens) return true;
        if (!allocated_) return false;

        ToroidalKVCacheConfig newCfg = config_;
        newCfg.maxTokens = newMaxTokens;

        // Allocate new buffers
        const size_t perHead = newMaxTokens * config_.headDim;
        const size_t perLayer = perHead * config_.numHeads;
        const size_t total = perLayer * config_.numLayers;

        std::vector<float> newKeys, newValues;
        try {
            newKeys.resize(total);
            newValues.resize(total);
        } catch (const std::bad_alloc&) {
            return false;
        }

        // Copy existing data in logical order
        for (size_t layer = 0; layer < config_.numLayers; ++layer) {
            for (size_t head = 0; head < config_.numHeads; ++head) {
                for (size_t i = 0; i < currentLen_; ++i) {
                    size_t srcIdx = computeIndex(layer, head, (readPos_ + i) % config_.maxTokens);
                    size_t dstIdx = (layer * perLayer + head * perHead + i) * config_.headDim;
                    
                    std::copy_n(
                        &keys_[srcIdx * config_.headDim], 
                        config_.headDim, 
                        &newKeys[dstIdx]
                    );
                    std::copy_n(
                        &values_[srcIdx * config_.headDim], 
                        config_.headDim, 
                        &newValues[dstIdx]
                    );
                }
            }
        }

        keys_.swap(newKeys);
        values_.swap(newValues);
        config_ = newCfg;
        writePos_ = currentLen_ % config_.maxTokens;
        readPos_ = 0;
        return true;
    }

    // Get bytes used
    size_t bytes() const {
        if (!allocated_) return 0;
        return (keys_.size() + values_.size()) * sizeof(float);
    }

    // Get write position (for debugging)
    size_t writePosition() const { return writePos_; }
    size_t readPosition() const { return readPos_; }

private:
    ToroidalKVCacheConfig config_;
    std::vector<float> keys_;
    std::vector<float> values_;
    size_t writePos_ = 0;
    size_t readPos_ = 0;
    size_t currentLen_ = 0;
    bool allocated_ = false;

    bool allocate() {
        const size_t perHead = config_.maxTokens * config_.headDim;
        const size_t perLayer = perHead * config_.numHeads;
        const size_t total = perLayer * config_.numLayers;

        try {
            keys_.assign(total, 0.0f);
            values_.assign(total, 0.0f);
        } catch (const std::bad_alloc&) {
            return false;
        }
        allocated_ = true;
        writePos_ = 0;
        readPos_ = 0;
        currentLen_ = 0;
        return true;
    }

    // Compute flat index for (layer, head, pos) with circular wrapping
    size_t computeIndex(size_t layer, size_t head, size_t pos) const {
        const size_t maxTokens = config_.maxTokens;
        const size_t perHead = maxTokens * config_.headDim;
        const size_t perLayer = perHead * config_.numHeads;
        
        // Circular position
        size_t circularPos = pos % maxTokens;
        
        return layer * perLayer + head * perHead + circularPos * config_.headDim;
    }
};

} // namespace Deep2