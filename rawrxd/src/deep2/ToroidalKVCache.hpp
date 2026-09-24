#pragma once
/* ToroidalKVCache — infinite-context ring buffer KV cache */
#include <cstdint>
#include <cstddef>
#include <vector>
#include <memory>
#include <stdexcept>
namespace Deep2 {

class ToroidalKVCache {
public:
    struct Slot {
        float* k = nullptr;
        float* v = nullptr;
        bool valid = false;
        size_t seqPos = 0; // original sequence position for lookup
    };

    ToroidalKVCache(size_t numLayers, size_t numHeads, size_t headDim,
                    size_t maxTokens);
    ~ToroidalKVCache();

    // Disable copy/move (holds raw pointers)
    ToroidalKVCache(const ToroidalKVCache&) = delete;
    ToroidalKVCache& operator=(const ToroidalKVCache&) = delete;

    bool initialize();
    bool isInitialized() const { return initialized_; }

    // Write K/V for a given layer at current head position
    bool writeLayer(size_t layer, const float* k, const float* v, size_t len);

    // Read K/V for a given layer, concatenating from oldest to newest
    // Returns number of valid slots read
    size_t readLayer(size_t layer, float* kOut, float* vOut,
                     size_t maxLen) const;

    // Advance the ring head by one position
    bool advance();

    // Current number of valid positions in the ring
    size_t currentLength() const { return ringCount_; }

    // Maximum capacity
    size_t capacity() const { return maxTokens_; }

    // Reset to empty state
    void clear();

    size_t numLayers() const { return numLayers_; }
    size_t numHeads() const { return numHeads_; }
    size_t headDim() const { return headDim_; }

private:
    size_t numLayers_ = 0;
    size_t numHeads_ = 0;
    size_t headDim_ = 0;
    size_t maxTokens_ = 0;
    bool initialized_ = false;

    // Ring buffer: [layer][token][k or v data]
    // Flat allocation per layer: maxTokens * headDim floats each for K and V
    std::vector<std::unique_ptr<float[]>> kBuffers_;
    std::vector<std::unique_ptr<float[]>> vBuffers_;
    std::vector<bool> valid_;
    std::vector<size_t> seqPositions_;

    size_t ringHead_ = 0;   // write position
    size_t ringCount_ = 0;  // how many positions are currently valid
    size_t nextSeqPos_ = 0; // monotonic counter for seqPos

    size_t elementsPerToken() const { return numHeads_ * headDim_; }
};

} // namespace Deep2
