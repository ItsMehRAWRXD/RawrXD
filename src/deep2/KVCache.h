// ============================================================================
// KVCache.h - Key-Value Cache for Transformer Inference
// Eliminates O(n²) attention recomputation
// ============================================================================

#ifndef DEEP2_KVCACHE_H
#define DEEP2_KVCACHE_H

#include <cstddef>
#include <cstdint>

namespace Deep2 {

// ============================================================================
// KV Cache Configuration
// ============================================================================
struct KVCacheConfig {
    size_t numLayers;
    size_t maxSeqLen;
    size_t numHeads;
    size_t headDim;
    size_t batchSize;
    
    // Calculate total size
    size_t totalSize() const {
        return numLayers * maxSeqLen * numHeads * headDim * sizeof(float) * 2; // K + V
    }
};

// ============================================================================
// KV Cache State
// Stores K/V tensors for all previous tokens
// ============================================================================
class KVCache {
public:
    KVCache();
    ~KVCache();
    
    // Initialize cache with configuration
    bool initialize(const KVCacheConfig& config);
    
    // Reset cache for new sequence
    void reset();
    
    // Get pointers for current position
    // Returns pointers to K and V buffers for current token
    void getKVPointers(size_t layer, size_t head, 
                       float** kPtr, float** vPtr);
    
    // Get K/V from previous position (for attention)
    const float* getK(size_t layer, size_t head, size_t pos) const;
    const float* getV(size_t layer, size_t head, size_t pos) const;
    
    // Advance to next token position
    void advance();
    
    // Current sequence length
    size_t currentLength() const { return currentPos; }
    size_t maxLength()     const { return config.maxSeqLen; }
    size_t headDimSize()   const { return config.headDim; }
    
    // Check if cache is full
    bool isFull() const { return currentPos >= config.maxSeqLen; }
    
    // Memory usage
    size_t memoryUsed() const;
    
private:
    KVCacheConfig config;
    float* kCache;  // [layers][seq][heads][head_dim]
    float* vCache;  // [layers][seq][heads][head_dim]
    size_t currentPos;
    bool initialized;
    
    // Calculate offsets
    size_t getLayerOffset(size_t layer) const;
    size_t getHeadOffset(size_t layer, size_t head, size_t pos) const;
};

// ============================================================================
// Attention with KV Cache
// O(n) complexity instead of O(n²)
// ============================================================================
void AttentionWithCache(const float* query,
                        const KVCache& cache,
                        size_t layer,
                        size_t head,
                        float* output,
                        size_t seqLen);

} // namespace Deep2

#endif // DEEP2_KVCACHE_H
