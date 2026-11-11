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
    size_t numLayers()    const { return config.numLayers; }
    size_t maxSeqLen()    const { return config.maxSeqLen; }
    bool isInitialized() const { return initialized; }
    size_t maxLength()     const { return config.maxSeqLen; }
    size_t headDimSize()   const { return config.headDim; }
    size_t headCount()     const { return config.numHeads; }
    
    // Check if cache is full
    bool isFull() const { return currentPos >= config.maxSeqLen; }

    // ------------------------------------------------------------------------
    // DEEP2_BATCHED_PREFILL_001 — writable KV primitives.
    //
    // getKVPointers() only exposes the CURRENT position, which is all the
    // serial one-token-at-a-time prefill ever needed. A chunked prefill path
    // must write several consecutive positions per layer before committing the
    // cursor, so it needs an explicit writable accessor at a given position.
    //
    // These are the ONLY writers that accept a caller-chosen position, and
    // they are what makes transactional KV writes possible: a chunk is fully
    // written and only then committed via advanceBy(), so a mid-chunk failure
    // cannot leave a half-written prefix that later attention would read as
    // committed.
    // ------------------------------------------------------------------------
    float* keyPtr(size_t layer, size_t head, size_t pos);
    float* valuePtr(size_t layer, size_t head, size_t pos);

    // Read-only alias of keyPtr/valuePtr, for callers that prefer pointer
    // naming symmetry with the accessors above.
    const float* keyAt(size_t layer, size_t head, size_t pos) const {
        return getK(layer, head, pos);
    }
    const float* valueAt(size_t layer, size_t head, size_t pos) const {
        return getV(layer, head, pos);
    }

    // Advance the committed cursor by n positions in one transaction.
    // Returns false (and advances nothing) when the span does not fit.
    bool advanceBy(size_t n);

    // Committed-window capacity actually backed by pages right now. This is
    // NOT virtualMaxSeq: the cache grows lazily, so a caller that wants to
    // know how many positions it can safely index must ask here.
    size_t capacity() const { return allocatedSeq; }

    // Grow maxSeqLen, preserving written prefix positions
    bool grow(size_t newMaxSeqLen);
    
    // Memory usage — live allocated pages, not virtual maxSeq
    size_t memoryUsed() const;
    size_t liveBytes() const { return memoryUsed(); }
    size_t evictColdPages();
    
private:
    KVCacheConfig config;
    float* kCache;  // [layers][allocatedSeq][heads][head_dim]
    float* vCache;
    size_t currentPos;
    size_t allocatedSeq;
    size_t virtualMaxSeq;
    bool initialized;
    
    // Calculate offsets
    size_t getLayerOffset(size_t layer) const;
    size_t getHeadOffset(size_t layer, size_t head, size_t pos) const;
};

// ============================================================================
// Attention with KV Cache
// O(n) complexity instead of O(n²)
// ============================================================================
// Returns false when attention cannot produce a finite result. On failure the
// output buffer is filled with quiet NaN so callers cannot mistake a skipped
// or masked score for a valid hidden state.
bool AttentionWithCache(const float* query,
                        const KVCache& cache,
                        size_t layer,
                        size_t head,
                        float* output,
                        size_t seqLen);

} // namespace Deep2

#endif // DEEP2_KVCACHE_H
