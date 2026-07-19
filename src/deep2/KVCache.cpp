// ============================================================================
// KVCache.cpp - Key-Value Cache Implementation
// ============================================================================

#include "KVCache.h"
#include <cstring>
#include <cstdio>
#include <cmath>
#include <cstdlib>
#ifdef _WIN32
    #include <malloc.h>
#else
    #include <stdlib.h>
#endif

namespace Deep2 {

// ============================================================================
// Aligned Memory Allocation
// ============================================================================
static float* alignedAlloc(size_t count) {
#ifdef _WIN32
    return (float*)_aligned_malloc(count * sizeof(float), 32);
#else
    return (float*)aligned_alloc(32, count * sizeof(float));
#endif
}

static void alignedFree(float* ptr) {
#ifdef _WIN32
    _aligned_free(ptr);
#else
    free(ptr);
#endif
}

// ============================================================================
// KVCache Implementation
// ============================================================================

KVCache::KVCache() : kCache(nullptr), vCache(nullptr), currentPos(0), initialized(false) {}

KVCache::~KVCache() {
    if (kCache) alignedFree(kCache);
    if (vCache) alignedFree(vCache);
}

bool KVCache::initialize(const KVCacheConfig& cfg) {
    config = cfg;
    
    size_t cacheSize = config.numLayers * config.maxSeqLen * 
                       config.numHeads * config.headDim;
    
    printf("[KVCache] Initializing: %zu layers, %zu max seq, %zu heads, %zu dim\n",
           config.numLayers, config.maxSeqLen, config.numHeads, config.headDim);
    printf("[KVCache] Total cache size: %.2f MB\n", cacheSize * 2 * sizeof(float) / (1024.0 * 1024.0));
    
    // Allocate K and V caches
    kCache = alignedAlloc(cacheSize);
    vCache = alignedAlloc(cacheSize);
    
    if (!kCache || !vCache) {
        printf("[KVCache] ERROR: Failed to allocate cache memory\n");
        return false;
    }
    
    // Zero initialize
    memset(kCache, 0, cacheSize * sizeof(float));
    memset(vCache, 0, cacheSize * sizeof(float));
    
    currentPos = 0;
    initialized = true;
    
    printf("[KVCache] Initialization complete\n");
    return true;
}

void KVCache::reset() {
    currentPos = 0;
    if (kCache && vCache) {
        size_t cacheSize = config.numLayers * config.maxSeqLen * 
                          config.numHeads * config.headDim;
        memset(kCache, 0, cacheSize * sizeof(float));
        memset(vCache, 0, cacheSize * sizeof(float));
    }
}

void KVCache::getKVPointers(size_t layer, size_t head, float** kPtr, float** vPtr) {
    if (!initialized || !kCache || !vCache) {
        *kPtr = nullptr;
        *vPtr = nullptr;
        return;
    }
    
    size_t offset = getHeadOffset(layer, head, currentPos);
    *kPtr = kCache + offset;
    *vPtr = vCache + offset;
}

const float* KVCache::getK(size_t layer, size_t head, size_t pos) const {
    if (!initialized || !kCache || pos >= config.maxSeqLen) return nullptr;
    return kCache + getHeadOffset(layer, head, pos);
}

const float* KVCache::getV(size_t layer, size_t head, size_t pos) const {
    if (!initialized || !vCache || pos >= config.maxSeqLen) return nullptr;
    return vCache + getHeadOffset(layer, head, pos);
}

void KVCache::advance() {
    if (currentPos < config.maxSeqLen) {
        currentPos++;
    }
}

size_t KVCache::memoryUsed() const {
    if (!initialized) return 0;
    return config.totalSize();
}

size_t KVCache::getLayerOffset(size_t layer) const {
    return layer * config.maxSeqLen * config.numHeads * config.headDim;
}

size_t KVCache::getHeadOffset(size_t layer, size_t head, size_t pos) const {
    return getLayerOffset(layer) + 
           pos * config.numHeads * config.headDim +
           head * config.headDim;
}

// ============================================================================
// Attention with KV Cache
// O(n) instead of O(n²)
// ============================================================================
void AttentionWithCache(const float* query,
                        const KVCache& cache,
                        size_t layer,
                        size_t head,
                        float* output,
                        size_t seqLen) {
    
    size_t headDim = cache.maxLength(); // Actually headDim
    // For simplicity, compute attention scores
    
    // Clear output
    memset(output, 0, headDim * sizeof(float));
    
    // For each previous position
    for (size_t pos = 0; pos < seqLen; ++pos) {
        const float* k = cache.getK(layer, head, pos);
        const float* v = cache.getV(layer, head, pos);
        
        if (!k || !v) continue;
        
        // Compute attention score: query · key
        float score = 0.0f;
        for (size_t i = 0; i < headDim; ++i) {
            score += query[i] * k[i];
        }
        
        // Scale
        score /= sqrtf((float)headDim);
        
        // Accumulate weighted value
        for (size_t i = 0; i < headDim; ++i) {
            output[i] += score * v[i];
        }
    }
}

} // namespace Deep2
