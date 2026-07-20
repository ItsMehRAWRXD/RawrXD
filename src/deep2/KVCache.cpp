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
    if (kCache && vCache && currentPos > 0) {
        // Only zero the positions that were actually written
        size_t usedSize = config.numLayers * currentPos *
                          config.numHeads * config.headDim;
        memset(kCache, 0, usedSize * sizeof(float));
        memset(vCache, 0, usedSize * sizeof(float));
    }
    currentPos = 0;
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
// Proper scaled dot-product attention with softmax over cached positions
// ============================================================================
void AttentionWithCache(const float* query,
                        const KVCache& cache,
                        size_t layer,
                        size_t head,
                        float* output,
                        size_t seqLen) {

    // headDim comes from the cache config, not maxLength()
    const size_t headDim  = cache.headDimSize();
    const float  scale    = 1.0f / sqrtf((float)headDim);
    const size_t seqUsed  = cache.currentLength();
    const size_t attend   = (seqLen < seqUsed) ? seqLen : seqUsed;

    if (headDim == 0 || attend == 0) {
        memset(output, 0, headDim * sizeof(float));
        return;
    }

    // --- Pass 1: compute raw scores and running softmax max (online softmax) ---
    // Use a small VLA-style heap buffer to avoid stack overflow for large seqLen
    float* scores = new float[attend];

    float maxScore = -1e38f;
    for (size_t pos = 0; pos < attend; ++pos) {
        const float* k = cache.getK(layer, head, pos);
        if (!k) { scores[pos] = -1e38f; continue; }

        float dot = 0.0f;
        for (size_t i = 0; i < headDim; ++i)
            dot += query[i] * k[i];
        scores[pos] = dot * scale;
        if (scores[pos] > maxScore) maxScore = scores[pos];
    }

    // --- Pass 2: softmax denominator ---
    float sumExp = 0.0f;
    for (size_t pos = 0; pos < attend; ++pos) {
        scores[pos] = expf(scores[pos] - maxScore);
        sumExp += scores[pos];
    }
    if (sumExp < 1e-12f) sumExp = 1e-12f;

    // --- Pass 3: weighted sum of values ---
    memset(output, 0, headDim * sizeof(float));
    for (size_t pos = 0; pos < attend; ++pos) {
        const float* v = cache.getV(layer, head, pos);
        if (!v) continue;
        const float w = scores[pos] / sumExp;
        for (size_t i = 0; i < headDim; ++i)
            output[i] += w * v[i];
    }

    delete[] scores;
}

} // namespace Deep2
