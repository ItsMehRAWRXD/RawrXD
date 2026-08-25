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
    
    size_t kBytes = cacheSize * sizeof(float);
    size_t vBytes = cacheSize * sizeof(float);
    size_t totalBytes = kBytes + vBytes;
    printf("[KVCache] Initializing: layers=%zu maxSeqLen=%zu numHeads=%zu headDim=%zu\n",
           config.numLayers, config.maxSeqLen, config.numHeads, config.headDim);
    printf("[KVCache] Formula: layers * maxSeqLen * numHeads * headDim * 2(K+V) * sizeof(float)\n");
    printf("[KVCache]        = %zu * %zu * %zu * %zu * 2 * %zu\n",
           config.numLayers, config.maxSeqLen, config.numHeads, config.headDim, sizeof(float));
    printf("[KVCache]        = %zu bytes (K=%zu + V=%zu)\n", totalBytes, kBytes, vBytes);
    printf("[KVCache] Total cache size: %.2f MB\n", totalBytes / (1024.0 * 1024.0));
    
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
// AVX2-optimized dot product for Q*K^T
// ============================================================================
#ifdef __AVX2__
#include <immintrin.h>

static inline float avx2_dot_product(const float* a, const float* b, size_t n) {
    __m256 acc = _mm256_setzero_ps();
    size_t i = 0;
    
    // Process 8 floats at a time
    for (; i + 8 <= n; i += 8) {
        __m256 va = _mm256_loadu_ps(a + i);
        __m256 vb = _mm256_loadu_ps(b + i);
        acc = _mm256_fmadd_ps(va, vb, acc);
    }
    
    // Horizontal sum
    __m256 hsum = _mm256_hadd_ps(acc, acc);
    hsum = _mm256_hadd_ps(hsum, hsum);
    float result = _mm_cvtss_f32(_mm256_castps256_ps128(hsum)) + 
                   _mm_cvtss_f32(_mm256_extractf128_ps(hsum, 1));
    
    // Scalar tail
    for (; i < n; ++i) {
        result += a[i] * b[i];
    }
    return result;
}

// AVX2-optimized weighted accumulation: output += weight * values
static inline void avx2_weighted_accumulate(float* output, const float* values, float weight, size_t n) {
    __m256 wvec = _mm256_set1_ps(weight);
    size_t i = 0;
    
    for (; i + 8 <= n; i += 8) {
        __m256 out = _mm256_loadu_ps(output + i);
        __m256 val = _mm256_loadu_ps(values + i);
        out = _mm256_fmadd_ps(wvec, val, out);
        _mm256_storeu_ps(output + i, out);
    }
    
    for (; i < n; ++i) {
        output[i] += weight * values[i];
    }
}
#endif

// Fast approximate expf for softmax (available regardless of AVX2)
static inline float fast_expf(float x) {
    // Clamp to avoid overflow
    if (x > 88.0f) return 1e38f;
    if (x < -88.0f) return 0.0f;
    return expf(x);
}

// Forward declaration for fast_expf used in AttentionWithCache
static inline float fast_expf(float x);

// ============================================================================
// Attention with KV Cache
// Production AVX2-optimized scaled dot-product attention with softmax
// ============================================================================
void AttentionWithCache(const float* query,
                        const KVCache& cache,
                        size_t layer,
                        size_t head,
                        float* output,
                        size_t seqLen) {

    const size_t headDim  = cache.headDimSize();
    const float  scale    = 1.0f / sqrtf((float)headDim);
    // Use seqLen (the number of positions to attend to, including current)
    // rather than seqUsed (cache.currentLength) which may lag by one.
    const size_t attend   = seqLen;

    if (headDim == 0 || attend == 0) {
        memset(output, 0, headDim * sizeof(float));
        return;
    }

    // Allocate scores buffer (aligned for potential SIMD)
    float* scores = (float*)_aligned_malloc(attend * sizeof(float), 32);
    if (!scores) {
        memset(output, 0, headDim * sizeof(float));
        return;
    }

    // --- Pass 1: Compute Q*K^T scores with AVX2 dot products ---
    float maxScore = -1e38f;
    
#ifdef __AVX2__
    for (size_t pos = 0; pos < attend; ++pos) {
        const float* k = cache.getK(layer, head, pos);
        if (!k) { 
            scores[pos] = -1e38f; 
            continue; 
        }
        float dot = avx2_dot_product(query, k, headDim);
        scores[pos] = dot * scale;
        if (scores[pos] > maxScore) maxScore = scores[pos];
    }
#else
    // Scalar fallback
    for (size_t pos = 0; pos < attend; ++pos) {
        const float* k = cache.getK(layer, head, pos);
        if (!k) { scores[pos] = -1e38f; continue; }

        float dot = 0.0f;
        for (size_t i = 0; i < headDim; ++i)
            dot += query[i] * k[i];
        scores[pos] = dot * scale;
        if (scores[pos] > maxScore) maxScore = scores[pos];
    }
#endif

    // --- Pass 2: Online softmax with numerical stability ---
    // Use online softmax algorithm for better numerical stability
    float sumExp = 0.0f;
    for (size_t pos = 0; pos < attend; ++pos) {
        scores[pos] = fast_expf(scores[pos] - maxScore);
        sumExp += scores[pos];
    }
    if (sumExp < 1e-12f) sumExp = 1e-12f;
    
    // Normalize to get softmax probabilities
    float invSum = 1.0f / sumExp;
    for (size_t pos = 0; pos < attend; ++pos) {
        scores[pos] *= invSum;
    }

    // --- Pass 3: Weighted sum of values with AVX2 ---
    memset(output, 0, headDim * sizeof(float));
    
#ifdef __AVX2__
    for (size_t pos = 0; pos < attend; ++pos) {
        const float* v = cache.getV(layer, head, pos);
        if (!v) continue;
        avx2_weighted_accumulate(output, v, scores[pos], headDim);
    }
#else
    for (size_t pos = 0; pos < attend; ++pos) {
        const float* v = cache.getV(layer, head, pos);
        if (!v) continue;
        const float w = scores[pos];
        for (size_t i = 0; i < headDim; ++i)
            output[i] += w * v[i];
    }
#endif

    _aligned_free(scores);
}

} // namespace Deep2
