// ============================================================================
// KVCache.cpp - Key-Value Cache Implementation
// ============================================================================

#include "KVCache.h"
#include "AttnCertProbe.hpp"
#include <cstring>
#include <cstdio>
#include <cmath>
#include <cstdlib>
#include <cstdint>
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

KVCache::KVCache()
    : kCache(nullptr), vCache(nullptr), currentPos(0), allocatedSeq(0),
      virtualMaxSeq(0), initialized(false) {}

KVCache::~KVCache() {
    if (kCache) alignedFree(kCache);
    if (vCache) alignedFree(vCache);
}

bool KVCache::initialize(const KVCacheConfig& cfg) {
    config = cfg;
    virtualMaxSeq = cfg.maxSeqLen ? cfg.maxSeqLen : 1;
    allocatedSeq = virtualMaxSeq < 8 ? virtualMaxSeq : 8;

    size_t cacheSize = config.numLayers * allocatedSeq *
                       config.numHeads * config.headDim;

    size_t kBytes = cacheSize * sizeof(float);
    size_t vBytes = cacheSize * sizeof(float);
    size_t totalBytes = kBytes + vBytes;
    printf("[KVCache] Lazy pages: layers=%zu page=%zu virtualMax=%zu heads=%zu dim=%zu\n",
           config.numLayers, allocatedSeq, virtualMaxSeq, config.numHeads,
           config.headDim);
    printf("[KVCache] HOT_BYTES=%zu (not layers*maxSeq*heads)\n", totalBytes);
    
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
    if (currentPos >= allocatedSeq && currentPos < virtualMaxSeq)
        grow(currentPos + 8 < virtualMaxSeq ? currentPos + 8 : virtualMaxSeq);
    
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
    if (currentPos + 1 > allocatedSeq && currentPos + 1 <= virtualMaxSeq)
        grow(currentPos + 8 < virtualMaxSeq ? currentPos + 8 : virtualMaxSeq);
    if (currentPos < virtualMaxSeq)
        currentPos++;
}

bool KVCache::grow(size_t newMaxSeqLen) {
    if (!initialized || !kCache || !vCache) return false;
    if (newMaxSeqLen > virtualMaxSeq) virtualMaxSeq = newMaxSeqLen;
    if (newMaxSeqLen <= allocatedSeq) return true;
    const size_t oldMax = allocatedSeq;
    const size_t heads = config.numHeads;
    const size_t dim = config.headDim;
    const size_t layers = config.numLayers;
    const size_t newElems = layers * newMaxSeqLen * heads * dim;
    float* nk = alignedAlloc(newElems);
    float* nv = alignedAlloc(newElems);
    if (!nk || !nv) {
        if (nk) alignedFree(nk);
        if (nv) alignedFree(nv);
        return false;
    }
    memset(nk, 0, newElems * sizeof(float));
    memset(nv, 0, newElems * sizeof(float));
    // Layout: [layer][pos][head][dim] — copy each layer's used prefix
    for (size_t L = 0; L < layers; ++L) {
        for (size_t p = 0; p < currentPos && p < oldMax; ++p) {
            for (size_t h = 0; h < heads; ++h) {
                const size_t oldOff = L * oldMax * heads * dim + p * heads * dim + h * dim;
                const size_t newOff = L * newMaxSeqLen * heads * dim + p * heads * dim + h * dim;
                memcpy(nk + newOff, kCache + oldOff, dim * sizeof(float));
                memcpy(nv + newOff, vCache + oldOff, dim * sizeof(float));
            }
        }
    }
    alignedFree(kCache);
    alignedFree(vCache);
    kCache = nk;
    vCache = nv;
    allocatedSeq = newMaxSeqLen;
    config.maxSeqLen = virtualMaxSeq;
    printf("[KVCache] page grow %zu -> %zu hot (virtualMax=%zu pos=%zu)\n",
           oldMax, newMaxSeqLen, virtualMaxSeq, currentPos);
    return true;
}

size_t KVCache::memoryUsed() const {
    if (!initialized) return 0;
    return config.numLayers * allocatedSeq * config.numHeads * config.headDim *
           sizeof(float) * 2;
}

size_t KVCache::evictColdPages() {
    if (!initialized || allocatedSeq <= 8) return 0;
    const size_t keep = currentPos < 8 ? 8 : currentPos;
    if (keep >= allocatedSeq) return 0;
    const size_t before = memoryUsed();
    // Keep hot prefix; drop unused tail by shrinking allocation.
    const size_t oldMax = allocatedSeq;
    const size_t heads = config.numHeads;
    const size_t dim = config.headDim;
    const size_t layers = config.numLayers;
    const size_t newElems = layers * keep * heads * dim;
    float* nk = alignedAlloc(newElems);
    float* nv = alignedAlloc(newElems);
    if (!nk || !nv) {
        if (nk) alignedFree(nk);
        if (nv) alignedFree(nv);
        return 0;
    }
    memset(nk, 0, newElems * sizeof(float));
    memset(nv, 0, newElems * sizeof(float));
    for (size_t L = 0; L < layers; ++L) {
        for (size_t p = 0; p < currentPos && p < keep; ++p) {
            for (size_t h = 0; h < heads; ++h) {
                const size_t oldOff = L * oldMax * heads * dim + p * heads * dim + h * dim;
                const size_t newOff = L * keep * heads * dim + p * heads * dim + h * dim;
                memcpy(nk + newOff, kCache + oldOff, dim * sizeof(float));
                memcpy(nv + newOff, vCache + oldOff, dim * sizeof(float));
            }
        }
    }
    alignedFree(kCache);
    alignedFree(vCache);
    kCache = nk;
    vCache = nv;
    allocatedSeq = keep;
    return before > memoryUsed() ? before - memoryUsed() : 0;
}

size_t KVCache::getLayerOffset(size_t layer) const {
    return layer * allocatedSeq * config.numHeads * config.headDim;
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

static inline float fast_expf(float x) {
    if (x > 88.0f) return 1e38f;
    if (x < -88.0f) return 0.0f;
    return expf(x);
}

/* IEEE754 RNE f16 — match ggml / Deep2Engine cache-type f16. */
static inline float attnFp16ToF32(uint16_t h) {
    uint32_t sign = (h >> 15) & 1u, exp = (h >> 10) & 0x1Fu, mant = h & 0x3FFu, f;
    if (exp == 0) {
        if (!mant) f = sign << 31;
        else {
            int e = 0; while (!(mant & 0x400u)) { mant <<= 1; ++e; }
            mant &= 0x3FFu;
            f = (sign << 31) | ((uint32_t)(113 - e) << 23) | (mant << 13);
        }
    } else if (exp == 31) f = (sign << 31) | (0xFFu << 23) | (mant << 13);
    else f = (sign << 31) | ((exp + 127u - 15u) << 23) | (mant << 13);
    float r; memcpy(&r, &f, 4); return r;
}
static inline uint16_t attnF32ToFp16(float val) {
    uint32_t x; memcpy(&x, &val, 4);
    const uint32_t sign = (x >> 16) & 0x8000u, exp = (x >> 23) & 0xFFu, mant = x & 0x7FFFFFu;
    if (exp == 0xFFu) return (uint16_t)(sign | 0x7C00u | (mant ? 0x200u : 0u));
    const int e = (int)exp - 127 + 15;
    if (e >= 31) return (uint16_t)(sign | 0x7C00u);
    if (e <= 0) {
        if (e < -10) return (uint16_t)sign;
        uint32_t m = mant | 0x800000u; const int rs = 14 - e;
        uint32_t q = m >> rs, rem = m & ((1u << rs) - 1u), half = 1u << (rs - 1);
        if (rem > half || (rem == half && (q & 1u))) ++q;
        return (uint16_t)(sign | q);
    }
    uint32_t he = (uint32_t)e << 10, hm = mant >> 13, rem = mant & 0x1FFFu;
    if (rem > 0x1000u || (rem == 0x1000u && (hm & 1u))) {
        ++hm;
        if (hm == 0x400u) { hm = 0; he += 0x400u; if (he >= 0x7C00u) return (uint16_t)(sign | 0x7C00u); }
    }
    return (uint16_t)(sign | he | hm);
}
static inline float attnF16RT(float x) { return attnFp16ToF32(attnF32ToFp16(x)); }

// ============================================================================
// AttentionWithCache — T=1 host SDPA; T>=2 ggml flash_attn_ext F16 VKQ (OPTION_A)
// ============================================================================
void AttentionWithCache(const float* query,
                        const KVCache& cache,
                        size_t layer,
                        size_t head,
                        float* output,
                        size_t seqLen) {
    const size_t headDim = cache.headDimSize();
    const float scale = 1.0f / sqrtf((float)headDim);
    const size_t attend = seqLen;
    if (headDim == 0 || attend == 0) {
        memset(output, 0, headDim * sizeof(float));
        return;
    }

    /* OPTION_A: ggml flash_attn_ext F16 VKQ online mad (llama kqv_out T>=2). */
    if (attend >= 2) {
        static int s_faOnce = 0;
        if (s_faOnce == 0) {
            s_faOnce = 1;
            std::fprintf(stderr, "ATTN_GGML_FA_F16=1 attend=%zu headDim=%zu\n",
                         attend, headDim);
            std::fflush(stderr);
        }
        float* q16 = (float*)_aligned_malloc(headDim * sizeof(float), 32);
        uint16_t* vkq16 = (uint16_t*)_aligned_malloc(headDim * sizeof(uint16_t), 32);
        if (!q16 || !vkq16) {
            if (q16) _aligned_free(q16);
            if (vkq16) _aligned_free(vkq16);
            memset(output, 0, headDim * sizeof(float));
            return;
        }
        for (size_t i = 0; i < headDim; ++i) q16[i] = attnF16RT(query[i]);
        memset(vkq16, 0, headDim * sizeof(uint16_t));
        float M = -INFINITY, S = 0.0f;
        for (size_t pos = 0; pos < attend; ++pos) {
            const float* k = cache.getK(layer, head, pos);
            const float* v = cache.getV(layer, head, pos);
            if (!k || !v) continue;
            float dot = 0.0f;
            for (size_t i = 0; i < headDim; ++i) dot += q16[i] * attnF16RT(k[i]);
            const float s = dot * scale;
            const float Mold = M;
            float ms = 1.0f, vs = 1.0f;
            if (s > M) {
                M = s;
                ms = (Mold == -INFINITY) ? 0.0f : expf(Mold - M);
                vs = 1.0f;
                if (Mold != -INFINITY) {
                    for (size_t i = 0; i < headDim; ++i)
                        vkq16[i] = attnF32ToFp16(attnFp16ToF32(vkq16[i]) * ms);
                }
            } else {
                vs = expf(s - M);
            }
            for (size_t i = 0; i < headDim; ++i) {
                const float vv = attnF16RT(v[i]);
                vkq16[i] = attnF32ToFp16(attnFp16ToF32(vkq16[i]) + vv * vs);
            }
            S = S * ms + vs;
        }
        const float invS = (S == 0.0f) ? 0.0f : 1.0f / S;
        for (size_t i = 0; i < headDim; ++i)
            output[i] = attnFp16ToF32(vkq16[i]) * invS;
        _aligned_free(q16);
        _aligned_free(vkq16);
        return;
    }

    /* T=1: prior host SDPA (retain ATTN_PRE_O@pos0 BITEXACT). */
    float* scores = (float*)_aligned_malloc(attend * sizeof(float), 32);
    if (!scores) {
        memset(output, 0, headDim * sizeof(float));
        return;
    }
    float maxScore = -1e38f;
#ifdef __AVX2__
    for (size_t pos = 0; pos < attend; ++pos) {
        const float* k = cache.getK(layer, head, pos);
        if (!k) { scores[pos] = -1e38f; continue; }
        float dot = avx2_dot_product(query, k, headDim);
        scores[pos] = dot * scale;
        if (scores[pos] > maxScore) maxScore = scores[pos];
    }
#else
    for (size_t pos = 0; pos < attend; ++pos) {
        const float* k = cache.getK(layer, head, pos);
        if (!k) { scores[pos] = -1e38f; continue; }
        float dot = 0.0f;
        for (size_t i = 0; i < headDim; ++i) dot += query[i] * k[i];
        scores[pos] = dot * scale;
        if (scores[pos] > maxScore) maxScore = scores[pos];
    }
#endif
    if (layer == 0 && head == 0) {
        AttnCert::record(AttnCert::Stage::PreSoftmax, 0,
                         static_cast<std::uint32_t>(cache.currentLength()),
                         scores, attend, static_cast<double>(maxScore));
    }
    float sumExp = 0.0f;
    for (size_t pos = 0; pos < attend; ++pos) {
        scores[pos] = fast_expf(scores[pos] - maxScore);
        sumExp += scores[pos];
    }
    if (sumExp < 1e-12f) sumExp = 1e-12f;
    float invSum = 1.0f / sumExp;
    double sumCheck = 0.0;
    for (size_t pos = 0; pos < attend; ++pos) {
        scores[pos] *= invSum;
        sumCheck += scores[pos];
    }
    if (layer == 0 && head == 0) {
        AttnCert::record(AttnCert::Stage::Softmax, 0,
                         static_cast<std::uint32_t>(cache.currentLength()),
                         scores, attend, sumCheck);
    }
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
        for (size_t i = 0; i < headDim; ++i) output[i] += w * v[i];
    }
#endif
    _aligned_free(scores);
}

} // namespace Deep2
