/**
 * @file attention_kernels.cpp
 * @brief Optimized attention mechanisms (FlashAttention, etc.)
 *
 * Implements:
 * - Standard multi-head attention (AVX2 FMA, thread-local scratchpads)
 * - FlashAttention-style memory-efficient attention
 * - Grouped-query attention (GQA)
 * - Sliding window attention
 *
 * @author RawrXD Inference Team
 * @version 2.0.0
 */

#include "attention_kernels.h"
#include "llama_kernel_ops.h"
#include <cmath>
#include <algorithm>
#include <immintrin.h>   // AVX2 / AVX-512 intrinsics
#include <malloc.h>      // _aligned_malloc / _aligned_free

namespace RawrXD::Inference {

// ============================================================================
// MASM extern: accumulate_row_avx2_asm (zero-prologue FMA kernel)
// R9 = nextVRow ptr for software prefetch (nullptr = skip)
// ============================================================================
extern "C" void accumulate_row_avx2_asm(float* out, const float* vRow,
                                         int headDim, float weight,
                                         const float* nextVRow);

// ============================================================================
// Thread-Local Aligned Scratchpad (eliminates heap tax inside hot loops)
// ============================================================================
class ThreadLocalScratchpad {
public:
    static float* acquire(size_t count) {
        thread_local ThreadLocalScratchpad instance;
        if (count > instance.capacity_) {
            instance.grow(count);
        }
        return instance.buffer_;
    }
private:
    float* buffer_ = nullptr;
    size_t capacity_ = 0;

    void grow(size_t count) {
        if (buffer_) _aligned_free(buffer_);
        capacity_ = count;
        buffer_ = static_cast<float*>(_aligned_malloc(count * sizeof(float), 32));
    }

    ~ThreadLocalScratchpad() {
        if (buffer_) _aligned_free(buffer_);
    }
};

// ============================================================================
// AVX2 FMA Dot Product (8 floats / cycle, 2x unroll for ILP)
// ============================================================================
inline float dot_product_avx2(const float* __restrict a,
                              const float* __restrict b,
                              int dim) {
    __m256 sum0 = _mm256_setzero_ps();
    __m256 sum1 = _mm256_setzero_ps();
    int i = 0;

    // 2x unrolled AVX2 FMA loop with software prefetching
    for (; i <= dim - 16; i += 16) {
        __m256 va0 = _mm256_loadu_ps(a + i);
        __m256 vb0 = _mm256_loadu_ps(b + i);
        sum0 = _mm256_fmadd_ps(va0, vb0, sum0);

        __m256 va1 = _mm256_loadu_ps(a + i + 8);
        __m256 vb1 = _mm256_loadu_ps(b + i + 8);
        sum1 = _mm256_fmadd_ps(va1, vb1, sum1);

        // Prefetch next cache line to hide DRAM latency
        _mm_prefetch(reinterpret_cast<const char*>(a + i + 32), _MM_HINT_T0);
        _mm_prefetch(reinterpret_cast<const char*>(b + i + 32), _MM_HINT_T0);
    }

    // Merge partial sums
    sum0 = _mm256_add_ps(sum0, sum1);

    // Remaining 8-element chunk
    for (; i <= dim - 8; i += 8) {
        __m256 va = _mm256_loadu_ps(a + i);
        __m256 vb = _mm256_loadu_ps(b + i);
        sum0 = _mm256_fmadd_ps(va, vb, sum0);
    }

    // Horizontal reduction
    float res[8];
    _mm256_storeu_ps(res, sum0);
    float total = res[0] + res[1] + res[2] + res[3] +
                  res[4] + res[5] + res[6] + res[7];

    // Scalar tail
    for (; i < dim; ++i) {
        total += a[i] * b[i];
    }
    return total;
}

// ============================================================================
// AVX2 Vectorized Softmax Row (loads/stores 8 floats at a time)
// ============================================================================
inline void softmax_row_avx2(float* __restrict row, int len) {
    // --- Pass 1: find max ---
    float maxVal = row[0];
    int i = 1;
    for (; i <= len - 8; i += 8) {
        __m256 v = _mm256_loadu_ps(row + i);
        // Horizontal max is expensive; do scalar max of partials for now
        float tmp[8];
        _mm256_storeu_ps(tmp, v);
        for (int j = 0; j < 8; ++j) maxVal = std::max(maxVal, tmp[j]);
    }
    for (; i < len; ++i) maxVal = std::max(maxVal, row[i]);

    // --- Pass 2: exp and sum ---
    float sum = 0.0f;
    for (int j = 0; j < len; ++j) {
        row[j] = std::exp(row[j] - maxVal);
        sum += row[j];
    }

    // --- Pass 3: normalize ---
    float invSum = 1.0f / sum;
    i = 0;
    __m256 vInvSum = _mm256_set1_ps(invSum);
    for (; i <= len - 8; i += 8) {
        __m256 v = _mm256_loadu_ps(row + i);
        v = _mm256_mul_ps(v, vInvSum);
        _mm256_storeu_ps(row + i, v);
    }
    for (; i < len; ++i) row[i] *= invSum;
}

// ============================================================================
// AVX2 Weighted Row Accumulator: out += weight * V_row
// Thin wrapper around MASM kernel (zero prologue/epilogue)
// nextVRow = prefetch target for the upcoming V row (nullptr = skip)
// ============================================================================
inline void accumulate_row_avx2(float* __restrict out,
                                const float* __restrict vRow,
                                float weight,
                                int headDim,
                                const float* nextVRow = nullptr) {
    accumulate_row_avx2_asm(out, vRow, headDim, weight, nextVRow);
}

// ============================================================================
// Multi-Head Attention
// ============================================================================

void multi_head_attention(const float* query, const float* key, const float* value,
                         float* output,
                         int batchSize, int seqLen, int numHeads, int headDim,
                         const float* mask, float scale) {
    int totalHeads = batchSize * numHeads;

    #pragma omp parallel for schedule(static)
    for (int h = 0; h < totalHeads; ++h) {
        int b = h / numHeads;

        const float* qHead = query + h * seqLen * headDim;
        const float* kHead = key   + h * seqLen * headDim;
        const float* vHead = value + h * seqLen * headDim;
        float* outHead = output + h * seqLen * headDim;

        // --- Tax-Free: thread-local aligned scratchpad (no heap inside loop) ---
        float* scores = ThreadLocalScratchpad::acquire(seqLen * seqLen);

        // Compute attention scores: Q @ K^T  (AVX2 FMA dot product)
        for (int i = 0; i < seqLen; ++i) {
            for (int j = 0; j < seqLen; ++j) {
                float dot = dot_product_avx2(
                    qHead + i * headDim,
                    kHead + j * headDim,
                    headDim);
                scores[i * seqLen + j] = dot * scale;
            }
        }

        // Apply mask if provided
        if (mask) {
            for (int i = 0; i < seqLen; ++i) {
                for (int j = 0; j < seqLen; ++j) {
                    if (mask[b * seqLen * seqLen + i * seqLen + j] <= 0.0f) {
                        scores[i * seqLen + j] = -std::numeric_limits<float>::infinity();
                    }
                }
            }
        }

        // Softmax over rows (AVX2 vectorized)
        for (int i = 0; i < seqLen; ++i) {
            softmax_row_avx2(scores + i * seqLen, seqLen);
        }

        // Apply attention to values: scores @ V (AVX2 weighted row accumulation)
        for (int i = 0; i < seqLen; ++i) {
            float* outRow = outHead + i * headDim;
            // Zero-init output row via AVX2 stores (negligible vs FMA work)
            int d = 0;
            __m256 zero = _mm256_setzero_ps();
            for (; d <= headDim - 8; d += 8) {
                _mm256_storeu_ps(outRow + d, zero);
            }
            for (; d < headDim; ++d) outRow[d] = 0.0f;

            for (int j = 0; j < seqLen; ++j) {
                const float* nextVRow = (j + 1 < seqLen)
                    ? vHead + (j + 1) * headDim
                    : nullptr;
                accumulate_row_avx2(outRow,
                                    vHead + j * headDim,
                                    scores[i * seqLen + j],
                                    headDim,
                                    nextVRow);
            }
        }
    }
}

// ============================================================================
// FlashAttention (Memory-Efficient)
// ============================================================================

void flash_attention(const float* query, const float* key, const float* value,
                    float* output,
                    int batchSize, int seqLen, int numHeads, int headDim,
                    const float* mask, float scale, int blockSize) {
    int totalHeads = batchSize * numHeads;
    
    #pragma omp parallel for schedule(static)
    for (int h = 0; h < totalHeads; ++h) {
        int b = h / numHeads;
        
        const float* qHead = query + h * seqLen * headDim;
        const float* kHead = key + h * seqLen * headDim;
        const float* vHead = value + h * seqLen * headDim;
        float* outHead = output + h * seqLen * headDim;
        
        // Process in blocks for memory efficiency
        for (int qBlock = 0; qBlock < seqLen; qBlock += blockSize) {
            int qBlockEnd = std::min(qBlock + blockSize, seqLen);
            
            for (int kBlock = 0; kBlock < seqLen; kBlock += blockSize) {
                int kBlockEnd = std::min(kBlock + blockSize, seqLen);
                
                // Compute block of attention scores
                for (int i = qBlock; i < qBlockEnd; ++i) {
                    // Online softmax for numerical stability
                    float maxVal = -std::numeric_limits<float>::infinity();
                    
                    for (int j = kBlock; j < kBlockEnd; ++j) {
                        if (mask && mask[b * seqLen * seqLen + i * seqLen + j] <= 0.0f) {
                            continue;
                        }
                        
                        float dot = 0.0f;
                        for (int d = 0; d < headDim; ++d) {
                            dot += qHead[i * headDim + d] * kHead[j * headDim + d];
                        }
                        maxVal = std::max(maxVal, dot * scale);
                    }
                    
                    // Compute softmax and accumulate output
                    float sum = 0.0f;
                    std::vector<float> weights(kBlockEnd - kBlock);
                    
                    for (int j = kBlock; j < kBlockEnd; ++j) {
                        if (mask && mask[b * seqLen * seqLen + i * seqLen + j] <= 0.0f) {
                            weights[j - kBlock] = 0.0f;
                            continue;
                        }
                        
                        float dot = 0.0f;
                        for (int d = 0; d < headDim; ++d) {
                            dot += qHead[i * headDim + d] * kHead[j * headDim + d];
                        }
                        
                        weights[j - kBlock] = std::exp(dot * scale - maxVal);
                        sum += weights[j - kBlock];
                    }
                    
                    // Apply to values (AVX2 weighted row accumulation)
                    if (sum > 0.0f) {
                        float invSum = 1.0f / sum;
                        for (int j = kBlock; j < kBlockEnd; ++j) {
                            float w = weights[j - kBlock] * invSum;
                            const float* nextVRow = (j + 1 < kBlockEnd)
                                ? vHead + (j + 1) * headDim
                                : nullptr;
                            accumulate_row_avx2(outHead + i * headDim,
                                                vHead + j * headDim,
                                                w, headDim,
                                                nextVRow);
                        }
                    }
                }
            }
        }
    }
}

// ============================================================================
// Grouped-Query Attention (GQA)
// ============================================================================

void grouped_query_attention(const float* query, const float* key, const float* value,
                            float* output,
                            int batchSize, int seqLen, int numQHeads, int numKVHeads,
                            int headDim, const float* mask, float scale) {
    int headsPerKV = numQHeads / numKVHeads;
    
    #pragma omp parallel for schedule(static)
    for (int b = 0; b < batchSize; ++b) {
        for (int qHead = 0; qHead < numQHeads; ++qHead) {
            int kvHead = qHead / headsPerKV;
            
            const float* qHeadPtr = query + ((b * numQHeads + qHead) * seqLen * headDim);
            const float* kHeadPtr = key + ((b * numKVHeads + kvHead) * seqLen * headDim);
            const float* vHeadPtr = value + ((b * numKVHeads + kvHead) * seqLen * headDim);
            float* outHeadPtr = output + ((b * numQHeads + qHead) * seqLen * headDim);
            
            // Compute attention scores
            std::vector<float> scores(seqLen * seqLen);
            for (int i = 0; i < seqLen; ++i) {
                for (int j = 0; j < seqLen; ++j) {
                    float dot = 0.0f;
                    for (int d = 0; d < headDim; ++d) {
                        dot += qHeadPtr[i * headDim + d] * kHeadPtr[j * headDim + d];
                    }
                    scores[i * seqLen + j] = dot * scale;
                }
            }
            
            // Apply mask
            if (mask) {
                for (int i = 0; i < seqLen; ++i) {
                    for (int j = 0; j < seqLen; ++j) {
                        if (mask[b * seqLen * seqLen + i * seqLen + j] <= 0.0f) {
                            scores[i * seqLen + j] = -std::numeric_limits<float>::infinity();
                        }
                    }
                }
            }
            
            // Softmax
            for (int i = 0; i < seqLen; ++i) {
                float maxVal = scores[i * seqLen];
                for (int j = 1; j < seqLen; ++j) {
                    maxVal = std::max(maxVal, scores[i * seqLen + j]);
                }
                
                float sum = 0.0f;
                for (int j = 0; j < seqLen; ++j) {
                    scores[i * seqLen + j] = std::exp(scores[i * seqLen + j] - maxVal);
                    sum += scores[i * seqLen + j];
                }
                
                float invSum = 1.0f / sum;
                for (int j = 0; j < seqLen; ++j) {
                    scores[i * seqLen + j] *= invSum;
                }
            }
            
            // Apply to values (AVX2 weighted row accumulation)
            for (int i = 0; i < seqLen; ++i) {
                float* outRow = outHeadPtr + i * headDim;
                int d = 0;
                __m256 zero = _mm256_setzero_ps();
                for (; d <= headDim - 8; d += 8) {
                    _mm256_storeu_ps(outRow + d, zero);
                }
                for (; d < headDim; ++d) outRow[d] = 0.0f;

                for (int j = 0; j < seqLen; ++j) {
                    const float* nextVRow = (j + 1 < seqLen)
                        ? vHeadPtr + (j + 1) * headDim
                        : nullptr;
                    accumulate_row_avx2(outRow,
                                        vHeadPtr + j * headDim,
                                        scores[i * seqLen + j],
                                        headDim,
                                        nextVRow);
                }
            }
        }
    }
}

// ============================================================================
// Sliding Window Attention
// ============================================================================

void sliding_window_attention(const float* query, const float* key, const float* value,
                             float* output,
                             int batchSize, int seqLen, int numHeads, int headDim,
                             int windowSize, float scale) {
    int totalHeads = batchSize * numHeads;
    
    #pragma omp parallel for schedule(static)
    for (int h = 0; h < totalHeads; ++h) {
        int b = h / numHeads;
        
        const float* qHead = query + h * seqLen * headDim;
        const float* kHead = key + h * seqLen * headDim;
        const float* vHead = value + h * seqLen * headDim;
        float* outHead = output + h * seqLen * headDim;
        
        for (int i = 0; i < seqLen; ++i) {
            // Only attend to tokens within window
            int windowStart = std::max(0, i - windowSize);
            int windowEnd = std::min(seqLen, i + windowSize + 1);
            int windowLen = windowEnd - windowStart;
            
            // Compute attention scores within window
            std::vector<float> scores(windowLen);
            float maxVal = -std::numeric_limits<float>::infinity();
            
            for (int j = windowStart; j < windowEnd; ++j) {
                float dot = 0.0f;
                for (int d = 0; d < headDim; ++d) {
                    dot += qHead[i * headDim + d] * kHead[j * headDim + d];
                }
                scores[j - windowStart] = dot * scale;
                maxVal = std::max(maxVal, scores[j - windowStart]);
            }
            
            // Softmax
            float sum = 0.0f;
            for (int j = 0; j < windowLen; ++j) {
                scores[j] = std::exp(scores[j] - maxVal);
                sum += scores[j];
            }
            
            float invSum = 1.0f / sum;
            
            // Apply to values (AVX2 weighted row accumulation)
            {
                float* outRow = outHead + i * headDim;
                int d = 0;
                __m256 zero = _mm256_setzero_ps();
                for (; d <= headDim - 8; d += 8) {
                    _mm256_storeu_ps(outRow + d, zero);
                }
                for (; d < headDim; ++d) outRow[d] = 0.0f;

                for (int j = windowStart; j < windowEnd; ++j) {
                    float w = scores[j - windowStart] * invSum;
                    const float* nextVRow = (j + 1 < windowEnd)
                        ? vHead + (j + 1) * headDim
                        : nullptr;
                    accumulate_row_avx2(outRow,
                                        vHead + j * headDim,
                                        w, headDim,
                                        nextVRow);
                }
            }
        }
    }
}

// ============================================================================
// KV Cache Attention (for autoregressive generation)
// ============================================================================

void kv_cache_attention(const float* query,
                       const float* keyCache, const float* valueCache,
                       float* output,
                       int batchSize, int numHeads, int headDim,
                       int cacheLen, int seqLen,
                       float scale) {
    int totalHeads = batchSize * numHeads;
    
    #pragma omp parallel for schedule(static)
    for (int h = 0; h < totalHeads; ++h) {
        const float* qHead = query + h * seqLen * headDim;
        const float* kHead = keyCache + h * cacheLen * headDim;
        const float* vHead = valueCache + h * cacheLen * headDim;
        float* outHead = output + h * seqLen * headDim;
        
        for (int i = 0; i < seqLen; ++i) {
            // Compute attention scores against cache
            std::vector<float> scores(cacheLen);
            float maxVal = -std::numeric_limits<float>::infinity();
            
            for (int j = 0; j < cacheLen; ++j) {
                float dot = 0.0f;
                for (int d = 0; d < headDim; ++d) {
                    dot += qHead[i * headDim + d] * kHead[j * headDim + d];
                }
                scores[j] = dot * scale;
                maxVal = std::max(maxVal, scores[j]);
            }
            
            // Softmax
            float sum = 0.0f;
            for (int j = 0; j < cacheLen; ++j) {
                scores[j] = std::exp(scores[j] - maxVal);
                sum += scores[j];
            }
            
            float invSum = 1.0f / sum;
            
            // Apply to values (AVX2 weighted row accumulation)
            {
                float* outRow = outHead + i * headDim;
                int d = 0;
                __m256 zero = _mm256_setzero_ps();
                for (; d <= headDim - 8; d += 8) {
                    _mm256_storeu_ps(outRow + d, zero);
                }
                for (; d < headDim; ++d) outRow[d] = 0.0f;

                for (int j = 0; j < cacheLen; ++j) {
                    float w = scores[j] * invSum;
                    const float* nextVRow = (j + 1 < cacheLen)
                        ? vHead + (j + 1) * headDim
                        : nullptr;
                    accumulate_row_avx2(outRow,
                                        vHead + j * headDim,
                                        w, headDim,
                                        nextVRow);
                }
            }
        }
    }
}

} // namespace RawrXD::Inference
