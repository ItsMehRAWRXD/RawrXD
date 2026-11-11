/*===========================================================================
 * sliding_window_attention_nhwc.cpp
 * 
 * Sliding Window Attention optimized for NHWC memory layout
 * 
 * NHWC layout: [batch, seq, heads, head_dim] instead of [batch, heads, seq, head_dim]
 * Benefits:
 *   - Contiguous memory access for head_dim (64 bytes = 16 floats for AVX-512)
 *   - Better cache utilization when computing attention scores
 *   - Vectorized loads/stores without gather/scatter
 * 
 * Target: 1.5-2x throughput improvement (360→540 TPS)
 *===========================================================================*/

#include "sliding_window_attention.hpp"
#include "tensor_layout.hpp"
#include "avx512_kernels.hpp"
#include <cstring>
#include <immintrin.h>

namespace RawrXD {
namespace Kernels {

// NHWC layout dimensions
// Q/K/V: [batch, seq_len, num_heads, head_dim]
// Attention scores: [batch, num_heads, seq_len, window_size]

bool SlidingWindowAttentionNHWC::Initialize(
    uint32_t batchSize,
    uint32_t numHeads,
    uint32_t headDim,
    uint32_t windowSize,
    uint32_t maxSeqLength
) {
    m_batchSize = batchSize;
    m_numHeads = numHeads;
    m_headDim = headDim;
    m_windowSize = windowSize;
    m_maxSeqLength = maxSeqLength;
    
    // Align head_dim to 64 bytes for AVX-512
    m_headDimAligned = (headDim + 15) & ~15;  // Round up to multiple of 16 floats
    
    // Calculate strides for NHWC layout
    // Tensor shape: [N, H, W, C] where H=seq_len, W=num_heads, C=head_dim
    m_strideSeq = numHeads * m_headDimAligned;    // Stride to next sequence position
    m_strideHead = m_headDimAligned;               // Stride to next head
    m_strideBatch = maxSeqLength * m_strideSeq;      // Stride to next batch
    
    // Allocate aligned memory for Q/K/V caches
    size_t qkvSize = batchSize * maxSeqLength * numHeads * m_headDimAligned * sizeof(float);
    
    #ifdef _WIN32
    m_qBuffer = (float*)_aligned_malloc(qkvSize, 64);
    m_kBuffer = (float*)_aligned_malloc(qkvSize, 64);
    m_vBuffer = (float*)_aligned_malloc(qkvSize, 64);
    #else
    m_qBuffer = (float*)aligned_alloc(64, qkvSize);
    m_kBuffer = (float*)aligned_alloc(64, qkvSize);
    m_vBuffer = (float*)aligned_alloc(64, qkvSize);
    #endif
    
    if (!m_qBuffer || !m_kBuffer || !m_vBuffer) {
        Cleanup();
        return false;
    }
    
    // Zero initialize
    std::memset(m_qBuffer, 0, qkvSize);
    std::memset(m_kBuffer, 0, qkvSize);
    std::memset(m_vBuffer, 0, qkvSize);
    
    // Allocate attention scores buffer
    // Shape: [batch, num_heads, seq_len, window_size]
    size_t scoreSize = batchSize * numHeads * maxSeqLength * windowSize * sizeof(float);
    
    #ifdef _WIN32
    m_scoreBuffer = (float*)_aligned_malloc(scoreSize, 64);
    #else
    m_scoreBuffer = (float*)aligned_alloc(64, scoreSize);
    #endif
    
    if (!m_scoreBuffer) {
        Cleanup();
        return false;
    }
    std::memset(m_scoreBuffer, 0, scoreSize);
    
    m_initialized = true;
    return true;
}

void SlidingWindowAttentionNHWC::Cleanup() {
    #ifdef _WIN32
    if (m_qBuffer) { _aligned_free(m_qBuffer); m_qBuffer = nullptr; }
    if (m_kBuffer) { _aligned_free(m_kBuffer); m_kBuffer = nullptr; }
    if (m_vBuffer) { _aligned_free(m_vBuffer); m_vBuffer = nullptr; }
    if (m_scoreBuffer) { _aligned_free(m_scoreBuffer); m_scoreBuffer = nullptr; }
    #else
    if (m_qBuffer) { free(m_qBuffer); m_qBuffer = nullptr; }
    if (m_kBuffer) { free(m_kBuffer); m_kBuffer = nullptr; }
    if (m_vBuffer) { free(m_vBuffer); m_vBuffer = nullptr; }
    if (m_scoreBuffer) { free(m_scoreBuffer); m_scoreBuffer = nullptr; }
    #endif
    
    m_initialized = false;
}

// Get pointer to Q/K/V at specific position in NHWC layout
// Returns pointer to [head_dim] contiguous floats
float* SlidingWindowAttentionNHWC::GetQPtr(uint32_t batch, uint32_t seq, uint32_t head) {
    return m_qBuffer + batch * m_strideBatch + seq * m_strideSeq + head * m_strideHead;
}

float* SlidingWindowAttentionNHWC::GetKPtr(uint32_t batch, uint32_t seq, uint32_t head) {
    return m_kBuffer + batch * m_strideBatch + seq * m_strideSeq + head * m_strideHead;
}

float* SlidingWindowAttentionNHWC::GetVPtr(uint32_t batch, uint32_t seq, uint32_t head) {
    return m_vBuffer + batch * m_strideBatch + seq * m_strideSeq + head * m_strideHead;
}

// Compute attention scores for current position
// Uses NHWC layout for contiguous head_dim access
void SlidingWindowAttentionNHWC::ComputeAttentionScores(
    uint32_t batch,
    uint32_t seqPos,
    uint32_t head
) {
    float* q = GetQPtr(batch, seqPos, head);
    
    // Determine window range
    uint32_t windowStart = (seqPos > m_windowSize) ? (seqPos - m_windowSize) : 0;
    uint32_t windowLen = seqPos - windowStart;
    
    // Compute Q @ K^T for each position in window
    // In NHWC: K is contiguous in head_dim, so dot product is sequential access
    for (uint32_t kPos = windowStart; kPos < seqPos; ++kPos) {
        float* k = GetKPtr(batch, kPos, head);
        
        // Dot product using AVX-512
        __m512 sumVec = _mm512_setzero_ps();
        uint32_t d = 0;
        
        // Process 16 floats at a time (64 bytes)
        for (; d + 16 <= m_headDim; d += 16) {
            __m512 qVec = _mm512_loadu_ps(q + d);
            __m512 kVec = _mm512_loadu_ps(k + d);
            sumVec = _mm512_fmadd_ps(qVec, kVec, sumVec);
        }
        
        // Horizontal sum
        float score = _mm512_reduce_add_ps(sumVec);
        
        // Handle remainder (if head_dim not multiple of 16)
        for (; d < m_headDim; ++d) {
            score += q[d] * k[d];
        }
        
        // Scale by sqrt(head_dim)
        score /= std::sqrt(static_cast<float>(m_headDim));
        
        // Store score
        uint32_t scoreIdx = (batch * m_numHeads + head) * m_maxSeqLength * m_windowSize
                        + seqPos * m_windowSize + (kPos - windowStart);
        m_scoreBuffer[scoreIdx] = score;
    }
    
    // Apply softmax to scores
    SoftmaxScores(batch, seqPos, head, windowLen);
}

// Softmax over attention scores
void SlidingWindowAttentionNHWC::SoftmaxScores(
    uint32_t batch,
    uint32_t seqPos,
    uint32_t head,
    uint32_t windowLen
) {
    // Find max for numerical stability
    float maxScore = -std::numeric_limits<float>::infinity();
    for (uint32_t i = 0; i < windowLen; ++i) {
        uint32_t scoreIdx = (batch * m_numHeads + head) * m_maxSeqLength * m_windowSize
                        + seqPos * m_windowSize + i;
        maxScore = std::max(maxScore, m_scoreBuffer[scoreIdx]);
    }
    
    // Compute exp and sum
    float sumExp = 0.0f;
    for (uint32_t i = 0; i < windowLen; ++i) {
        uint32_t scoreIdx = (batch * m_numHeads + head) * m_maxSeqLength * m_windowSize
                        + seqPos * m_windowSize + i;
        float expScore = std::exp(m_scoreBuffer[scoreIdx] - maxScore);
        m_scoreBuffer[scoreIdx] = expScore;
        sumExp += expScore;
    }
    
    // Normalize
    float invSum = 1.0f / sumExp;
    for (uint32_t i = 0; i < windowLen; ++i) {
        uint32_t scoreIdx = (batch * m_numHeads + head) * m_maxSeqLength * m_windowSize
                        + seqPos * m_windowSize + i;
        m_scoreBuffer[scoreIdx] *= invSum;
    }
}

// Compute attention output: softmax(scores) @ V
// Uses NHWC layout for contiguous access
void SlidingWindowAttentionNHWC::ComputeAttentionOutput(
    uint32_t batch,
    uint32_t seqPos,
    uint32_t head,
    float* output
) {
    // Determine window range
    uint32_t windowStart = (seqPos > m_windowSize) ? (seqPos - m_windowSize) : 0;
    uint32_t windowLen = seqPos - windowStart;
    
    // Initialize output to zero
    for (uint32_t d = 0; d < m_headDim; ++d) {
        output[d] = 0.0f;
    }
    
    // Weighted sum of V vectors
    for (uint32_t vPos = windowStart; vPos < seqPos; ++vPos) {
        uint32_t scoreIdx = (batch * m_numHeads + head) * m_maxSeqLength * m_windowSize
                        + seqPos * m_windowSize + (vPos - windowStart);
        float score = m_scoreBuffer[scoreIdx];
        
        float* v = GetVPtr(batch, vPos, head);
        
        // Accumulate using AVX-512
        uint32_t d = 0;
        for (; d + 16 <= m_headDim; d += 16) {
            __m512 outVec = _mm512_loadu_ps(output + d);
            __m512 vVec = _mm512_loadu_ps(v + d);
            __m512 scoreVec = _mm512_set1_ps(score);
            outVec = _mm512_fmadd_ps(scoreVec, vVec, outVec);
            _mm512_storeu_ps(output + d, outVec);
        }
        
        // Handle remainder
        for (; d < m_headDim; ++d) {
            output[d] += score * v[d];
        }
    }
}

// Full attention forward pass for one position
bool SlidingWindowAttentionNHWC::Forward(
    uint32_t batch,
    uint32_t seqPos,
    const float* qInput,      // [head_dim] - already in NHWC format
    const float* kInput,      // [head_dim] - already in NHWC format
    const float* vInput,      // [head_dim] - already in NHWC format
    float* output             // [num_heads, head_dim] - output in NHWC format
) {
    if (!m_initialized) return false;
    
    // Copy Q/K/V to cache (already in NHWC layout)
    for (uint32_t head = 0; head < m_numHeads; ++head) {
        float* qCache = GetQPtr(batch, seqPos, head);
        float* kCache = GetKPtr(batch, seqPos, head);
        float* vCache = GetVPtr(batch, seqPos, head);
        
        // Copy from input (assumes input is [num_heads, head_dim] contiguous)
        std::memcpy(qCache, qInput + head * m_headDim, m_headDim * sizeof(float));
        std::memcpy(kCache, kInput + head * m_headDim, m_headDim * sizeof(float));
        std::memcpy(vCache, vInput + head * m_headDim, m_headDim * sizeof(float));
    }
    
    // Compute attention for each head
    for (uint32_t head = 0; head < m_numHeads; ++head) {
        // Compute attention scores
        ComputeAttentionScores(batch, seqPos, head);
        
        // Compute output
        float* outPtr = output + head * m_headDim;
        ComputeAttentionOutput(batch, seqPos, head, outPtr);
    }
    
    return true;
}

// C exports for MASM integration
extern "C" {

__declspec(dllexport) void* RawrXD_SlidingWindowAttentionNHWC_Create() {
    return new RawrXD::Kernels::SlidingWindowAttentionNHWC();
}

__declspec(dllexport) int RawrXD_SlidingWindowAttentionNHWC_Init(
    void* handle,
    uint32_t batchSize,
    uint32_t numHeads,
    uint32_t headDim,
    uint32_t windowSize,
    uint32_t maxSeqLength
) {
    auto* attn = static_cast<RawrXD::Kernels::SlidingWindowAttentionNHWC*>(handle);
    return attn->Initialize(batchSize, numHeads, headDim, windowSize, maxSeqLength) ? 0 : -1;
}

__declspec(dllexport) int RawrXD_SlidingWindowAttentionNHWC_Forward(
    void* handle,
    uint32_t batch,
    uint32_t seqPos,
    const float* qInput,
    const float* kInput,
    const float* vInput,
    float* output
) {
    auto* attn = static_cast<RawrXD::Kernels::SlidingWindowAttentionNHWC*>(handle);
    return attn->Forward(batch, seqPos, qInput, kInput, vInput, output) ? 0 : -1;
}

__declspec(dllexport) void RawrXD_SlidingWindowAttentionNHWC_Destroy(void* handle) {
    delete static_cast<RawrXD::Kernels::SlidingWindowAttentionNHWC*>(handle);
}

} // extern "C"

} // namespace Kernels
} // namespace RawrXD
