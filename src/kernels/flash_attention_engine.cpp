/*===========================================================================
 * flash_attention_engine.cpp
 * 
 * Flash Attention Engine Implementation (Fix #5)
 * 
 * High-level C++ wrapper around the AVX-512 ASM kernel
 *===========================================================================*/

#include "flash_attention.hpp"
#include "../telemetry/RawrXD_Telemetry_Fix4.hpp"
#include "../runtime/RawrXD_DeterministicPerformance.hpp"
#include <cstring>
#include <chrono>

namespace RawrXD {
namespace Kernels {

// SoftmaxState implementation
void SoftmaxState::Update(float local_max, float local_sum) {
    // Numerically stable online softmax update
    // m_new = max(m_old, local_max)
    // l_new = l_old * exp(m_old - m_new) + local_sum * exp(local_max - m_new)
    
    float m_new = std::max(m, local_max);
    
    // Compute rescaling factors
    float scale_old = std::exp(m - m_new);
    float scale_local = std::exp(local_max - m_new);
    
    // Update running sum
    l = l * scale_old + local_sum * scale_local;
    
    // Update max
    m = m_new;
}

// FlashAttentionConfig implementation
uint32_t FlashAttentionConfig::GetOptimalBlockSize() const {
    // Target 75% L2 utilization
    size_t targetBytes = (l2CacheSize * 3) / 4;
    size_t bytesPerToken = headDim * sizeof(float);
    size_t maxTokens = targetBytes / (numHeads * bytesPerToken);
    
    // Clamp to valid range and round to power of 2
    if (maxTokens >= 256) return 256;
    if (maxTokens >= 128) return 128;
    if (maxTokens >= 64) return 64;
    return 32;
}

// FlashAttentionEngine implementation
FlashAttentionEngine::FlashAttentionEngine() = default;

FlashAttentionEngine::~FlashAttentionEngine() {
    Shutdown();
}

bool FlashAttentionEngine::Initialize(const FlashAttentionConfig& config) {
    if (m_initialized) {
        Shutdown();
    }
    
    m_config = config;
    
    // Auto-detect optimal block size if not specified
    if (m_config.blockSize == 0) {
        m_config.blockSize = m_config.GetOptimalBlockSize();
    }
    
    // Clamp block size
    m_config.blockSize = std::max(FlashAttention::MIN_BC,
        std::min(m_config.blockSize, FlashAttention::MAX_BC));
    
    // Initialize softmax state for all heads
    m_softmaxState.resize(m_config.numHeads);
    for (auto& state : m_softmaxState) {
        state.Reset();
    }
    
    // Allocate aligned buffers
    if (!AllocateBuffers()) {
        return false;
    }
    
    m_initialized = true;
    return true;
}

void FlashAttentionEngine::Shutdown() {
    FreeBuffers();
    m_softmaxState.clear();
    m_initialized = false;
}

bool FlashAttentionEngine::AllocateBuffers() {
    size_t blockBytes = m_config.blockSize * m_config.headDim * sizeof(float);
    
    // Allocate 64-byte aligned buffers
    #ifdef _WIN32
    m_kBlockBuffer = (float*)_aligned_malloc(blockBytes, FlashAttention::ALIGNMENT);
    m_vBlockBuffer = (float*)_aligned_malloc(blockBytes, FlashAttention::ALIGNMENT);
    m_scoreBuffer = (float*)_aligned_malloc(m_config.blockSize * sizeof(float), FlashAttention::ALIGNMENT);
    #else
    m_kBlockBuffer = (float*)aligned_alloc(FlashAttention::ALIGNMENT, blockBytes);
    m_vBlockBuffer = (float*)aligned_alloc(FlashAttention::ALIGNMENT, blockBytes);
    m_scoreBuffer = (float*)aligned_alloc(FlashAttention::ALIGNMENT, m_config.blockSize * sizeof(float));
    #endif
    
    if (!m_kBlockBuffer || !m_vBlockBuffer || !m_scoreBuffer) {
        FreeBuffers();
        return false;
    }
    
    return true;
}

void FlashAttentionEngine::FreeBuffers() {
    #ifdef _WIN32
    if (m_kBlockBuffer) { _aligned_free(m_kBlockBuffer); m_kBlockBuffer = nullptr; }
    if (m_vBlockBuffer) { _aligned_free(m_vBlockBuffer); m_vBlockBuffer = nullptr; }
    if (m_scoreBuffer) { _aligned_free(m_scoreBuffer); m_scoreBuffer = nullptr; }
    #else
    if (m_kBlockBuffer) { free(m_kBlockBuffer); m_kBlockBuffer = nullptr; }
    if (m_vBlockBuffer) { free(m_vBlockBuffer); m_vBlockBuffer = nullptr; }
    if (m_scoreBuffer) { free(m_scoreBuffer); m_scoreBuffer = nullptr; }
    #endif
}

bool FlashAttentionEngine::ComputeDecode(
    uint32_t batchIdx,
    uint32_t seqPos,
    const float* Q,
    const float* K_cache,
    const float* V_cache,
    float* Output
) {
    if (!m_initialized) return false;
    
    // Enforce deterministic mode
    if (!RawrXD::DeterministicPerformance::IsLocked()) {
        return false;
    }
    
    auto startTime = std::chrono::high_resolution_clock::now();
    
    // Reset output accumulator
    std::memset(Output, 0, m_config.headDim * sizeof(float));
    
    // Process KV cache in blocks
    uint32_t Bc = m_config.blockSize;
    uint32_t numBlocks = (seqPos + Bc - 1) / Bc;
    
    for (uint32_t blockIdx = 0; blockIdx < numBlocks; ++blockIdx) {
        uint32_t blockStart = blockIdx * Bc;
        uint32_t blockEnd = std::min(blockStart + Bc, seqPos);
        uint32_t actualBlockSize = blockEnd - blockStart;
        
        // Load K/V block from cache
        // K_cache layout: [seq_len, head_dim]
        for (uint32_t i = 0; i < actualBlockSize; ++i) {
            const float* kSrc = K_cache + (blockStart + i) * m_config.headDim;
            const float* vSrc = V_cache + (blockStart + i) * m_config.headDim;
            
            std::memcpy(
                m_kBlockBuffer + i * m_config.headDim,
                kSrc,
                m_config.headDim * sizeof(float)
            );
            std::memcpy(
                m_vBlockBuffer + i * m_config.headDim,
                vSrc,
                m_config.headDim * sizeof(float)
            );
        }
        
        // Zero-pad remaining block if needed
        if (actualBlockSize < Bc) {
            size_t padOffset = actualBlockSize * m_config.headDim;
            size_t padBytes = (Bc - actualBlockSize) * m_config.headDim * sizeof(float);
            std::memset(m_kBlockBuffer + padOffset, 0, padBytes);
            std::memset(m_vBlockBuffer + padOffset, 0, padBytes);
        }
        
        // Call ASM kernel for this block
        for (uint32_t head = 0; head < m_config.numHeads; ++head) {
            const float* qHead = Q + head * m_config.headDim;
            float* outHead = Output + head * m_config.headDim;
            
            // Get softmax state for this head
            float state[2] = { m_softmaxState[head].m, m_softmaxState[head].l };
            
            FlashAttention_Kernel_AVX512(
                const_cast<float*>(qHead),
                m_kBlockBuffer,
                m_vBlockBuffer,
                outHead,
                state,
                Bc
            );
            
            // Update state
            m_softmaxState[head].m = state[0];
            m_softmaxState[head].l = state[1];
        }
    }
    
    // Finalize: divide by running sum
    for (uint32_t head = 0; head < m_config.numHeads; ++head) {
        float* outHead = Output + head * m_config.headDim;
        float l = m_softmaxState[head].l;
        
        if (l > 0) {
            float invL = 1.0f / l;
            for (uint32_t d = 0; d < m_config.headDim; ++d) {
                outHead[d] *= invL;
            }
        }
    }
    
    // Update metrics
    auto endTime = std::chrono::high_resolution_clock::now();
    double latencyUs = std::chrono::duration<double, std::micro>(endTime - startTime).count();
    
    m_metrics.avgLatencyUs = (m_metrics.avgLatencyUs * m_metrics.totalTokensProcessed + latencyUs)
        / (m_metrics.totalTokensProcessed + 1);
    m_metrics.totalTokensProcessed++;
    m_metrics.peakTPS = std::max(m_metrics.peakTPS, 1e6 / latencyUs);
    
    return true;
}

bool FlashAttentionEngine::ComputePrefill(
    uint32_t batchIdx,
    uint32_t seqLen,
    const float* Q,
    const float* K_cache,
    const float* V_cache,
    float* Output
) {
    // For prefill, we can process multiple query positions at once
    // This is essentially the same as decode but with Br > 1
    
    // For now, fall back to sequential decode
    // Full prefill optimization would use Br = 64 tile
    for (uint32_t pos = 0; pos < seqLen; ++pos) {
        const float* qPos = Q + pos * m_config.numHeads * m_config.headDim;
        float* outPos = Output + pos * m_config.numHeads * m_config.headDim;
        
        if (!ComputeDecode(batchIdx, pos + 1, qPos, K_cache, V_cache, outPos)) {
            return false;
        }
    }
    
    return true;
}

FlashAttentionEngine::Metrics FlashAttentionEngine::GetMetrics() const {
    return m_metrics;
}

bool FlashAttentionEngine::ValidateNumerical(
    const float* reference,
    const float* result,
    uint32_t numElements,
    float tolerance
) {
    float maxAbsError = 0.0f;
    float maxRelError = 0.0f;
    
    for (uint32_t i = 0; i < numElements; ++i) {
        float absError = std::abs(reference[i] - result[i]);
        maxAbsError = std::max(maxAbsError, absError);
        
        if (std::abs(reference[i]) > 1e-6f) {
            float relError = absError / std::abs(reference[i]);
            maxRelError = std::max(maxRelError, relError);
        }
    }
    
    return maxAbsError < tolerance && maxRelError < tolerance * 10;
}

} // namespace Kernels
} // namespace RawrXD
