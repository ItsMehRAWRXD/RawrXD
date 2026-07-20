//=============================================================================
// Fix 5A: KV Cache Layout Rewrite
// RawrXD IDE - High-Performance Inference
//=============================================================================
// Transforms KV cache from [K][V][head][token] to [token][head][K/V]
// Provides contiguous token stepping with prefetch optimization
//=============================================================================

#pragma once

#include <cstdint>
#include <cstddef>
#include <immintrin.h>

namespace RawrXD {
namespace Memory {

//=============================================================================
// KV Cache Layout Configuration
//=============================================================================
struct KVCacheConfig {
    uint32_t num_layers = 32;        // Number of transformer layers
    uint32_t num_heads = 32;         // Number of attention heads
    uint32_t head_dim = 128;         // Dimension per head
    uint32_t max_seq_len = 8192;     // Maximum sequence length
    uint32_t window_size = 2048;     // Sliding window size (0 = full)
    
    // Alignment
    static constexpr uint32_t CACHE_LINE_SIZE = 64;
    static constexpr uint32_t ALIGNMENT = 64;  // AVX-512 alignment
    
    // Prefetch distance (tokens ahead to prefetch)
    static constexpr uint32_t PREFETCH_DISTANCE = 4;
    
    // Calculate sizes with guaranteed 64-byte alignment
    size_t GetTokenStride() const {
        // [head][K/V][head_dim] per token
        size_t raw_size = num_heads * 2 * head_dim * sizeof(float);
        // Round up to nearest cache line (64 bytes)
        return (raw_size + CACHE_LINE_SIZE - 1) & ~(CACHE_LINE_SIZE - 1);
    }
    
    size_t GetTotalSize() const {
        return max_seq_len * GetTokenStride();
    }
    
    size_t GetLayerSize() const {
        return GetTotalSize();
    }
    
    // Validate alignment for given dimensions
    bool IsAligned() const {
        size_t head_kv_size = 2 * head_dim * sizeof(float);  // K+V per head
        size_t token_stride = num_heads * head_kv_size;
        return (token_stride % CACHE_LINE_SIZE) == 0;
    }
    
    // Get padding bytes per token
    size_t GetTokenPadding() const {
        size_t raw_size = num_heads * 2 * head_dim * sizeof(float);
        size_t aligned_size = GetTokenStride();
        return aligned_size - raw_size;
    }
};

//=============================================================================
// Optimized KV Cache Layout
// Layout: [token][head][K/V][dim]
//=============================================================================
class OptimizedKVCache {
public:
    // Constructor
    OptimizedKVCache(const KVCacheConfig& config);
    
    // Destructor
    ~OptimizedKVCache();
    
    // Disable copy
    OptimizedKVCache(const OptimizedKVCache&) = delete;
    OptimizedKVCache& operator=(const OptimizedKVCache&) = delete;
    
    // Enable move
    OptimizedKVCache(OptimizedKVCache&& other) noexcept;
    OptimizedKVCache& operator=(OptimizedKVCache&& other) noexcept;

    //=============================================================================
    // Core Access Methods
    //=============================================================================
    
    // Get pointer to K vector for specific token and head
    // Returns: Pointer to head_dim floats
    float* GetK(uint32_t token_idx, uint32_t head_idx);
    const float* GetK(uint32_t token_idx, uint32_t head_idx) const;
    
    // Get pointer to V vector for specific token and head
    // Returns: Pointer to head_dim floats
    float* GetV(uint32_t token_idx, uint32_t head_idx);
    const float* GetV(uint32_t token_idx, uint32_t head_idx) const;
    
    // Get pointer to both K and V (contiguous in memory)
    // Returns: Pointer to 2*head_dim floats (K followed by V)
    float* GetKV(uint32_t token_idx, uint32_t head_idx);
    const float* GetKV(uint32_t token_idx, uint32_t head_idx) const;

    //=============================================================================
    // Optimized Batch Access
    //=============================================================================
    
    // Prefetch tokens for upcoming attention computation
    // Prefetches [token_idx, token_idx + PREFETCH_DISTANCE)
    void PrefetchTokens(uint32_t start_token, uint32_t num_tokens) const;
    
    // Get contiguous block of tokens for a specific head
    // Optimized for attention Q*K^T computation
    const float* GetTokenBlock(uint32_t start_token, uint32_t num_tokens, 
                               uint32_t head_idx, bool is_k) const;
    
    // Copy tokens from another cache (for window sliding)
    void CopyTokens(const OptimizedKVCache& source, 
                    uint32_t src_start, uint32_t dst_start, 
                    uint32_t num_tokens);

    //=============================================================================
    // Window Management
    //=============================================================================
    
    // Get valid token range for sliding window
    void GetWindowRange(uint32_t current_seq_len, 
                        uint32_t& window_start, 
                        uint32_t& window_end) const;
    
    // Check if token is in current window
    bool IsTokenInWindow(uint32_t token_idx, uint32_t current_seq_len) const;
    
    // Rotate window (move oldest tokens out, make room for new)
    void RotateWindow(uint32_t new_tokens);

    //=============================================================================
    // Validation & Debug
    //=============================================================================
    
    // Verify cache integrity
    bool Validate() const;
    
    // Get memory layout info
    void GetLayoutInfo(std::string& info) const;
    
    // Calculate cache hit rate (for profiling)
    float GetCacheEfficiency() const;

    //=============================================================================
    // Comparison with Old Layout
    //=============================================================================
    
    // Calculate expected performance improvement
    static float CalculateExpectedSpeedup(uint32_t seq_len, uint32_t num_heads);

private:
    KVCacheConfig m_config;
    float* m_data = nullptr;
    size_t m_size = 0;
    
    // Statistics for profiling
    mutable uint64_t m_access_count = 0;
    mutable uint64_t m_prefetch_count = 0;
    
    // Calculate offset into data buffer
    size_t CalculateOffset(uint32_t token_idx, uint32_t head_idx, bool is_k) const;
    
    // Validate indices
    bool ValidateIndices(uint32_t token_idx, uint32_t head_idx) const;
};

//=============================================================================
// Legacy Layout (for comparison)
// Layout: [K][V][head][token][dim]
//=============================================================================
class LegacyKVCache {
public:
    LegacyKVCache(const KVCacheConfig& config);
    ~LegacyKVCache();
    
    float* GetK(uint32_t token_idx, uint32_t head_idx);
    float* GetV(uint32_t token_idx, uint32_t head_idx);
    
private:
    KVCacheConfig m_config;
    float* m_k_data = nullptr;
    float* m_v_data = nullptr;
};

//=============================================================================
// Inline Access Methods (Hot Path)
//=============================================================================
inline size_t OptimizedKVCache::CalculateOffset(uint32_t token_idx, 
                                                uint32_t head_idx, 
                                                bool is_k) const {
    // Layout: [token][head][K/V][dim]
    // Offset = token * (num_heads * 2 * head_dim) 
    //        + head * (2 * head_dim)
    //        + (is_k ? 0 : head_dim)
    
    const size_t token_stride = m_config.num_heads * 2 * m_config.head_dim;
    const size_t head_stride = 2 * m_config.head_dim;
    
    return token_idx * token_stride + head_idx * head_stride + (is_k ? 0 : m_config.head_dim);
}

inline float* OptimizedKVCache::GetK(uint32_t token_idx, uint32_t head_idx) {
    if (!ValidateIndices(token_idx, head_idx)) return nullptr;
    
    size_t offset = CalculateOffset(token_idx, head_idx, true);
    
    // Prefetch next tokens
    if (m_config.PREFETCH_DISTANCE > 0) {
        uint32_t next_token = token_idx + m_config.PREFETCH_DISTANCE;
        if (next_token < m_config.max_seq_len) {
            size_t prefetch_offset = CalculateOffset(next_token, head_idx, true);
            _mm_prefetch((const char*)(m_data + prefetch_offset), _MM_HINT_T1);
        }
    }
    
    m_access_count++;
    return m_data + offset;
}

inline const float* OptimizedKVCache::GetK(uint32_t token_idx, uint32_t head_idx) const {
    if (!ValidateIndices(token_idx, head_idx)) return nullptr;
    return m_data + CalculateOffset(token_idx, head_idx, true);
}

inline float* OptimizedKVCache::GetV(uint32_t token_idx, uint32_t head_idx) {
    if (!ValidateIndices(token_idx, head_idx)) return nullptr;
    
    size_t offset = CalculateOffset(token_idx, head_idx, false);
    
    // Prefetch next tokens
    if (m_config.PREFETCH_DISTANCE > 0) {
        uint32_t next_token = token_idx + m_config.PREFETCH_DISTANCE;
        if (next_token < m_config.max_seq_len) {
            size_t prefetch_offset = CalculateOffset(next_token, head_idx, false);
            _mm_prefetch((const char*)(m_data + prefetch_offset), _MM_HINT_T1);
        }
    }
    
    m_access_count++;
    return m_data + offset;
}

inline const float* OptimizedKVCache::GetV(uint32_t token_idx, uint32_t head_idx) const {
    if (!ValidateIndices(token_idx, head_idx)) return nullptr;
    return m_data + CalculateOffset(token_idx, head_idx, false);
}

inline float* OptimizedKVCache::GetKV(uint32_t token_idx, uint32_t head_idx) {
    // K and V are contiguous: K at offset, V at offset + head_dim
    return GetK(token_idx, head_idx);
}

inline const float* OptimizedKVCache::GetKV(uint32_t token_idx, uint32_t head_idx) const {
    return GetK(token_idx, head_idx);
}

inline bool OptimizedKVCache::ValidateIndices(uint32_t token_idx, uint32_t head_idx) const {
    return (token_idx < m_config.max_seq_len) && (head_idx < m_config.num_heads);
}

} // namespace Memory
} // namespace RawrXD
