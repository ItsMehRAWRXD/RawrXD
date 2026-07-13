// ============================================================================
// KV Cache Optimizer
// ============================================================================
// Optimizes KV cache memory layout for better locality and bandwidth
// ============================================================================

#pragma once

#include <cstdint>
#include <vector>
#include <cstring>
#include <algorithm>

namespace seg {

// Cache line size (64 bytes on x86_64)
constexpr size_t CACHE_LINE_SIZE = 64;
constexpr size_t FLOATS_PER_CACHE_LINE = CACHE_LINE_SIZE / sizeof(float);

// ============================================================================
// Optimized KV Cache Layout
// ============================================================================
// Layout: [seq_len][num_kv_heads][head_dim] but with cache-line alignment
// This ensures that when we access a position, we get contiguous data
// ============================================================================
class OptimizedKVCache {
public:
    OptimizedKVCache() = default;
    
    // Initialize with optimized layout
    bool Initialize(uint32_t max_seq_len, uint32_t num_kv_heads, uint32_t head_dim);
    
    // Reset cache (clear without deallocating)
    void Reset();
    
    // Get pointer to K cache for a specific position
    // Returns cache-line aligned pointer
    float* GetK(uint32_t seq_pos, uint32_t kv_head);
    const float* GetK(uint32_t seq_pos, uint32_t kv_head) const;
    
    // Get pointer to V cache for a specific position
    float* GetV(uint32_t seq_pos, uint32_t kv_head);
    const float* GetV(uint32_t seq_pos, uint32_t kv_head) const;
    
    // Get stride between sequence positions (for vectorized access)
    size_t GetSeqStride() const { return seq_stride_; }
    
    // Current sequence length
    uint32_t GetSeqLen() const { return current_seq_len_; }
    void SetSeqLen(uint32_t len) { current_seq_len_ = len; }
    void IncrementSeqLen() { current_seq_len_++; }
    
    // Memory statistics
    size_t GetMemoryUsage() const;
    float GetCacheHitRate() const;  // Simulated
    
private:
    // Aligned storage
    std::vector<float> k_cache_;
    std::vector<float> v_cache_;
    
    // Dimensions
    uint32_t max_seq_len_ = 0;
    uint32_t num_kv_heads_ = 0;
    uint32_t head_dim_ = 0;
    uint32_t current_seq_len_ = 0;
    
    // Strides for indexing
    size_t seq_stride_ = 0;      // Bytes between sequence positions
    size_t head_stride_ = 0;     // Bytes between heads
    
    // Align dimension to cache line
    static uint32_t AlignToCacheLine(uint32_t dim);
};

// ============================================================================
// Standard KV Cache (for comparison)
// ============================================================================
class StandardKVCache {
public:
    StandardKVCache() = default;
    
    bool Initialize(uint32_t max_seq_len, uint32_t num_kv_heads, uint32_t head_dim);
    void Reset();
    
    float* GetK(uint32_t seq_pos, uint32_t kv_head);
    const float* GetK(uint32_t seq_pos, uint32_t kv_head) const;
    float* GetV(uint32_t seq_pos, uint32_t kv_head);
    const float* GetV(uint32_t seq_pos, uint32_t kv_head) const;
    
    uint32_t GetSeqLen() const { return current_seq_len_; }
    void SetSeqLen(uint32_t len) { current_seq_len_ = len; }
    void IncrementSeqLen() { current_seq_len_++; }
    
    size_t GetMemoryUsage() const;
    
private:
    std::vector<float> k_cache_;
    std::vector<float> v_cache_;
    
    uint32_t max_seq_len_ = 0;
    uint32_t num_kv_heads_ = 0;
    uint32_t head_dim_ = 0;
    uint32_t current_seq_len_ = 0;
};

// ============================================================================
// Attention with Optimized KV Cache
// ============================================================================
void ComputeAttentionOptimized(
    const float* query,           // [num_heads, head_dim]
    const OptimizedKVCache& kv_cache,
    uint32_t num_heads,
    uint32_t num_kv_heads,
    uint32_t head_dim,
    uint32_t seq_len,
    float* output                 // [num_heads, head_dim]
);

void ComputeAttentionStandard(
    const float* query,
    const StandardKVCache& kv_cache,
    uint32_t num_heads,
    uint32_t num_kv_heads,
    uint32_t head_dim,
    uint32_t seq_len,
    float* output
);

} // namespace seg
