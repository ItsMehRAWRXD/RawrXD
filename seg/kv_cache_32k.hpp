// ============================================================================
// 32K Context Optimized KV Cache
// ============================================================================
// Memory-efficient KV cache with compression for 32k context
// ============================================================================

#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>
#include <memory>
#include "int8_gemm.hpp"

namespace RawrXD {
namespace Inference {

// Quantized KV cache entry for memory efficiency
struct Q8_KV_Cache {
    // Per-head quantization
    float k_scale;           // Scale for K dequantization
    float v_scale;           // Scale for V dequantization
    int8_t* k_q8;           // Quantized K values [max_seq_len, head_dim]
    int8_t* v_q8;           // Quantized V values [max_seq_len, head_dim]
    
    // FP32 cache for recent tokens (sliding window)
    float* k_recent;        // [window_size, head_dim]
    float* v_recent;        // [window_size, head_dim]
    uint32_t recent_start;  // Start index in circular buffer
};

// 32K context optimized KV cache
class KVCache32K {
public:
    KVCache32K(uint32_t num_kv_heads, uint32_t head_dim, 
                uint32_t max_seq_len = 32768,
                uint32_t window_size = 4096);
    ~KVCache32K();
    
    // Disable copy
    KVCache32K(const KVCache32K&) = delete;
    KVCache32K& operator=(const KVCache32K&) = delete;
    
    // Get cache length
    uint32_t GetCacheLen() const { return cache_len_; }
    
    // Append K and V for new token
    void AppendK(uint32_t head_idx, const float* k_values);
    void AppendV(uint32_t head_idx, const float* v_values);
    
    // Get K and V for attention computation
    // Returns pointer to K/V values (may be dequantized on-the-fly)
    const float* GetK(uint32_t head_idx, uint32_t pos) const;
    const float* GetV(uint32_t head_idx, uint32_t pos) const;
    
    // Get all K/V for a head (for Flash Attention)
    const float* GetKBuffer(uint32_t head_idx) const;
    const float* GetVBuffer(uint32_t head_idx) const;
    
    // Clear cache
    void Clear();
    
    // Memory usage stats
    size_t GetMemoryUsage() const;
    size_t GetFP32MemoryUsage() const;
    float GetCompressionRatio() const;
    
private:
    uint32_t num_kv_heads_;
    uint32_t head_dim_;
    uint32_t max_seq_len_;
    uint32_t window_size_;
    uint32_t cache_len_;
    
    // Quantized cache for long history
    std::vector<Q8_KV_Cache> heads_;
    
    // Working buffers for dequantization
    mutable std::vector<float> k_dequantized_;
    mutable std::vector<float> v_dequantized_;
    
    // Quantize FP32 to INT8
    void QuantizeK(uint32_t head_idx, uint32_t pos, const float* values);
    void QuantizeV(uint32_t head_idx, uint32_t pos, const float* values);
    
    // Dequantize INT8 to FP32
    void DequantizeK(uint32_t head_idx, uint32_t pos, float* output) const;
    void DequantizeV(uint32_t head_idx, uint32_t pos, float* output) const;
    
    // Check if position is in recent window
    bool IsRecent(uint32_t pos) const;
    uint32_t GetRecentIndex(uint32_t pos) const;
};

// Ring buffer implementation for O(1) append
class RingBufferKVCache {
public:
    RingBufferKVCache(uint32_t num_heads, uint32_t head_dim, uint32_t capacity);
    
    void Append(const float* k_values, const float* v_values);
    void GetKV(uint32_t pos, float* k_out, float* v_out) const;
    uint32_t Size() const { return size_; }
    
private:
    uint32_t num_heads_;
    uint32_t head_dim_;
    uint32_t capacity_;
    uint32_t size_;
    uint32_t head_;  // Write position
    
    std::vector<float> k_buffer_;
    std::vector<float> v_buffer_;
};

} // namespace Inference
} // namespace RawrXD
