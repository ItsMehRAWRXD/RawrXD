#pragma once
// ============================================================================
// KV Cache — Key-Value cache for transformer autoregressive generation
// ============================================================================
// Layout: [t, h, d] → index = ((t * num_heads) + h) * head_dim + d
// Supports multi-head attention with per-head access
// ============================================================================

#include <vector>
#include <cstddef>
#include <cstdint>

namespace RawrXD {
namespace CLI {

// KV Cache for transformer attention
// Stores key and value vectors for all previous tokens
struct KVCache {
    std::vector<float> k_cache;   // [max_seq_len * num_heads * head_dim]
    std::vector<float> v_cache;   // [max_seq_len * num_heads * head_dim]

    size_t max_seq_len = 0;
    size_t num_heads   = 0;
    size_t head_dim    = 0;
    size_t current_len = 0;

    // Initialize/resize cache
    void Resize(size_t maxLen, size_t heads, size_t dim);

    // Clear cache (reset current_len but keep allocation)
    void Clear() { current_len = 0; }

    // Layout: [t, h, d] → index = ((t * num_heads) + h) * head_dim + d
    inline size_t Index(size_t t, size_t h, size_t d) const {
        return ((t * num_heads) + h) * head_dim + d;
    }

    // Append new token's k,v vectors to cache
    // k_row, v_row: [num_heads * head_dim] flattened
    void Append(const float* k_row, const float* v_row);

    // Get key vector for position t, head h
    // dst must have space for head_dim floats
    void GetKey(size_t t, size_t h, float* dst) const;

    // Get value vector for position t, head h
    // dst must have space for head_dim floats
    void GetValue(size_t t, size_t h, float* dst) const;

    // Get pointer to key cache for position t, head h (for direct access)
    const float* GetKeyPtr(size_t t, size_t h) const {
        return &k_cache[Index(t, h, 0)];
    }

    // Get pointer to value cache for position t, head h (for direct access)
    const float* GetValuePtr(size_t t, size_t h) const {
        return &v_cache[Index(t, h, 0)];
    }

    // Check if cache is valid
    bool IsValid() const {
        return !k_cache.empty() && !v_cache.empty() && 
               max_seq_len > 0 && num_heads > 0 && head_dim > 0;
    }

    // Get total size in bytes
    size_t ByteSize() const {
        return (k_cache.size() + v_cache.size()) * sizeof(float);
    }
};

// Single-head attention on top of KV cache
// query: [head_dim]
// cache: KV cache with stored keys/values
// head_index: which head to compute attention for
// output: [head_dim] attention result
void AttentionSingleHead(
    const float* query,          // [head_dim]
    const KVCache& cache,
    size_t head_index,
    float* output                // [head_dim]
);

// Multi-head attention using KV cache
// query: [num_heads, head_dim] flattened
// output: [num_heads, head_dim] flattened
void AttentionMultiHead(
    const float* query,          // [num_heads * head_dim]
    const KVCache& cache,
    float* output                // [num_heads * head_dim]
);

} // namespace CLI
} // namespace RawrXD
