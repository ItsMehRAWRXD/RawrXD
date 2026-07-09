// ============================================================================
// Flash Attention Implementation for AVX-512
// ============================================================================
// Memory-efficient attention that avoids materializing the full attention matrix
// Uses online softmax and tiling to reduce memory bandwidth
// ============================================================================

#pragma once

#include <cstdint>
#include <cstddef>

namespace SEG {

// Flash Attention forward pass
// Computes: softmax(Q @ K^T / sqrt(d_k)) @ V
// Without materializing the N x N attention matrix
//
// Q: [seq_len, head_dim] - query matrix
// K: [seq_len, head_dim] - key matrix  
// V: [seq_len, head_dim] - value matrix
// output: [seq_len, head_dim] - output
// seq_len: sequence length
// head_dim: dimension per head
void FlashAttentionForwardF32(const float* Q, const float* K, const float* V,
                               float* output,
                               size_t seq_len, size_t head_dim);

// Flash Attention with KV cache
// For incremental decoding where K/V come from cache
//
// q: [head_dim] - single query vector
// k_cache: [cache_len, head_dim] - cached keys
// v_cache: [cache_len, head_dim] - cached values
// output: [head_dim] - output
// cache_len: current cache length
// head_dim: dimension per head
void FlashAttentionCachedF32(const float* q,
                              const float* k_cache, const float* v_cache,
                              float* output,
                              size_t cache_len, size_t head_dim);

} // namespace SEG
