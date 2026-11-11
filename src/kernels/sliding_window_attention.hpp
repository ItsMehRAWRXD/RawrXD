//=============================================================================
// Sliding Window Attention (SWA) - O(n·w) Complexity
// Replaces O(n²) full attention with O(n·w) windowed attention
// Window size W << sequence length N, giving massive performance gain
//=============================================================================
#pragma once

#include <immintrin.h>
#include <cstdint>
#include <cstddef>

namespace RawrXD {
namespace Kernels {

// Configuration: Sliding window size
// 1024 tokens provides good context while maintaining performance
constexpr int kSlidingWindowSize = 1024;

// KV Cache Ring Buffer for O(1) sliding
// Uses circular indexing to avoid memory movement
template <typename T, size_t Capacity>
class alignas(64) KVCacheRingBuffer {
    static_assert((Capacity & (Capacity - 1)) == 0, "Capacity must be power of 2");
    
public:
    static constexpr size_t kMask = Capacity - 1;
    
    // Initialize with pinned memory (prevents swapping to disk)
    bool Initialize() {
        // Pre-allocate entire buffer at initialization
        // This prevents allocation during inference (stops hotswap triggers)
        buffer_ = static_cast<T*>(_aligned_malloc(sizeof(T) * Capacity, 64));
        if (!buffer_) return false;
        
        // Pin memory to prevent OS swapping (Tier 1 memory guarantee)
        // Note: VirtualLock requires MEM_COMMIT pages
        #ifdef _WIN32
        // Already committed by _aligned_malloc, just pin it
        VirtualLock(buffer_, sizeof(T) * Capacity);
        #endif
        
        head_ = 0;
        tail_ = 0;
        size_ = 0;
        return true;
    }
    
    // Push new KV pair - O(1)
    void Push(const T& k, const T& v) {
        size_t idx = head_ & kMask;
        k_buffer_[idx] = k;
        v_buffer_[idx] = v;
        head_++;
        
        if (size_ < Capacity) {
            size_++;
        } else {
            // Buffer full, advance tail (circular eviction)
            tail_++;
        }
    }
    
    // Get window start index for attention computation
    // Returns the oldest token index within the window
    size_t GetWindowStart(size_t current_seq_len) const {
        if (current_seq_len <= kSlidingWindowSize) {
            return 0;
        }
        // Return position of token at (current_seq_len - window_size)
        return current_seq_len - kSlidingWindowSize;
    }
    
    // Get K/V at logical position (handles circular indexing)
    const T& GetK(size_t logical_pos) const {
        return k_buffer_[logical_pos & kMask];
    }
    
    const T& GetV(size_t logical_pos) const {
        return v_buffer_[logical_pos & kMask];
    }
    
    // Current window size (min of capacity and sequence length)
    size_t GetCurrentWindowSize(size_t seq_len) const {
        return (seq_len < kSlidingWindowSize) ? seq_len : kSlidingWindowSize;
    }
    
    // Cleanup
    void Shutdown() {
        if (buffer_) {
            #ifdef _WIN32
            VirtualUnlock(buffer_, sizeof(T) * Capacity);
            #endif
            _aligned_free(buffer_);
            buffer_ = nullptr;
        }
    }
    
    ~KVCacheRingBuffer() {
        Shutdown();
    }
    
private:
    T* buffer_ = nullptr;
    T* k_buffer_ = nullptr;
    T* v_buffer_ = nullptr;
    alignas(64) size_t head_ = 0;
    alignas(64) size_t tail_ = 0;
    size_t size_ = 0;
};

//=============================================================================
// Sliding Window Attention Kernel - AVX-512 Optimized
//=============================================================================

// Compute attention scores for a single query position
// Only attends to the last kSlidingWindowSize tokens
// Handles head_dim not divisible by 16 via tail loop
inline void ComputeWindowedAttentionScores(
    const float* __restrict q_vec,           // Query vector (head_dim floats)
    const float* __restrict k_cache,       // Key cache (circular buffer)
    float* __restrict scores,              // Output scores
    int head_dim,                          // Dimension per head
    size_t window_start,                   // Start of attention window
    size_t window_end,                     // End of attention window (current position)
    float scale                            // 1/sqrt(head_dim)
) {
    // AVX-512: Process 16 floats per iteration
    const int simd_width = 16;
    const int num_simd_iters = head_dim / simd_width;
    const int tail_size = head_dim % simd_width;
    
    for (size_t j = window_start; j < window_end; j++) {
        const float* k_vec = k_cache + (j * head_dim);
        
        // Dot product: Q · K^T using AVX-512 FMA
        __m512 sum_vec = _mm512_setzero_ps();
        
        // Main SIMD loop
        for (int d = 0; d < num_simd_iters; d++) {
            __m512 q = _mm512_load_ps(q_vec + d * simd_width);  // Aligned load
            __m512 k = _mm512_load_ps(k_vec + d * simd_width);  // Aligned load
            sum_vec = _mm512_fmadd_ps(q, k, sum_vec);
        }
        
        // Tail handling for dimensions not divisible by 16
        float tail_sum = 0.0f;
        for (int d = num_simd_iters * simd_width; d < head_dim; d++) {
            tail_sum += q_vec[d] * k_vec[d];
        }
        
        // Horizontal sum + tail
        float score = (_mm512_reduce_add_ps(sum_vec) + tail_sum) * scale;
        scores[j - window_start] = score;
    }
}

// Optimized softmax over windowed scores
inline void WindowedSoftmax(
    float* __restrict scores,
    size_t window_size,
    float* __restrict max_score_out = nullptr
) {
    // Find max for numerical stability
    float max_score = scores[0];
    for (size_t i = 1; i < window_size; i++) {
        if (scores[i] > max_score) max_score = scores[i];
    }
    
    // Compute exp and sum
    float sum_exp = 0.0f;
    for (size_t i = 0; i < window_size; i++) {
        scores[i] = expf(scores[i] - max_score);
        sum_exp += scores[i];
    }
    
    // Normalize
    float inv_sum = 1.0f / sum_exp;
    for (size_t i = 0; i < window_size; i++) {
        scores[i] *= inv_sum;
    }
    
    if (max_score_out) *max_score_out = max_score;
}

// Compute weighted sum of values using attention scores
// AVX-512 optimized with tail handling
inline void ComputeWeightedSum(
    const float* __restrict v_cache,       // Value cache (circular buffer)
    const float* __restrict scores,        // Attention scores (softmax output)
    float* __restrict output,              // Output vector
    int head_dim,                          // Dimension per head
    size_t window_start,                   // Start of window
    size_t window_size                     // Size of window
) {
    const int simd_width = 16;
    const int num_simd_iters = head_dim / simd_width;
    const int tail_size = head_dim % simd_width;
    
    // Initialize SIMD accumulators
    __m512 out_acc[16];  // Max 256 dims / 16 = 16 registers
    for (int d = 0; d < num_simd_iters; d++) {
        out_acc[d] = _mm512_setzero_ps();
    }
    
    // Initialize tail accumulator
    float tail_acc[16] = {};  // Max tail is 15
    
    // Weighted sum: Σ(attn_score[j] * V[j])
    for (size_t j = 0; j < window_size; j++) {
        size_t cache_idx = (window_start + j);
        const float* v_vec = v_cache + (cache_idx * head_dim);
        __m512 score_vec = _mm512_set1_ps(scores[j]);
        
        // SIMD accumulation
        for (int d = 0; d < num_simd_iters; d++) {
            __m512 v = _mm512_load_ps(v_vec + d * simd_width);
            out_acc[d] = _mm512_fmadd_ps(score_vec, v, out_acc[d]);
        }
        
        // Tail accumulation
        for (int d = 0; d < tail_size; d++) {
            tail_acc[d] += scores[j] * v_vec[num_simd_iters * simd_width + d];
        }
    }
    
    // Store SIMD results
    for (int d = 0; d < num_simd_iters; d++) {
        _mm512_store_ps(output + d * simd_width, out_acc[d]);
    }
    
    // Store tail results
    for (int d = 0; d < tail_size; d++) {
        output[num_simd_iters * simd_width + d] = tail_acc[d];
    }
}

//=============================================================================
// Main Sliding Window Attention Function
//=============================================================================

extern "C" void sliding_window_attention_avx512(
    const float* __restrict Q,             // Query matrix [seq_len, num_heads, head_dim]
    const float* __restrict K_cache,       // Key cache (circular) [max_seq, num_heads, head_dim]
    const float* __restrict V_cache,       // Value cache (circular) [max_seq, num_heads, head_dim]
    float* __restrict output,              // Output matrix [seq_len, num_heads, head_dim]
    int batch_size,
    int seq_len,
    int num_heads,
    int head_dim,
    size_t kv_cache_head                 // Current head position in KV cache
);

} // namespace Kernels
} // namespace RawrXD
