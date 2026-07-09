// ============================================================================
// flash_attention.hpp - Optimized Attention Kernels
// ============================================================================
// FlashAttention-style tiling for memory-efficient, compute-bound attention.
// Optimized for:
//   - AVX2/AVX512 vectorization
//   - Q4_K/Q2_K quantized weights
//   - Streaming KV cache access
//   - Single-token inference (decoding)
//
// Architecture:
//   FlashAttention::Forward(q, k_cache, v_cache, output)
//     → Tile over sequence length
//     → Compute attention scores in tiles
//     → Online softmax (numerically stable)
//     → Accumulate weighted values
//     → Write output
// ============================================================================

#pragma once

#include <cstdint>
#include <cstddef>
#include <immintrin.h>

namespace RawrXD {
namespace Runtime {

// Forward declarations
class KVCache;
class TensorView;

// ============================================================================
// FlashAttention Configuration
// ============================================================================
struct FlashAttentionConfig {
    uint32_t head_dim = 64;           // Dimension per head
    uint32_t num_heads = 32;          // Number of query heads
    uint32_t num_kv_heads = 32;       // Number of KV heads (GQA/MQA)
    uint32_t max_seq_len = 8192;      // Maximum sequence length
    
    // Tiling parameters (tuned for cache size)
    uint32_t tile_size_q = 64;        // Query tile size
    uint32_t tile_size_kv = 256;      // KV tile size
    uint32_t tile_size_dim = 64;      // Dimension tile size
    
    // Numerical stability
    float softmax_scale = 1.0f;       // 1/sqrt(head_dim)
    float attention_scale = 0.0f;       // Computed from head_dim
    
    // Optimization flags
    bool use_avx512 = false;          // Enable AVX512
    bool use_avx2 = true;             // Enable AVX2
    bool use_fma = true;              // Enable FMA
    
    void Initialize(uint32_t hdim, uint32_t nheads, uint32_t nkv) {
        head_dim = hdim;
        num_heads = nheads;
        num_kv_heads = nkv;
        attention_scale = 1.0f / std::sqrt(static_cast<float>(head_dim));
        
        #ifdef __AVX512F__
        use_avx512 = true;
        tile_size_q = 128;
        tile_size_kv = 512;
        #elif defined(__AVX2__)
        use_avx2 = true;
        tile_size_q = 64;
        tile_size_kv = 256;
        #endif
    }
};

// ============================================================================
// Online Softmax State (for numerical stability)
// ============================================================================
struct OnlineSoftmaxState {
    float max_val = -INFINITY;        // Running max
    float sum_exp = 0.0f;             // Running sum of exp(x - max)
    float scale = 1.0f;               // Normalization factor
    
    void Update(float x);
    float Normalize(float x) const;
    void Reset() { max_val = -INFINITY; sum_exp = 0.0f; scale = 1.0f; }
};

// ============================================================================
// FlashAttention Kernel
// ============================================================================
class FlashAttention {
public:
    FlashAttention();
    ~FlashAttention();
    
    // Initialize with configuration
    bool Initialize(const FlashAttentionConfig& config);
    
    // ------------------------------------------------------------------------
    // Main Forward Pass
    // ------------------------------------------------------------------------
    // Input:  q [num_heads, head_dim] - query vectors for current token
    //         k_cache, v_cache - KV cache with all previous tokens
    //         seq_len - current sequence length
    // Output: out [num_heads, head_dim] - attention output
    // ------------------------------------------------------------------------
    bool Forward(
        const float* q,                   // [num_heads, head_dim]
        const KVCache& kv_cache,          // Cached keys and values
        uint32_t seq_len,                 // Current sequence length
        float* output,                    // [num_heads, head_dim]
        uint64_t* cycles_out = nullptr    // Optional: timing output
    );
    
    // Single-head attention (for testing)
    bool ForwardSingleHead(
        const float* q_head,              // [head_dim]
        const float* k_cache_head,        // [seq_len, head_dim]
        const float* v_cache_head,        // [seq_len, head_dim]
        uint32_t seq_len,
        float* output_head                // [head_dim]
    );

private:
    FlashAttentionConfig m_config;
    bool m_initialized = false;
    
    // Temporary buffers (aligned for SIMD)
    alignas(64) float m_tile_q[256 * 64];       // Query tile
    alignas(64) float m_tile_k[256 * 64];       // Key tile
    alignas(64) float m_tile_v[256 * 64];       // Value tile
    alignas(64) float m_tile_scores[256 * 256]; // Attention scores
    alignas(64) float m_tile_out[256 * 64];     // Output accumulator
    alignas(64) float m_softmax_buf[256];       // Softmax temp
    
    // Internal kernels
    void ComputeQKDotProduct(
        const float* q_tile,
        const float* k_tile,
        float* scores,
        uint32_t q_len,
        uint32_t kv_len,
        uint32_t dim
    );
    
    void ApplySoftmax(
        float* scores,
        uint32_t rows,
        uint32_t cols
    );
    
    void ComputeWeightedSum(
        const float* scores,
        const float* v_tile,
        float* output,
        uint32_t q_len,
        uint32_t kv_len,
        uint32_t dim
    );
    
    // SIMD kernels
    void ComputeQKDotProductAVX2(
        const float* q,
        const float* k,
        float* scores,
        uint32_t q_len,
        uint32_t kv_len,
        uint32_t dim
    );
    
    void ComputeQKDotProductAVX512(
        const float* q,
        const float* k,
        float* scores,
        uint32_t q_len,
        uint32_t kv_len,
        uint32_t dim
    );
    
    void SoftmaxAVX2(float* data, uint32_t len);
    void SoftmaxAVX512(float* data, uint32_t len);
    
    // GQA/MQA mapping
    uint32_t GetKVHeadIndex(uint32_t q_head) const {
        if (m_config.num_kv_heads >= m_config.num_heads) {
            return q_head;
        }
        // GQA: multiple query heads share same KV head
        return q_head / (m_config.num_heads / m_config.num_kv_heads);
    }
};

// ============================================================================
// Optimized Q4_K MatMul for Attention
// ============================================================================
class QuantizedMatMul {
public:
    // Compute: output = quantized_weights @ input
    // For attention: q = W_q @ x, k = W_k @ x, v = W_v @ x
    static bool Compute(
        const TensorView& weight,       // Q4_K quantized weights
        const float* input,             // [in_dim]
        float* output,                  // [out_dim]
        uint32_t in_dim,
        uint32_t out_dim,
        bool use_avx2 = true
    );
    
    // Batch version for multiple heads
    static bool ComputeBatch(
        const TensorView& weight,
        const float* input,             // [batch, in_dim]
        float* output,                  // [batch, out_dim]
        uint32_t batch_size,
        uint32_t in_dim,
        uint32_t out_dim
    );

private:
    // AVX2 kernel for Q4_K dequantization + matmul
    static void DequantizeAndDotAVX2(
        const uint8_t* q4k_block,      // 144-byte Q4_K block
        const float* input,
        float* accum,
        uint32_t in_dim
    );
};

// ============================================================================
// Utility Functions
// ============================================================================

// Detect CPU features at runtime
struct CPUFeatures {
    bool has_avx = false;
    bool has_avx2 = false;
    bool has_avx512f = false;
    bool has_fma = false;
    
    static CPUFeatures Detect();
};

// Tile size selection based on cache
uint32_t SelectOptimalTileSize(uint32_t head_dim, uint32_t cache_line_size = 64);

} // namespace Runtime
} // namespace RawrXD
