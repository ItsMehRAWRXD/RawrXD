// ============================================================================
// FlashAttention Kernel - Memory-Efficient Attention
// ============================================================================
// Implements FlashAttention algorithm for reduced memory bandwidth
// Fuses Q@K^T, softmax, and @V into a single kernel with tiling
// ============================================================================

#pragma once

#include <cstdint>
#include <cmath>
#include <algorithm>

namespace RawrXD {
namespace Kernels {

// FlashAttention configuration
struct FlashAttentionConfig {
    uint32_t batch_size = 1;
    uint32_t num_heads = 32;
    uint32_t seq_len = 1;      // Current sequence length
    uint32_t head_dim = 128;
    uint32_t max_seq_len = 4096;
    float scale = 1.0f;        // 1/sqrt(head_dim)
};

// FlashAttention state (kept in registers/cache)
struct FlashAttentionState {
    float* q;           // Query [head_dim]
    float* k_cache;     // Key cache [max_seq_len, head_dim]
    float* v_cache;     // Value cache [max_seq_len, head_dim]
    float* output;      // Output [head_dim]
    
    // Tiling buffers (SRAM/register sized)
    float q_tile[64];           // Query tile
    float k_tile[64][64];       // Key tile (transposed)
    float v_tile[64][64];       // Value tile
    float s_tile[64];           // Softmax accumulator
    float m_prev[64];           // Max for numerical stability
    float l_prev[64];           // Sum for softmax
};

// ============================================================================
// FlashAttention Implementation
// ============================================================================

class FlashAttentionKernel {
public:
    FlashAttentionKernel();
    ~FlashAttentionKernel();
    
    // Initialize with configuration
    bool Initialize(const FlashAttentionConfig& config);
    
    // Forward pass for single token (incremental decoding)
    // Much faster than full attention for autoregressive generation
    void ForwardSingle(
        const float* query,           // [head_dim]
        const float* key_cache,       // [seq_len, head_dim]
        const float* value_cache,     // [seq_len, head_dim]
        float* output,                // [head_dim]
        uint32_t seq_len);
    
    // Forward pass for full sequence (prefill phase)
    void ForwardFull(
        const float* queries,         // [seq_len, head_dim]
        const float* keys,            // [seq_len, head_dim]
        const float* values,          // [seq_len, head_dim]
        float* output,                // [seq_len, head_dim]
        uint32_t seq_len);
    
    // Multi-head attention wrapper
    void MultiHeadForward(
        const float* q,               // [num_heads, head_dim]
        const float* k_cache,         // [num_heads, max_seq_len, head_dim]
        const float* v_cache,         // [num_heads, max_seq_len, head_dim]
        float* output,                // [num_heads, head_dim]
        uint32_t seq_len);
    
    // Get configuration
    const FlashAttentionConfig& GetConfig() const { return config_; }
    
private:
    FlashAttentionConfig config_;
    
    // Tile size for blocking (fits in L1 cache)
    static constexpr uint32_t TILE_SIZE = 64;
    
    // Internal tile buffers (thread-local)
    alignas(64) float q_tile_[TILE_SIZE];
    alignas(64) float k_tile_[TILE_SIZE * TILE_SIZE];
    alignas(64) float v_tile_[TILE_SIZE * TILE_SIZE];
    alignas(64) float s_tile_[TILE_SIZE];
    
    // Softmax online statistics
    alignas(64) float m_prev_[TILE_SIZE];  // Running max
    alignas(64) float l_prev_[TILE_SIZE];  // Running sum
    
    // Single head attention (core kernel)
    void AttentionSingleHead(
        const float* q,
        const float* k_cache,
        const float* v_cache,
        float* output,
        uint32_t seq_len);
    
    // Compute Q@K^T for a tile
    void ComputeQKTile(
        const float* q,
        const float* k_tile,
        float* s_tile,
        uint32_t tile_len);
    
    // Online softmax update
    void OnlineSoftmaxUpdate(
        float* s_tile,
        float* m_prev,
        float* l_prev,
        float* output_acc,
        const float* v_tile,
        uint32_t tile_len);
};

// ============================================================================
// C API for external linkage
// ============================================================================

extern "C" {
    // Create FlashAttention context
    void* FlashAttention_Create(uint32_t num_heads, uint32_t head_dim, uint32_t max_seq_len);
    
    // Destroy context
    void FlashAttention_Destroy(void* ctx);
    
    // Single token forward (for generation)
    void FlashAttention_ForwardSingle(
        void* ctx,
        const float* query,
        const float* key_cache,
        const float* value_cache,
        float* output,
        uint32_t seq_len);
    
    // Full sequence forward (for prefill)
    void FlashAttention_ForwardFull(
        void* ctx,
        const float* queries,
        const float* keys,
        const float* values,
        float* output,
        uint32_t seq_len);
}

} // namespace Kernels
} // namespace RawrXD
