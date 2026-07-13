#pragma once
// ============================================================================
// FlashAttention v2 - Memory-Efficient Attention Kernel
// ============================================================================
// Implements the FlashAttention algorithm with tiling for cache efficiency
// Reduces HBM accesses from O(N^2) to O(N) for sequence length N
// ============================================================================

#include <cstdint>
#include <cstddef>
#include <vector>
#include <functional>

namespace RawrXD {
namespace Runtime {

// FlashAttention v2 configuration
struct FlashAttentionConfig {
    uint32_t seq_len;        // Sequence length
    uint32_t num_heads;      // Number of attention heads
    uint32_t head_dim;       // Dimension per head (typically 64 or 128)
    uint32_t batch_size;     // Batch size
    
    // Tiling parameters (tuned for cache size)
    uint32_t block_q = 64;   // Query block size (Br in paper)
    uint32_t block_kv = 64;  // Key/Value block size (Bc in paper)
    
    // Numerical stability
    float softmax_scale;     // 1/sqrt(head_dim)
};

// FlashAttention v2 kernel
class FlashAttentionV2 {
public:
    FlashAttentionV2(const FlashAttentionConfig& config);
    ~FlashAttentionV2() = default;
    
    // Forward pass: compute attention(Q, K, V)
    // Input: Q, K, V are [batch, num_heads, seq_len, head_dim]
    // Output: O is [batch, num_heads, seq_len, head_dim]
    void Forward(const float* Q, const float* K, const float* V, 
                 float* O, float* softmax_lse = nullptr);
    
    // Forward with causal masking (for autoregressive generation)
    void ForwardCausal(const float* Q, const float* K, const float* V,
                       float* O, float* softmax_lse = nullptr);
    
    // Get configuration
    const FlashAttentionConfig& GetConfig() const { return config_; }
    
    // Get workspace size required
    size_t GetWorkspaceSize() const;
    
    // Set workspace buffer (must be pre-allocated)
    void SetWorkspace(void* workspace, size_t size);

private:
    FlashAttentionConfig config_;
    
    // Workspace for intermediate results
    std::vector<float> workspace_;
    float* workspace_ptr_ = nullptr;
    size_t workspace_size_ = 0;
    
    // Tiled computation
    void ComputeBlock(const float* Q_block, const float* K_block, const float* V_block,
                      float* O_block, float* m_block, float* l_block,
                      uint32_t seq_len, uint32_t head_dim);
    
    // Online softmax update
    void OnlineSoftmaxUpdate(float* m, float* l, float* acc,
                            const float* S, const float* V_block,
                            uint32_t q_len, uint32_t kv_len, uint32_t head_dim);
    
    // Matrix multiplication (GEMM)
    void GemmQK(const float* Q, const float* K, float* S,
                uint32_t m, uint32_t n, uint32_t k);
    
    void GemmSV(const float* S, const float* V, float* O,
                uint32_t m, uint32_t n, uint32_t k);
};

// Utility: Initialize FlashAttention config from model parameters
FlashAttentionConfig MakeFlashAttentionConfig(
    uint32_t seq_len,
    uint32_t num_heads, 
    uint32_t head_dim,
    uint32_t batch_size = 1
);

// Utility: Compute optimal block sizes based on cache size
void ComputeOptimalBlockSizes(uint32_t head_dim, uint32_t& block_q, uint32_t& block_kv);

} // namespace Runtime
} // namespace RawrXD
