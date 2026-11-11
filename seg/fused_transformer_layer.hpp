// ============================================================================
// Fused Transformer Layer
// ============================================================================
// Combines RMSNorm → Attention → RMSNorm → MLP into a single kernel
// Reduces memory round-trips and improves cache locality
// ============================================================================

#pragma once

#include <cstdint>
#include <vector>
#include <cmath>

namespace seg {

// ============================================================================
// Fused Layer Configuration
// ============================================================================
struct FusedLayerConfig {
    uint32_t hidden_size = 2048;
    uint32_t num_heads = 32;
    uint32_t num_kv_heads = 32;
    uint32_t head_dim = 64;  // hidden_size / num_heads
    uint32_t intermediate_size = 5504;
    float rms_norm_eps = 1e-5f;
};

// ============================================================================
// Fused Transformer Layer
// ============================================================================
// Single kernel that processes: input → RMSNorm → Attention → RMSNorm → MLP → output
// Keeps intermediate results in L1/L2 cache
// ============================================================================
class FusedTransformerLayer {
public:
    FusedTransformerLayer() = default;
    
    // Initialize with configuration
    bool Initialize(const FusedLayerConfig& config);
    
    // Forward pass (fused)
    // input/output: [hidden_size]
    // q/k/v/o weights: projection matrices
    // gate/up/down weights: MLP matrices
    bool Forward(
        const float* input,
        float* output,
        // Attention weights (simplified - would be TensorView in real impl)
        const float* q_weight, const float* k_weight, 
        const float* v_weight, const float* o_weight,
        // MLP weights
        const float* gate_weight, const float* up_weight, const float* down_weight,
        // RMSNorm weights
        const float* attn_norm_weight, const float* mlp_norm_weight,
        // KV cache (for this layer)
        float* k_cache, float* v_cache,
        uint32_t seq_pos, uint32_t seq_len
    );
    
    // Get configuration
    const FusedLayerConfig& GetConfig() const { return config_; }
    
private:
    FusedLayerConfig config_;
    bool initialized_ = false;
    
    // Temporary buffers (kept in cache)
    std::vector<float> temp_buffer_1_;  // For RMSNorm output
    std::vector<float> temp_buffer_2_;  // For attention output
    std::vector<float> temp_buffer_3_;  // For MLP intermediate
    
    // Internal compute functions (inlined for fusion)
    inline void ComputeRMSNorm(const float* input, float* output, 
                               const float* weight, uint32_t size);
    inline void ComputeAttention(
        const float* input, float* output,
        const float* q_w, const float* k_w, const float* v_w, const float* o_w,
        float* k_cache, float* v_cache,
        uint32_t seq_pos, uint32_t seq_len
    );
    inline void ComputeMLP(
        const float* input, float* output,
        const float* gate_w, const float* up_w, const float* down_w
    );
    inline void ComputeSiLU(float* data, uint32_t size);
    inline void ComputeMatMul(const float* a, const float* b, float* c,
                              uint32_t m, uint32_t n, uint32_t k);
    inline void ComputeResidualAdd(const float* a, const float* b, float* c, 
                                     uint32_t size);
};

// ============================================================================
// Baseline (Non-Fused) Transformer Layer
// ============================================================================
// For comparison - separate operations with memory round-trips
// ============================================================================
class BaselineTransformerLayer {
public:
    BaselineTransformerLayer() = default;
    bool Initialize(const FusedLayerConfig& config);
    
    bool Forward(
        const float* input, float* output,
        const float* q_weight, const float* k_weight, 
        const float* v_weight, const float* o_weight,
        const float* gate_weight, const float* up_weight, const float* down_weight,
        const float* attn_norm_weight, const float* mlp_norm_weight,
        float* k_cache, float* v_cache,
        uint32_t seq_pos, uint32_t seq_len
    );
    
private:
    FusedLayerConfig config_;
    bool initialized_ = false;
};

} // namespace seg
