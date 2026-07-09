// ============================================================================
// Quantized Transformer Layer
// ============================================================================
// Uses Q8_K weights for 4x memory bandwidth reduction
// ============================================================================

#pragma once

#include "transformer_layer_inference.hpp"
#include "quantized_matmul_fast.hpp"
#include <vector>

namespace RawrXD {
namespace Inference {

// Quantized transformer weights
struct QuantizedTransformerWeights {
    // Attention weights in Q8_K format
    std::vector<SEG::Q8_K_Block> q_weight_q8;  // [hidden/256, hidden] blocks
    std::vector<SEG::Q8_K_Block> k_weight_q8;  // [kv_hidden/256, hidden] blocks
    std::vector<SEG::Q8_K_Block> v_weight_q8;  // [kv_hidden/256, hidden] blocks
    std::vector<SEG::Q8_K_Block> o_weight_q8;  // [hidden/256, hidden] blocks
    
    // FFN weights in Q8_K format
    std::vector<SEG::Q8_K_Block> ffn_gate_q8;  // [intermediate/256, hidden] blocks
    std::vector<SEG::Q8_K_Block> ffn_up_q8;     // [intermediate/256, hidden] blocks
    std::vector<SEG::Q8_K_Block> ffn_down_q8;    // [hidden/256, intermediate] blocks
    
    // Normalization weights (kept as float for precision)
    std::vector<float> attn_norm;
    std::vector<float> ffn_norm;
};

// Quantized transformer layer
class QuantizedTransformerLayer : public TransformerLayer {
public:
    QuantizedTransformerLayer(const TransformerConfig& config);
    
    // Load and quantize weights
    bool LoadWeightsQuantized(const float* q_w, const float* k_w,
                               const float* v_w, const float* o_w,
                               const float* attn_n,
                               const float* ffn_g, const float* ffn_u,
                               const float* ffn_d, const float* ffn_n);
    
    // Forward pass with quantized weights
    bool ForwardQuantized(const float* input, float* output,
                          KVCache& kv_cache, uint32_t position);

private:
    QuantizedTransformerWeights q_weights_;
    
    // Convert float weights to Q8_K
    void QuantizeWeights(const float* input, std::vector<SEG::Q8_K_Block>& output,
                         size_t num_blocks);
};

} // namespace Inference
} // namespace RawrXD
