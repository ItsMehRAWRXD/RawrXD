// ============================================================================
// Quantized Transformer Layer Implementation
// ============================================================================
// Uses Q8_K weights for 4x memory bandwidth reduction
// ============================================================================

#include "transformer_quantized.hpp"
#include <cmath>
#include <algorithm>

namespace RawrXD {
namespace Inference {

QuantizedTransformerLayer::QuantizedTransformerLayer(const TransformerConfig& config)
    : TransformerLayer(config) {
}

void QuantizedTransformerLayer::QuantizeWeights(const float* input, std::vector<SEG::Q8_K_Block>& output,
                                                  size_t num_blocks) {
    output.resize(num_blocks);
    
    for (size_t i = 0; i < num_blocks; i++) {
        const float* block_input = input + i * 256;
        SEG::Q8_K_Block& block = output[i];
        
        // Find max absolute value for scaling
        float max_abs = 0.0f;
        for (size_t j = 0; j < 256; j++) {
            max_abs = std::max(max_abs, std::abs(block_input[j]));
        }
        
        // Compute scale
        block.d = max_abs / 127.0f;
        if (block.d == 0.0f) block.d = 1.0f;
        
        // Quantize to int8
        for (size_t j = 0; j < 256; j++) {
            float scaled = block_input[j] / block.d;
            block.qs[j] = static_cast<int8_t>(std::round(std::clamp(scaled, -127.0f, 127.0f)));
        }
    }
}

bool QuantizedTransformerLayer::LoadWeightsQuantized(const float* q_w, const float* k_w,
                                                       const float* v_w, const float* o_w,
                                                       const float* attn_n,
                                                       const float* ffn_g, const float* ffn_u,
                                                       const float* ffn_d, const float* ffn_n) {
    uint32_t hidden = config_.hidden_size;
    uint32_t kv_hidden = config_.num_kv_heads * config_.head_dim;
    uint32_t intermediate = config_.intermediate_size;
    
    // Quantize attention weights
    QuantizeWeights(q_w, q_weights_.q_weight_q8, (hidden * hidden) / 256);
    QuantizeWeights(k_w, q_weights_.k_weight_q8, (hidden * kv_hidden) / 256);
    QuantizeWeights(v_w, q_weights_.v_weight_q8, (hidden * kv_hidden) / 256);
    QuantizeWeights(o_w, q_weights_.o_weight_q8, (hidden * hidden) / 256);
    
    // Quantize FFN weights
    QuantizeWeights(ffn_g, q_weights_.ffn_gate_q8, (hidden * intermediate) / 256);
    QuantizeWeights(ffn_u, q_weights_.ffn_up_q8, (hidden * intermediate) / 256);
    QuantizeWeights(ffn_d, q_weights_.ffn_down_q8, (intermediate * hidden) / 256);
    
    // Copy normalization weights (keep as float)
    q_weights_.attn_norm.assign(attn_n, attn_n + hidden);
    q_weights_.ffn_norm.assign(ffn_n, ffn_n + hidden);
    
    return true;
}

bool QuantizedTransformerLayer::ForwardQuantized(const float* input, float* output,
                                                  KVCache& kv_cache, uint32_t position) {
    uint32_t hidden = config_.hidden_size;
    uint32_t kv_hidden = config_.num_kv_heads * config_.head_dim;
    uint32_t intermediate = config_.intermediate_size;
    
    // === Attention Block ===
    // 1. RMSNorm
    RMSNorm(input, q_weights_.attn_norm.data(), normed_.data(), hidden);
    
    // 2. QKV projections with quantized weights
    SEG::QuantizedVecMatMulQ8_K_Fast(normed_.data(), q_weights_.q_weight_q8.data(), 
                                      q_proj_.data(), hidden, hidden);
    SEG::QuantizedVecMatMulQ8_K_Fast(normed_.data(), q_weights_.k_weight_q8.data(), 
                                      k_proj_.data(), kv_hidden, hidden);
    SEG::QuantizedVecMatMulQ8_K_Fast(normed_.data(), q_weights_.v_weight_q8.data(), 
                                      v_proj_.data(), kv_hidden, hidden);
    
    // 3. Attention
    AttentionForward(q_proj_.data(), k_proj_.data(), v_proj_.data(),
                     attn_out_.data(), kv_cache, position);
    
    // 4. Output projection with quantized weights
    SEG::QuantizedVecMatMulQ8_K_Fast(attn_out_.data(), q_weights_.o_weight_q8.data(),
                                      normed_.data(), hidden, hidden);
    
    // 5. Residual connection
    for (uint32_t i = 0; i < hidden; i++) {
        normed_[i] = input[i] + normed_[i];
    }
    
    // === FFN Block ===
    // 6. RMSNorm
    RMSNorm(normed_.data(), q_weights_.ffn_norm.data(), ffn_gate_.data(), hidden);
    
    // 7. FFN projections with quantized weights
    SEG::QuantizedVecMatMulQ8_K_Fast(ffn_gate_.data(), q_weights_.ffn_gate_q8.data(),
                                      ffn_gate_.data(), intermediate, hidden);
    SEG::QuantizedVecMatMulQ8_K_Fast(normed_.data(), q_weights_.ffn_up_q8.data(),
                                      ffn_up_.data(), intermediate, hidden);
    
    // 8. SiLU activation on gate
    SiLU(ffn_gate_.data(), intermediate);
    
    // 9. Element-wise multiply
    for (uint32_t i = 0; i < intermediate; i++) {
        ffn_act_[i] = ffn_gate_[i] * ffn_up_[i];
    }
    
    // 10. Down projection with quantized weights
    SEG::QuantizedVecMatMulQ8_K_Fast(ffn_act_.data(), q_weights_.ffn_down_q8.data(),
                                      output, hidden, intermediate);
    
    // 11. Residual connection
    for (uint32_t i = 0; i < hidden; i++) {
        output[i] = normed_[i] + output[i];
    }
    
    return true;
}

} // namespace Inference
} // namespace RawrXD
