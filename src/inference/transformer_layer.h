/**
 * @file transformer_layer.h
 * @brief RawrXD Transformer Layer - Full Forward Pass (C4)
 *
 * Complete transformer layer implementation:
 * Input → RMSNorm → Attention → Residual → RMSNorm → FFN → Residual → Output
 *
 * @copyright RawrXD 2026
 */

#pragma once

#include "../model/model_context.h"
#include "quantized_tensor.hpp"
#include <vector>
#include <cstdint>
#include <memory>

namespace rawrxd {
namespace inference {

// ============================================================================
// Transformer Configuration
// ============================================================================

struct TransformerConfig {
    uint32_t vocab_size = 32000;
    uint32_t hidden_size = 4096;      // embedding dimension
    uint32_t intermediate_size = 11008; // FFN intermediate size
    uint32_t num_layers = 32;
    uint32_t num_heads = 32;
    uint32_t num_kv_heads = 32;       // for GQA (grouped query attention)
    uint32_t head_dim = 128;          // hidden_size / num_heads
    float rms_norm_eps = 1e-6f;
    float rope_theta = 10000.0f;
};

// ============================================================================
// Attention Weights (Quantized)
// ============================================================================

struct AttentionWeights {
    QuantizedTensor q_proj;  // [hidden_size, hidden_size] - quantized
    QuantizedTensor k_proj;  // [hidden_size, num_kv_heads * head_dim] - quantized
    QuantizedTensor v_proj;  // [hidden_size, num_kv_heads * head_dim] - quantized
    QuantizedTensor o_proj;  // [hidden_size, hidden_size] - quantized
    
    // RMSNorm weights (keep as FP32 - small)
    std::vector<float> attn_norm; // [hidden_size]
};

// ============================================================================
// FFN Weights (Quantized)
// ============================================================================

struct FFNWeights {
    QuantizedTensor gate_proj; // [hidden_size, intermediate_size] - quantized
    QuantizedTensor up_proj;   // [hidden_size, intermediate_size] - quantized
    QuantizedTensor down_proj; // [intermediate_size, hidden_size] - quantized
    
    // RMSNorm weights (keep as FP32 - small)
    std::vector<float> ffn_norm;  // [hidden_size]
};

// ============================================================================
// Transformer Layer
// ============================================================================

class TransformerLayer {
public:
    TransformerLayer(const TransformerConfig& config, uint32_t layer_idx);
    ~TransformerLayer() = default;
    
    // Load weights from ModelContext
    bool LoadWeights(const model::ModelContext& model);
    
    // Forward pass
    // input: [seq_len, hidden_size]
    // output: [seq_len, hidden_size]
    std::vector<float> Forward(const std::vector<float>& input, uint32_t seq_len);
    
    // Forward with KV cache (for generation)
    std::vector<float> ForwardWithCache(
        const std::vector<float>& input,
        uint32_t seq_len,
        uint32_t start_pos,
        std::vector<float>& k_cache,
        std::vector<float>& v_cache
    );
    
private:
    TransformerConfig config_;
    uint32_t layer_idx_;
    
    AttentionWeights attn_weights_;
    FFNWeights ffn_weights_;
    
    bool weights_loaded_ = false;
    
    // Helper functions
    std::vector<float> RMSNorm(const std::vector<float>& x, const std::vector<float>& weight);
    std::vector<float> ApplyAttention(const std::vector<float>& x, uint32_t seq_len);
    std::vector<float> ApplyFFN(const std::vector<float>& x);
    std::vector<float> SiLU(const std::vector<float>& x);
    std::vector<float> Softmax(const std::vector<float>& x, uint32_t rows, uint32_t cols);
    
    // Matrix operations (now with quantized weights)
    std::vector<float> MatMul(
        const std::vector<float>& a, uint32_t a_rows, uint32_t a_cols,
        const QuantizedTensor& b, uint32_t b_rows, uint32_t b_cols
    );
    
    std::vector<float> Transpose(const std::vector<float>& x, uint32_t rows, uint32_t cols);
};

// ============================================================================
// Full Transformer Model
// ============================================================================

class TransformerModel {
public:
    TransformerModel() = default;
    ~TransformerModel() = default;
    
    // Load from GGUF
    bool Load(const std::string& path);
    
    // Forward pass for entire model
    std::vector<float> Forward(const std::vector<uint32_t>& token_ids);
    
    // Generate next token
    uint32_t GenerateNextToken(
        const std::vector<uint32_t>& prompt_tokens,
        float temperature = 0.8f,
        uint32_t top_k = 40
    );
    
private:
    std::unique_ptr<model::ModelContext> model_ctx_;
    std::vector<std::unique_ptr<TransformerLayer>> layers_;
    TransformerConfig config_;
    
    // Embedding and output weights (quantized)
    QuantizedTensor token_embeddings_;     // [vocab_size, hidden_size] - quantized
    std::vector<float> output_norm_;      // [hidden_size] - FP32
    QuantizedTensor lm_head_;              // [hidden_size, vocab_size] - quantized
    
    // KV cache for generation
    std::vector<std::vector<float>> k_cache_;
    std::vector<std::vector<float>> v_cache_;
    
    bool LoadEmbeddingWeights();
    std::vector<float> LookupEmbeddings(const std::vector<uint32_t>& token_ids);
    uint32_t Sample(const std::vector<float>& logits, float temperature, uint32_t top_k);
    
    // Matrix multiplication helper
    std::vector<float> MatMul(
        const std::vector<float>& a, uint32_t a_rows, uint32_t a_cols,
        const std::vector<float>& b, uint32_t b_rows, uint32_t b_cols
    );
};

} // namespace inference
} // namespace rawrxd
