/**
 * @file GGMLTransformerLayer.cpp
 * @brief Transformer layer implementation using GGML
 * 
 * Part of Phase 5: Real Forward Pass Implementation
 * Implements transformer encoder/decoder layers with self-attention.
 * 
 * @copyright RawrXD 2026
 */

#include "GGMLBackend.h"

#include <cmath>
#include <cstring>

// GGML includes
extern "C" {
#include "../../3rdparty/ggml/include/ggml.h"
#include "../../3rdparty/ggml/include/ggml-backend.h"
}

namespace RawrXD {
namespace Inference {

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * @brief Create a tensor name with layer prefix
 */
static std::string LayerTensorName(const char* baseName, int layer) {
    return "blk." + std::to_string(layer) + "." + baseName;
}

/**
 * @brief Get or create a tensor from context
 */
static struct ggml_rxd_tensor* GetOrCreateTensor(
    struct ggml_rxd_context* ctx,
    const char* name,
    int n_dims,
    int64_t ne0, int64_t ne1, int64_t ne2, int64_t ne3,
    enum ggml_rxd_type type) {
    
    struct ggml_rxd_tensor* tensor = ggml_rxd_get_tensor(ctx, name);
    if (!tensor) {
        // Create new tensor
        if (n_dims == 1) {
            tensor = ggml_rxd_new_tensor_1d(ctx, type, ne0);
        } else if (n_dims == 2) {
            tensor = ggml_rxd_new_tensor_2d(ctx, type, ne0, ne1);
        } else if (n_dims == 3) {
            tensor = ggml_rxd_new_tensor_3d(ctx, type, ne0, ne1, ne2);
        } else {
            tensor = ggml_rxd_new_tensor_4d(ctx, type, ne0, ne1, ne2, ne3);
        }
    }
    return tensor;
}

// ============================================================================
// Attention Implementation
// ============================================================================

/**
 * @brief Build self-attention layer
 * 
 * Computes: Attention(Q, K, V) = softmax(Q*K^T / sqrt(d_k)) * V
 * 
 * @param ctx GGML context
 * @param x Input tensor [n_embd, n_tokens]
 * @param layer Layer index
 * @param arch Model architecture
 * @return Output tensor after attention
 */
static struct ggml_rxd_tensor* BuildSelfAttention(
    struct ggml_rxd_context* ctx,
    struct ggml_rxd_tensor* x,
    int layer,
    const ModelArchitecture& arch) {
    
    const int n_embd = arch.embeddingDim;
    const int n_head = arch.numHeads;
    const int n_kv_head = arch.numKVHeads > 0 ? arch.numKVHeads : n_head;
    const int n_tokens = x->ne[1];
    
    // Head dimensions
    const int head_dim = n_embd / n_head;
    const int kv_head_dim = n_embd / n_kv_head;
    
    // Layer prefix for tensor names
    std::string prefix = "blk." + std::to_string(layer) + ".";
    
    // Q projection
    struct ggml_rxd_tensor* wq = ggml_rxd_get_tensor(ctx, (prefix + "attn_q.weight").c_str());
    struct ggml_rxd_tensor* bq = ggml_rxd_get_tensor(ctx, (prefix + "attn_q.bias").c_str());
    struct ggml_rxd_tensor* q = ggml_rxd_mul_mat(ctx, wq, x);
    if (bq) q = ggml_rxd_add(ctx, q, bq);
    
    // K projection
    struct ggml_rxd_tensor* wk = ggml_rxd_get_tensor(ctx, (prefix + "attn_k.weight").c_str());
    struct ggml_rxd_tensor* bk = ggml_rxd_get_tensor(ctx, (prefix + "attn_k.bias").c_str());
    struct ggml_rxd_tensor* k = ggml_rxd_mul_mat(ctx, wk, x);
    if (bk) k = ggml_rxd_add(ctx, k, bk);
    
    // V projection
    struct ggml_rxd_tensor* wv = ggml_rxd_get_tensor(ctx, (prefix + "attn_v.weight").c_str());
    struct ggml_rxd_tensor* bv = ggml_rxd_get_tensor(ctx, (prefix + "attn_v.bias").c_str());
    struct ggml_rxd_tensor* v = ggml_rxd_mul_mat(ctx, wv, x);
    if (bv) v = ggml_rxd_add(ctx, v, bv);
    
    // Reshape for multi-head attention
    // [n_embd, n_tokens] -> [head_dim, n_head, n_tokens]
    q = ggml_rxd_reshape_3d(ctx, q, head_dim, n_head, n_tokens);
    k = ggml_rxd_reshape_3d(ctx, k, kv_head_dim, n_kv_head, n_tokens);
    v = ggml_rxd_reshape_3d(ctx, v, kv_head_dim, n_kv_head, n_tokens);
    
    // Compute attention scores: Q * K^T / sqrt(head_dim)
    struct ggml_rxd_tensor* k_t = ggml_rxd_cont(ctx, ggml_rxd_transpose(ctx, k));
    struct ggml_rxd_tensor* scores = ggml_rxd_mul_mat(ctx, k_t, q);
    scores = ggml_rxd_scale(ctx, scores, 1.0f / sqrtf(static_cast<float>(head_dim)));
    
    // Apply causal mask (for autoregressive generation)
    // TODO: Implement causal mask
    
    // Softmax
    scores = ggml_rxd_soft_max(ctx, scores);
    
    // Apply attention to values
    struct ggml_rxd_tensor* attn_out = ggml_rxd_mul_mat(ctx, v, scores);
    
    // Reshape back: [head_dim, n_head, n_tokens] -> [n_embd, n_tokens]
    attn_out = ggml_rxd_reshape_2d(ctx, attn_out, n_embd, n_tokens);
    
    // Output projection
    struct ggml_rxd_tensor* wo = ggml_rxd_get_tensor(ctx, (prefix + "attn_output.weight").c_str());
    struct ggml_rxd_tensor* bo = ggml_rxd_get_tensor(ctx, (prefix + "attn_output.bias").c_str());
    struct ggml_rxd_tensor* out = ggml_rxd_mul_mat(ctx, wo, attn_out);
    if (bo) out = ggml_rxd_add(ctx, out, bo);
    
    return out;
}

// ============================================================================
// Feed-Forward Network
// ============================================================================

/**
 * @brief Build feed-forward network
 * 
 * Standard FFN: FFN(x) = activation(x*W1 + b1) * W2 + b2
 * Using SwiGLU variant: FFN(x) = (SiLU(x*W_gate) * (x*W_up)) * W_down
 * 
 * @param ctx GGML context
 * @param x Input tensor [n_embd, n_tokens]
 * @param layer Layer index
 * @param arch Model architecture
 * @return Output tensor after FFN
 */
static struct ggml_rxd_tensor* BuildFeedForward(
    struct ggml_rxd_context* ctx,
    struct ggml_rxd_tensor* x,
    int layer,
    const ModelArchitecture& arch) {
    
    const int n_embd = arch.embeddingDim;
    const int n_ff = arch.hiddenDim > 0 ? arch.hiddenDim : 4 * n_embd;
    
    std::string prefix = "blk." + std::to_string(layer) + ".";
    
    // Check for SwiGLU (gated) variant
    struct ggml_rxd_tensor* w_gate = ggml_rxd_get_tensor(ctx, (prefix + "ffn_gate.weight").c_str());
    struct ggml_rxd_tensor* w_up = ggml_rxd_get_tensor(ctx, (prefix + "ffn_up.weight").c_str());
    
    if (w_gate && w_up) {
        // SwiGLU variant
        struct ggml_rxd_tensor* gate = ggml_rxd_mul_mat(ctx, w_gate, x);
        gate = ggml_rxd_silu(ctx, gate);
        
        struct ggml_rxd_tensor* up = ggml_rxd_mul_mat(ctx, w_up, x);
        
        struct ggml_rxd_tensor* hidden = ggml_rxd_mul(ctx, gate, up);
        
        struct ggml_rxd_tensor* w_down = ggml_rxd_get_tensor(ctx, (prefix + "ffn_down.weight").c_str());
        struct ggml_rxd_tensor* out = ggml_rxd_mul_mat(ctx, w_down, hidden);
        
        return out;
    } else {
        // Standard FFN
        struct ggml_rxd_tensor* w1 = ggml_rxd_get_tensor(ctx, (prefix + "ffn_up.weight").c_str());
        struct ggml_rxd_tensor* hidden = ggml_rxd_mul_mat(ctx, w1, x);
        
        // Activation (GELU)
        hidden = ggml_rxd_gelu(ctx, hidden);
        
        struct ggml_rxd_tensor* w2 = ggml_rxd_get_tensor(ctx, (prefix + "ffn_down.weight").c_str());
        struct ggml_rxd_tensor* out = ggml_rxd_mul_mat(ctx, w2, hidden);
        
        return out;
    }
}

// ============================================================================
// Layer Normalization
// ============================================================================

/**
 * @brief Build layer normalization
 * 
 * @param ctx GGML context
 * @param x Input tensor
 * @param weightName Name of weight tensor
 * @param biasName Name of bias tensor (can be null)
 * @param eps Epsilon for numerical stability
 * @return Normalized tensor
 */
static struct ggml_rxd_tensor* BuildLayerNorm(
    struct ggml_rxd_context* ctx,
    struct ggml_rxd_tensor* x,
    const char* weightName,
    const char* biasName,
    float eps) {
    
    struct ggml_rxd_tensor* norm = ggml_rxd_norm(ctx, x, eps);
    
    struct ggml_rxd_tensor* weight = ggml_rxd_get_tensor(ctx, weightName);
    if (weight) {
        norm = ggml_rxd_mul(ctx, norm, weight);
    }
    
    if (biasName) {
        struct ggml_rxd_tensor* bias = ggml_rxd_get_tensor(ctx, biasName);
        if (bias) {
            norm = ggml_rxd_add(ctx, norm, bias);
        }
    }
    
    return norm;
}

// ============================================================================
// Transformer Layer
// ============================================================================

/**
 * @brief Build a complete transformer layer
 * 
 * Standard transformer layer:
 *   x = x + Attention(LayerNorm(x))
 *   x = x + FFN(LayerNorm(x))
 * 
 * @param ctx GGML context
 * @param x Input tensor [n_embd, n_tokens]
 * @param layer Layer index
 * @param arch Model architecture
 * @return Output tensor after transformer layer
 */
struct ggml_rxd_tensor* BuildTransformerLayer(
    struct ggml_rxd_context* ctx,
    struct ggml_rxd_tensor* x,
    int layer,
    const ModelArchitecture& arch) {
    
    std::string prefix = "blk." + std::to_string(layer) + ".";
    
    // Pre-attention layer norm
    struct ggml_rxd_tensor* attn_norm = BuildLayerNorm(
        ctx, x,
        (prefix + "attn_norm.weight").c_str(),
        (prefix + "attn_norm.bias").c_str(),
        1e-5f);
    
    // Self-attention
    struct ggml_rxd_tensor* attn_out = BuildSelfAttention(ctx, attn_norm, layer, arch);
    
    // Residual connection
    struct ggml_rxd_tensor* x_attn = ggml_rxd_add(ctx, x, attn_out);
    
    // Pre-FFN layer norm
    struct ggml_rxd_tensor* ffn_norm = BuildLayerNorm(
        ctx, x_attn,
        (prefix + "ffn_norm.weight").c_str(),
        (prefix + "ffn_norm.bias").c_str(),
        1e-5f);
    
    // Feed-forward network
    struct ggml_rxd_tensor* ffn_out = BuildFeedForward(ctx, ffn_norm, layer, arch);
    
    // Residual connection
    struct ggml_rxd_tensor* out = ggml_rxd_add(ctx, x_attn, ffn_out);
    
    return out;
}

// ============================================================================
// Full Model Forward Pass
// ============================================================================

/**
 * @brief Build complete transformer forward pass graph
 * 
 * @param ctx GGML context
 * @param input_tokens Input token IDs [n_tokens]
 * @param arch Model architecture
 * @return Output logits tensor
 */
struct ggml_rxd_tensor* BuildTransformerForward(
    struct ggml_rxd_context* ctx,
    struct ggml_rxd_tensor* input_tokens,
    const ModelArchitecture& arch) {
    
    const int n_embd = arch.embeddingDim;
    const int n_vocab = arch.vocabSize;
    const int n_tokens = input_tokens->ne[0];
    
    // Token embeddings
    struct ggml_rxd_tensor* token_embed = ggml_rxd_get_tensor(ctx, "token_embd.weight");
    struct ggml_rxd_tensor* x = ggml_rxd_get_rows(ctx, token_embed, input_tokens);
    
    // Add positional embeddings (if available)
    struct ggml_rxd_tensor* pos_embed = ggml_rxd_get_tensor(ctx, "position_embd.weight");
    if (pos_embed) {
        // Create position indices
        struct ggml_rxd_tensor* positions = ggml_rxd_new_tensor_1d(ctx, GGML_RXD_TYPE_I32, n_tokens);
        int32_t* pos_data = (int32_t*)positions->data;
        for (int i = 0; i < n_tokens; i++) {
            pos_data[i] = i;
        }
        
        struct ggml_rxd_tensor* pos_emb = ggml_rxd_get_rows(ctx, pos_embed, positions);
        x = ggml_rxd_add(ctx, x, pos_emb);
    }
    
    // Transformer layers
    for (int layer = 0; layer < arch.numLayers; layer++) {
        x = BuildTransformerLayer(ctx, x, layer, arch);
    }
    
    // Final layer norm
    x = BuildLayerNorm(ctx, x, "output_norm.weight", "output_norm.bias", 1e-5f);
    
    // Output projection (language model head)
    // Often tied with token embeddings
    struct ggml_rxd_tensor* output_weight = ggml_rxd_get_tensor(ctx, "output.weight");
    if (!output_weight) {
        output_weight = token_embed;  // Use tied embeddings
    }
    
    struct ggml_rxd_tensor* logits = ggml_rxd_mul_mat(ctx, output_weight, x);
    
    return logits;
}

} // namespace Inference
} // namespace RawrXD
