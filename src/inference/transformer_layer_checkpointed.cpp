// ============================================================================
// RawrXD Phase 7D: Checkpointed Transformer Layer
// ============================================================================
// Wraps the standard TransformerLayer with cryptographic checkpoint hooks
// This is a non-invasive integration that adds verification to existing code
// ============================================================================

#include "transformer_layer.h"
#include "../integration/gguf_checkpoint_hooks.hpp"
#include <cstdio>

namespace rawrxd {
namespace inference {

// Checkpointed version of TransformerLayer
class TransformerLayerCheckpointed : public TransformerLayer {
public:
    TransformerLayerCheckpointed(const TransformerConfig& config, uint32_t layer_idx,
                                   RawrXD::Integration::GGUFCheckpointContext* checkpoint_ctx)
        : TransformerLayer(config, layer_idx)
        , checkpoint_ctx_(checkpoint_ctx)
        , layer_idx_(layer_idx) {
    }

    // Override Forward to add checkpoints
    std::vector<float> Forward(const std::vector<float>& input, uint32_t seq_len) override {
        if (!checkpoint_ctx_) {
            // No checkpointing, use base implementation
            return TransformerLayer::Forward(input, seq_len);
        }

        uint32_t hidden_size = config_.hidden_size;

        // Checkpoint input
        RAWRXD_CHECKPOINT_RMSNORM(checkpoint_ctx_, input.data(), seq_len, hidden_size, layer_idx_);

        // Step 1: Attention with residual
        auto x_norm = RMSNorm(input, attn_weights_.attn_norm);
        
        // Checkpoint post-RMSNorm
        RAWRXD_CHECKPOINT_RMSNORM(checkpoint_ctx_, x_norm.data(), seq_len, hidden_size, layer_idx_);
        
        auto attn_out = ApplyAttention(x_norm, seq_len);
        
        // Checkpoint attention output
        RAWRXD_CHECKPOINT_ATTENTION(checkpoint_ctx_, attn_out.data(), seq_len, hidden_size, layer_idx_);
        
        // residual1 = input + attn_out
        std::vector<float> residual1(input.size());
        for (size_t i = 0; i < input.size(); ++i) {
            residual1[i] = input[i] + attn_out[i];
        }

        // Step 2: FFN with residual
        auto x_norm2 = RMSNorm(residual1, ffn_weights_.ffn_norm);
        
        // Checkpoint FFN input
        RAWRXD_CHECKPOINT_RMSNORM(checkpoint_ctx_, x_norm2.data(), seq_len, hidden_size, layer_idx_);
        
        auto ffn_out = ApplyFFN(x_norm2);
        
        // Checkpoint FFN output
        RAWRXD_CHECKPOINT_FFN(checkpoint_ctx_, ffn_out.data(), seq_len, hidden_size, layer_idx_);
        
        // output = residual1 + ffn_out
        std::vector<float> output(residual1.size());
        for (size_t i = 0; i < residual1.size(); ++i) {
            output[i] = residual1[i] + ffn_out[i];
        }

        return output;
    }

    // Forward with KV cache and checkpoints
    std::vector<float> ForwardWithCacheCheckpointed(
        const std::vector<float>& input,
        uint32_t seq_len,
        uint32_t start_pos,
        std::vector<float>& k_cache,
        std::vector<float>& v_cache) {
        
        if (!checkpoint_ctx_) {
            return ForwardWithCache(input, seq_len, start_pos, k_cache, v_cache);
        }

        uint32_t hidden_size = config_.hidden_size;
        uint32_t head_dim = config_.head_dim;
        uint32_t num_kv_heads = config_.num_kv_heads;
        uint32_t kv_len = start_pos + seq_len;

        // Step 1: Attention with residual
        auto x_norm = RMSNorm(input, attn_weights_.attn_norm);
        
        // Checkpoint RMSNorm
        RAWRXD_CHECKPOINT_RMSNORM(checkpoint_ctx_, x_norm.data(), seq_len, hidden_size, layer_idx_);
        
        // Apply attention and update KV cache
        auto attn_out = ApplyAttentionWithCache(x_norm, seq_len, start_pos, k_cache, v_cache);
        
        // Checkpoint attention output
        RAWRXD_CHECKPOINT_ATTENTION(checkpoint_ctx_, attn_out.data(), seq_len, hidden_size, layer_idx_);
        
        // Checkpoint KV cache
        if (!k_cache.empty() && !v_cache.empty()) {
            RAWRXD_CHECKPOINT_KV_CACHE(checkpoint_ctx_, 
                                       k_cache.data(), v_cache.data(),
                                       kv_len, head_dim, layer_idx_);
        }
        
        // residual1 = input + attn_out
        std::vector<float> residual1(input.size());
        for (size_t i = 0; i < input.size(); ++i) {
            residual1[i] = input[i] + attn_out[i];
        }

        // Step 2: FFN with residual
        auto x_norm2 = RMSNorm(residual1, ffn_weights_.ffn_norm);
        
        // Checkpoint FFN input
        RAWRXD_CHECKPOINT_RMSNORM(checkpoint_ctx_, x_norm2.data(), seq_len, hidden_size, layer_idx_);
        
        auto ffn_out = ApplyFFN(x_norm2);
        
        // Checkpoint FFN output
        RAWRXD_CHECKPOINT_FFN(checkpoint_ctx_, ffn_out.data(), seq_len, hidden_size, layer_idx_);
        
        // output = residual1 + ffn_out
        std::vector<float> output(residual1.size());
        for (size_t i = 0; i < residual1.size(); ++i) {
            output[i] = residual1[i] + ffn_out[i];
        }

        return output;
    }

private:
    RawrXD::Integration::GGUFCheckpointContext* checkpoint_ctx_ = nullptr;
    uint32_t layer_idx_ = 0;
    
    // Access config from base class
    using TransformerLayer::config_;
    using TransformerLayer::attn_weights_;
    using TransformerLayer::ffn_weights_;
    using TransformerLayer::weights_loaded_;
    using TransformerLayer::RMSNorm;
    using TransformerLayer::ApplyAttention;
    using TransformerLayer::ApplyAttentionWithCache;
    using TransformerLayer::ApplyFFN;
};

} // namespace inference
} // namespace rawrxd
