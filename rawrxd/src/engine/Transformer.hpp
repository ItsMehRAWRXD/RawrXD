#pragma once
#include <string>
#include <vector>
#include <span>
#include <memory>
#include <optional>
#include <functional>
#include <stdint.h>

namespace rawrxd::engine {

// ───────────────────────────────────────────────────────────────
// Tensor shape descriptor
// ───────────────────────────────────────────────────────────────
struct TensorShape {
    std::vector<size_t> dims;
    size_t NumElements() const;
    size_t ByteSize(size_t element_bytes) const;
};

// ───────────────────────────────────────────────────────────────
// Transformer configuration (architecture params)
// ───────────────────────────────────────────────────────────────
struct TransformerConfig {
    uint32_t vocab_size = 32000;
    uint32_t hidden_size = 4096;
    uint32_t intermediate_size = 11008;
    uint32_t num_hidden_layers = 32;
    uint32_t num_attention_heads = 32;
    uint32_t num_key_value_heads = 32;
    uint32_t max_position_embeddings = 4096;
    float rms_norm_eps = 1e-6f;
    float rope_theta = 10000.0f;
    bool use_gqa = false; // grouped-query attention
    std::string rope_scaling_type;
    float rope_scaling_factor = 1.0f;
};

// ───────────────────────────────────────────────────────────────
// Attention weights for a single layer
// ───────────────────────────────────────────────────────────────
struct AttentionWeights {
    std::vector<float> q_proj;
    std::vector<float> k_proj;
    std::vector<float> v_proj;
    std::vector<float> o_proj;
};

// ───────────────────────────────────────────────────────────────
// Feed-forward weights for a single layer
// ───────────────────────────────────────────────────────────────
struct FFNWeights {
    std::vector<float> gate_proj;
    std::vector<float> up_proj;
    std::vector<float> down_proj;
};

// ───────────────────────────────────────────────────────────────
// Transformer layer state
// ───────────────────────────────────────────────────────────────
struct TransformerLayer {
    AttentionWeights attn;
    FFNWeights ffn;
    std::vector<float> input_layernorm;
    std::vector<float> post_attention_layernorm;
};

// ───────────────────────────────────────────────────────────────
// KV cache entry for a single sequence
// ───────────────────────────────────────────────────────────────
struct KVCache {
    std::vector<float> k_cache; // [seq_len, num_kv_heads, head_dim]
    std::vector<float> v_cache; // [seq_len, num_kv_heads, head_dim]
    size_t current_len = 0;
    size_t max_len = 0;
};

// ───────────────────────────────────────────────────────────────
// Transformer — high-level inference engine
// ───────────────────────────────────────────────────────────────
class Transformer {
public:
    Transformer();
    ~Transformer();

    // Configuration
    bool Configure(const TransformerConfig& config);
    TransformerConfig GetConfig() const;

    // Weight loading
    bool LoadWeightsFromGGUF(const std::string& gguf_path);
    bool LoadWeightsFromBuffer(std::span<const uint8_t> data);
    bool IsLoaded() const;

    // Inference
    bool Forward(std::span<const uint32_t> input_tokens,
                  std::vector<float>& logits_out,
                  KVCache& kv_cache);
    bool ForwardLayer(uint32_t layer_idx,
                        std::span<const float> input,
                        std::span<const float> k_cache_in,
                        std::span<const float> v_cache_in,
                        std::vector<float>& output,
                        std::vector<float>& k_cache_out,
                        std::vector<float>& v_cache_out);

    // Attention sub-ops
    void RotaryEmbed(std::vector<float>& q, std::vector<float>& k,
                      size_t seq_len, size_t head_dim, size_t num_heads, size_t num_kv_heads);
    void Softmax(std::vector<float>& x, size_t rows, size_t cols);
    void RMSNorm(std::span<const float> x, std::span<const float> weight, float eps,
                  std::vector<float>& out);
    void SiLU(std::vector<float>& x);

    // KV cache management
    KVCache CreateKVCache(size_t max_seq_len) const;
    void ResetKVCache(KVCache& cache) const;
    size_t GetKVCacheByteSize(size_t max_seq_len) const;

    // Quantization-aware dispatch
    bool SetQuantizationMode(const std::string& mode); // "fp16", "q8_0", "q4_0", "q4_k", "q6_k"
    std::string GetQuantizationMode() const;

    // Performance
    float GetLastForwardTimeMs() const;
    float GetTflopsEstimate() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace rawrxd::engine
