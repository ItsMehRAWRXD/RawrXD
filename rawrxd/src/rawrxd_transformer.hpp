#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <optional>
#include <functional>
#include "gguf_loader.hpp"

namespace rawrxd {

struct TransformerConfig {
    uint32_t vocab_size = 32000;
    uint32_t hidden_size = 4096;
    uint32_t intermediate_size = 11008;
    uint32_t num_hidden_layers = 32;
    uint32_t num_attention_heads = 32;
    uint32_t num_key_value_heads = 32;
    uint32_t max_position_embeddings = 2048;
    float rms_norm_eps = 1e-6f;
    float rope_theta = 10000.0f;
    float attention_multiplier = 1.0f;
    bool use_rope = true;
    bool use_gqa = false;
    std::string rope_scaling_type;
    float rope_scaling_factor = 1.0f;
};

struct TransformerWeights {
    std::vector<float> token_embedding_table;
    std::vector<float> rms_att_weight;
    std::vector<float> rms_ffn_weight;
    std::vector<float> rms_final_weight;
    std::vector<float> wq;
    std::vector<float> wk;
    std::vector<float> wv;
    std::vector<float> wo;
    std::vector<float> w1;
    std::vector<float> w2;
    std::vector<float> w3;
    std::vector<float> freq_cis_real;
    std::vector<float> freq_cis_imag;
    std::vector<float> wcls;
};

struct ForwardResult {
    std::vector<float> logits;
    std::vector<float> hidden_states;
    bool success = false;
    std::string error_message;
    float perplexity = 0.0f;
};

struct KVCacheEntry {
    std::vector<float> key_cache;
    std::vector<float> value_cache;
    bool allocated = false;
};

class TransformerRuntime {
public:
    TransformerRuntime();
    ~TransformerRuntime();

    bool LoadWeights(const std::string& gguf_path);
    bool LoadWeightsFromMemory(const std::vector<uint8_t>& buffer);

    void SetConfig(const TransformerConfig& config);
    const TransformerConfig& GetConfig() const;

    bool IsLoaded() const;

    ForwardResult Forward(const std::vector<uint32_t>& tokens, int start_pos = 0);
    ForwardResult Forward(const std::vector<uint32_t>& tokens,
                          std::vector<KVCacheEntry>& kv_cache,
                          int start_pos = 0);

    void ResetKVCache();

    std::vector<float> GetEmbedding(uint32_t token_id) const;

    static TransformerConfig InferConfigFromGGUF(const GGUFLoader& loader);
    static TransformerConfig DefaultConfig();

    bool ExportWeights(const std::string& path) const;

    size_t GetWeightBytes() const;
    size_t GetActivationBytes() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace rawrxd
