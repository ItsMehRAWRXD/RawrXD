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

struct LayerWeights {
    std::vector<float> rms_att_weight;   // [hidden]
    std::vector<float> rms_ffn_weight;   // [hidden]
    // Attention projections. q/o are [n_heads*head_dim, hidden]; k/v are
    // [n_kv_heads*head_dim, hidden] (narrower under GQA).
    std::vector<float> wq;
    std::vector<float> wk;
    std::vector<float> wv;
    std::vector<float> wo;
    // SwiGLU FFN. gate/up are [intermediate, hidden]; down is [hidden, intermediate].
    std::vector<float> w_gate;
    std::vector<float> w_up;
    std::vector<float> w_down;
};

struct TransformerWeights {
    std::vector<float> token_embedding_table;  // [vocab, hidden]
    std::vector<float> rms_final_weight;       // [hidden]
    std::vector<float> wcls;                   // lm_head [vocab, hidden]; may alias embedding
    bool lm_head_tied = false;
    std::vector<LayerWeights> layers;          // one entry per transformer layer
};

struct ForwardResult {
    std::vector<float> logits;
    std::vector<float> hidden_states;
    bool success = false;
    std::string error_message;
    float perplexity = 0.0f;
};

struct KVCacheEntry {
    std::vector<float> key_cache;    // [capacity, kv_dim]
    std::vector<float> value_cache;  // [capacity, kv_dim]
    size_t capacity = 0;             // rows currently allocated
    bool allocated = false;
};

// Per-phase wall-clock attribution for one Forward() call. Populated only
// while profiling is enabled, because the timers themselves are not free in a
// hot loop. Fields are milliseconds.
struct StageTimes {
    double embed_ms = 0.0;
    double proj_qkv_ms = 0.0;   // Wq/Wk/Wv GEMV
    double rope_ms = 0.0;
    double kv_write_ms = 0.0;
    double qk_score_ms = 0.0;   // q . K^T (serial path only)
    double softmax_ms = 0.0;
    double vsum_ms = 0.0;       // weighted sum of V  (serial path only)
    // Fused head-loop time. When heads run in parallel the three phases above
    // cannot be separated without re-running the work, so this single figure is
    // the honest one for the parallel regime.
    double attention_fused_ms = 0.0;
    double out_proj_ms = 0.0;   // Wo GEMV
    double mlp_ms = 0.0;        // gate/up GEMVs + SiLU + down GEMV
    double norm_ms = 0.0;       // RMSNorm calls
    double lm_head_ms = 0.0;
    double total_ms = 0.0;
    uint64_t layers = 0;
    uint64_t heads = 0;
    double Sum() const {
        return embed_ms + proj_qkv_ms + rope_ms + kv_write_ms + qk_score_ms +
               softmax_ms + vsum_ms + attention_fused_ms + out_proj_ms + mlp_ms +
               norm_ms + lm_head_ms;
    }
    double AttentionTotal() const {
        return attention_fused_ms + qk_score_ms + softmax_ms + vsum_ms;
    }
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

    // Stage profiling. Disabled by default; enable explicitly before calling
    // Forward, and read StageTimes() afterwards.
    void SetProfiling(bool on) { profiling_ = on; }
    bool IsProfiling() const { return profiling_; }
    StageTimes StageTimesResult() const;
    void ResetStageTimes();

    std::vector<float> GetEmbedding(uint32_t token_id) const;

    static TransformerConfig InferConfigFromGGUF(const GGUFLoader& loader);
    static TransformerConfig DefaultConfig();

    bool ExportWeights(const std::string& path) const;

    size_t GetWeightBytes() const;
    size_t GetActivationBytes() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
    bool profiling_ = false;
};

} // namespace rawrxd
