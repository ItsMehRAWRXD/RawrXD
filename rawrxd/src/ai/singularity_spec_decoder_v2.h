#pragma once
#include <cstdint>
#include <memory>

namespace rxd::ai {

struct SingularityV2Config {
    uint32_t vocab_size = 32000;
    uint32_t max_draft_width = 512;
    uint32_t octo_gram_bits = 22;
    uint32_t sedecim_gram_bits = 20;
    uint32_t minhash_slots = 1 << 19;
    uint32_t mlp_hidden = 512;
    uint32_t mlp_embed = 512;
    uint32_t slim_vocab = 2048;
    uint32_t scope_depth = 128;
    uint32_t kv_cache_rows = 8192;
    uint32_t restless_buffers = 4;
    float temperature = 0.8f;
    float accept_target_high = 0.90f;
    float accept_target_low  = 0.20f;
    float bandit_temperature = 0.3f;
};

struct SingularityV2Stats {
    uint64_t drafts_total;
    uint64_t tokens_accepted;
    uint64_t tokens_rejected;
    uint64_t cascade_recoveries;
    uint64_t syntax_oracle_hits;
    uint64_t var_predict_hits;
    uint64_t octo_gram_hits;
    uint64_t sedecim_gram_hits;
    uint64_t minhash_hits;
    uint64_t kv_cache_hits;
    uint64_t restless_prefetch_hits;
    float acceptance_ewma;
    uint32_t current_width;
    float head_bandit_weights[12];
};

class SingularitySpecDecoderV2 {
public:
    explicit SingularitySpecDecoderV2(const SingularityV2Config& cfg);
    ~SingularitySpecDecoderV2();

    uint32_t Draft(const uint32_t* history, uint32_t hist_len,
                   uint32_t* out_draft, uint32_t max_draft);

    uint32_t ValidateArgmax(const uint32_t* draft, uint32_t n,
                            const uint32_t* target_argmax);

    uint32_t ValidateProbabilistic(const uint32_t* draft, uint32_t n,
                                   const float* target_logits,
                                   uint32_t vocab_stride);

    void FeedAccepted(const uint32_t* seq, uint32_t len);

    SingularityV2Stats GetStats() const;
    uint32_t GetDraftWidth() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace rxd::ai
