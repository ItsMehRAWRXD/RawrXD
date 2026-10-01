#include "Transformer.hpp"
#include <chrono>
#include <cmath>
#include <numeric>
#include <algorithm>

namespace rawrxd::engine {

class Transformer::Impl {
public:
    TransformerConfig config_;
    bool loaded_ = false;
    std::vector<TransformerLayer> layers_;
    std::vector<float> token_embeddings_;
    std::vector<float> output_norm_weight_;
    std::vector<float> lm_head_;
    float last_forward_ms_ = 0.0f;
    std::string quant_mode_ = "fp32";
};

Transformer::Transformer() : impl_(std::make_unique<Impl>()) {}
Transformer::~Transformer() = default;

bool Transformer::Configure(const TransformerConfig& config) {
    impl_->config_ = config;
    return true;
}

TransformerConfig Transformer::GetConfig() const {
    return impl_->config_;
}

bool Transformer::LoadWeightsFromGGUF(const std::string& /*gguf_path*/) {
    // RAWRXD_P0_FAIL_CLOSED_001: this never reads the file. Setting loaded_ here
    // let Forward() run over empty weights and emit synthetic logits that looked
    // like model output. There is no real implementation behind this entry point,
    // so it must not report success.
    impl_->layers_.clear();
    impl_->token_embeddings_.clear();
    impl_->output_norm_weight_.clear();
    impl_->lm_head_.clear();
    impl_->loaded_ = false;
    return false;
}

bool Transformer::LoadWeightsFromBuffer(std::span<const uint8_t> /*data*/) {
    impl_->layers_.clear();
    impl_->token_embeddings_.clear();
    impl_->output_norm_weight_.clear();
    impl_->lm_head_.clear();
    impl_->loaded_ = false;
    return false;
}

bool Transformer::IsLoaded() const {
    return impl_->loaded_;
}

bool Transformer::Forward(std::span<const uint32_t> input_tokens,
                              std::vector<float>& logits_out,
                              KVCache& kv_cache) {
    auto start = std::chrono::steady_clock::now();
    // RAWRXD_P0_FAIL_CLOSED_001: Forward below synthesised embeddings from
    // (token % 1000) and wrote one identical value into every vocabulary slot,
    // so callers received plausible-looking text with no relation to any model.
    // Refuse rather than fabricate. A real forward pass lives in
    // src/deep2/Deep2Engine.cpp (forwardTokenAllLayers) and in
    // src/rawrxd_transformer.cpp (LoadAllWeights + DoForward).
    logits_out.clear();
    if (!impl_->loaded_) return false;
    if (input_tokens.empty()) return false;
    if (impl_->token_embeddings_.empty() || impl_->lm_head_.empty()) return false;

    return false;  // no real weight-backed forward pass exists in this class
}


bool Transformer::ForwardLayer(uint32_t layer_idx,
                                std::span<const float> input,
                                std::span<const float> k_cache_in,
                                std::span<const float> v_cache_in,
                                std::vector<float>& output,
                                std::vector<float>& k_cache_out,
                                std::vector<float>& v_cache_out) {
    // RAWRXD_P0_FAIL_CLOSED_001: this copied input to output and the caches to
    // themselves, so it reported success while doing no attention. A caller
    // treating this as a real layer got an identity transform.
    output.clear();
    k_cache_out.clear();
    v_cache_out.clear();
    if (!impl_->loaded_ || layer_idx >= impl_->config_.num_hidden_layers) return false;
    if (impl_->layers_.empty()) return false;
    return false;  // no real per-layer implementation exists in this class
}

void Transformer::RotaryEmbed(std::vector<float>& q, std::vector<float>& k,
                                size_t seq_len, size_t head_dim, size_t num_heads, size_t num_kv_heads) {
    for (size_t pos = 0; pos < seq_len; ++pos) {
        for (size_t h = 0; h < num_heads; ++h) {
            for (size_t d = 0; d < head_dim; d += 2) {
                float theta = std::pow(impl_->config_.rope_theta, -2.0f * d / head_dim);
                float cos_val = std::cos(pos * theta);
                float sin_val = std::sin(pos * theta);
                size_t base = pos * num_heads * head_dim + h * head_dim + d;
                if (base + 1 < q.size()) {
                    float q0 = q[base], q1 = q[base + 1];
                    q[base] = q0 * cos_val - q1 * sin_val;
                    q[base + 1] = q0 * sin_val + q1 * cos_val;
                }
            }
        }
    }
    // RAWRXD_P0_FAIL_CLOSED_001: K previously ran `k[i] = k[i]*0.99f + 0.001f`,
    // which is not a rotation and destroyed the key cache. Apply the same
    // rotate-half used for Q, iterating the KV heads (GQA: n_kv_heads may be
    // fewer than n_heads, so K is laid out per KV head, not per query head).
    for (size_t pos = 0; pos < seq_len; ++pos) {
        for (size_t h = 0; h < num_kv_heads; ++h) {
            for (size_t d = 0; d < head_dim; d += 2) {
                const float theta = std::pow(impl_->config_.rope_theta, -2.0f * d / head_dim);
                const float cos_val = std::cos(pos * theta);
                const float sin_val = std::sin(pos * theta);
                const size_t base = pos * num_kv_heads * head_dim + h * head_dim + d;
                if (base + 1 < k.size()) {
                    const float k0 = k[base];
                    const float k1 = k[base + 1];
                    k[base] = k0 * cos_val - k1 * sin_val;
                    k[base + 1] = k0 * sin_val + k1 * cos_val;
                }
            }
        }
    }
}

void Transformer::Softmax(std::vector<float>& x, size_t rows, size_t cols) {
    for (size_t r = 0; r < rows; ++r) {
        float max_val = x[r * cols];
        for (size_t c = 1; c < cols; ++c) max_val = std::max(max_val, x[r * cols + c]);
        float sum = 0.0f;
        for (size_t c = 0; c < cols; ++c) {
            x[r * cols + c] = std::exp(x[r * cols + c] - max_val);
            sum += x[r * cols + c];
        }
        for (size_t c = 0; c < cols; ++c) x[r * cols + c] /= sum;
    }
}

void Transformer::RMSNorm(std::span<const float> x, std::span<const float> weight, float eps,
                            std::vector<float>& out) {
    size_t hidden = weight.size();
    out.resize(hidden);
    float ss = 0.0f;
    for (size_t i = 0; i < hidden; ++i) ss += x[i] * x[i];
    float rms = std::sqrt(ss / hidden + eps);
    for (size_t i = 0; i < hidden; ++i) out[i] = x[i] * weight[i] / rms;
}

void Transformer::SiLU(std::vector<float>& x) {
    for (auto& v : x) v = v * (1.0f / (1.0f + std::exp(-v)));
}

KVCache Transformer::CreateKVCache(size_t max_seq_len) const {
    KVCache cache;
    size_t head_dim = impl_->config_.hidden_size / impl_->config_.num_attention_heads;
    size_t num_kv_heads = impl_->config_.use_gqa ? impl_->config_.num_key_value_heads : impl_->config_.num_attention_heads;
    size_t elem_count = max_seq_len * num_kv_heads * head_dim;
    cache.k_cache.resize(elem_count, 0.0f);
    cache.v_cache.resize(elem_count, 0.0f);
    cache.max_len = max_seq_len;
    cache.current_len = 0;
    return cache;
}

void Transformer::ResetKVCache(KVCache& cache) const {
    cache.current_len = 0;
    std::fill(cache.k_cache.begin(), cache.k_cache.end(), 0.0f);
    std::fill(cache.v_cache.begin(), cache.v_cache.end(), 0.0f);
}

size_t Transformer::GetKVCacheByteSize(size_t max_seq_len) const {
    size_t head_dim = impl_->config_.hidden_size / impl_->config_.num_attention_heads;
    size_t num_kv_heads = impl_->config_.use_gqa ? impl_->config_.num_key_value_heads : impl_->config_.num_attention_heads;
    size_t elem_count = max_seq_len * num_kv_heads * head_dim * 2; // K + V
    return elem_count * sizeof(float);
}

bool Transformer::SetQuantizationMode(const std::string& mode) {
    impl_->quant_mode_ = mode;
    return true;
}

std::string Transformer::GetQuantizationMode() const {
    return impl_->quant_mode_;
}

float Transformer::GetLastForwardTimeMs() const {
    return impl_->last_forward_ms_;
}

float Transformer::GetTflopsEstimate() const {
    // Simplified TFLOPS: 2 * params * tokens / time
    size_t params = static_cast<size_t>(impl_->config_.num_hidden_layers) * 7ULL * impl_->config_.hidden_size * impl_->config_.hidden_size;
    if (impl_->last_forward_ms_ <= 0.0f) return 0.0f;
    float ops = 2.0f * params / 1e9f;
    return ops / (impl_->last_forward_ms_ / 1000.0f);
}

} // namespace rawrxd::engine
