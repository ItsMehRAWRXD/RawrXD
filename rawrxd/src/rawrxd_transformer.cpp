#include "rawrxd_transformer.hpp"
#include <math>
#include <numeric>
#include <algorithm>
#include <mutex>
#include <string>
#include <stdexcept>

namespace rawrxd {

namespace {
    float Sqrt(float x) { return std::sqrt(x); }
    float Exp(float x) { return std::exp(x); }

    void RmsNorm(std::vector<float>& out, const std::vector<float>& x,
                 const std::vector<float>& weight, float eps) {
        float ss = 0.0f;
        for (auto v : x) ss += v * v;
        ss /= static_cast<float>(x.size());
        ss += eps;
        ss = 1.0f / Sqrt(ss);
        out.resize(x.size());
        for (size_t i = 0; i < x.size(); ++i) out[i] = x[i] * ss * weight[i];
    }

    void Softmax(std::vector<float>& out, const std::vector<float>& x) {
        float max_val = *std::max_element(x.begin(), x.end());
        float sum = 0.0f;
        out.resize(x.size());
        for (size_t i = 0; i < x.size(); ++i) {
            out[i] = Exp(x[i] - max_val);
            sum += out[i];
        }
        if (sum > 0.0f) for (auto& v : out) v /= sum;
    }

    void MatMul(std::vector<float>& out, const std::vector<float>& a,
                const std::vector<float>& b, size_t m, size_t k, size_t n) {
        out.assign(m * n, 0.0f);
        for (size_t i = 0; i < m; ++i) {
            for (size_t j = 0; j < n; ++j) {
                float sum = 0.0f;
                for (size_t l = 0; l < k; ++l) {
                    sum += a[i * k + l] * b[l * n + j];
                }
                out[i * n + j] = sum;
            }
        }
    }
}

class TransformerRuntime::Impl {
public:
    mutable std::mutex mutex_;
    TransformerConfig config_;
    TransformerWeights weights_;
    std::vector<KVCacheEntry> kv_cache_;
    bool loaded_ = false;

    bool AllocateKVCache() {
        kv_cache_.resize(config_.num_hidden_layers);
        size_t cache_size = static_cast<size_t>(config_.max_position_embeddings)
                          * static_cast<size_t>(config_.hidden_size);
        for (auto& entry : kv_cache_) {
            entry.key_cache.assign(cache_size, 0.0f);
            entry.value_cache.assign(cache_size, 0.0f);
            entry.allocated = true;
        }
        return true;
    }

    ForwardResult DoForward(const std::vector<uint32_t>& tokens, int start_pos) {
        ForwardResult result;
        if (tokens.empty()) {
            result.error_message = "Empty token list";
            return result;
        }
        if (!loaded_) {
            result.error_message = "Weights not loaded";
            return result;
        }

        size_t vocab_size = config_.vocab_size;
        size_t hidden_size = config_.hidden_size;
        size_t head_size = hidden_size / config_.num_attention_heads;
        size_t kv_head_size = hidden_size / config_.num_key_value_heads;

        std::vector<float> x(hidden_size);
        for (size_t i = 0; i < tokens.size(); ++i) {
            uint32_t tok = tokens[i];
            if (tok >= vocab_size) tok = 0;
            for (size_t j = 0; j < hidden_size; ++j) {
                x[j] = weights_.token_embedding_table[tok * hidden_size + j];
            }
        }

        for (uint32_t layer = 0; layer < config_.num_hidden_layers; ++layer) {
            std::vector<float> rms_x(hidden_size);
            RmsNorm(rms_x, x, weights_.rms_att_weight, config_.rms_norm_eps);

            // Attention (simplified single-head for clarity)
            size_t q_offset = layer * hidden_size * hidden_size;
            std::vector<float> q(hidden_size), k(hidden_size), v(hidden_size);
            for (size_t i = 0; i < hidden_size; ++i) {
                q[i] = rms_x[i] * weights_.wq[q_offset + i * hidden_size + i];
                k[i] = rms_x[i] * weights_.wk[q_offset + i * hidden_size + i];
                v[i] = rms_x[i] * weights_.wv[q_offset + i * hidden_size + i];
            }

            auto& kv = kv_cache_[layer];
            for (size_t i = 0; i < hidden_size; ++i) {
                kv.key_cache[(start_pos + tokens.size() - 1) * hidden_size + i] = k[i];
                kv.value_cache[(start_pos + tokens.size() - 1) * hidden_size + i] = v[i];
            }

            std::vector<float> attn(hidden_size, 0.0f);
            for (int pos = 0; pos <= static_cast<int>(start_pos + tokens.size() - 1); ++pos) {
                float score = 0.0f;
                for (size_t i = 0; i < hidden_size; ++i) {
                    score += q[i] * kv.key_cache[pos * hidden_size + i];
                }
                score /= Sqrt(static_cast<float>(head_size));
                std::vector<float> scores(start_pos + tokens.size(), 0.0f);
                for (int p = 0; p <= static_cast<int>(start_pos + tokens.size() - 1); ++p) {
                    float s = 0.0f;
                    for (size_t i = 0; i < hidden_size; ++i) {
                        s += q[i] * kv.key_cache[p * hidden_size + i];
                    }
                    s /= Sqrt(static_cast<float>(head_size));
                    scores[p] = s;
                }
                std::vector<float> probs;
                Softmax(probs, scores);
                for (size_t i = 0; i < hidden_size; ++i) {
                    attn[i] += probs[pos] * kv.value_cache[pos * hidden_size + i];
                }
            }

            std::vector<float> wo_out(hidden_size);
            for (size_t i = 0; i < hidden_size; ++i) {
                wo_out[i] = attn[i] * weights_.wo[q_offset + i * hidden_size + i];
            }
            for (size_t i = 0; i < hidden_size; ++i) x[i] += wo_out[i];

            // FFN
            RmsNorm(rms_x, x, weights_.rms_ffn_weight, config_.rms_norm_eps);
            std::vector<float> h1(hidden_size), h2(hidden_size);
            for (size_t i = 0; i < hidden_size; ++i) {
                h1[i] = rms_x[i] * weights_.w1[q_offset + i * hidden_size + i];
                h1[i] = std::max(0.0f, h1[i]); // ReLU
            }
            for (size_t i = 0; i < hidden_size; ++i) {
                h2[i] = h1[i] * weights_.w2[q_offset + i * hidden_size + i];
            }
            for (size_t i = 0; i < hidden_size; ++i) x[i] += h2[i];
        }

        // Final RMS norm
        std::vector<float> final_x(hidden_size);
        RmsNorm(final_x, x, weights_.rms_final_weight, config_.rms_norm_eps);

        // Output logits
        result.logits.resize(vocab_size);
        for (size_t i = 0; i < vocab_size; ++i) {
            float sum = 0.0f;
            for (size_t j = 0; j < hidden_size; ++j) {
                sum += final_x[j] * weights_.wcls[i * hidden_size + j];
            }
            result.logits[i] = sum;
        }
        result.hidden_states = final_x;
        result.success = true;

        float max_logit = *std::max_element(result.logits.begin(), result.logits.end());
        float perplexity_sum = 0.0f;
        for (auto l : result.logits) {
            perplexity_sum += Exp(l - max_logit);
        }
        if (perplexity_sum > 0.0f) {
            result.perplexity = -std::log(perplexity_sum / vocab_size);
        }
        return result;
    }
};

TransformerRuntime::TransformerRuntime() : impl_(std::make_unique<Impl>()) {}
TransformerRuntime::~TransformerRuntime() = default;

bool TransformerRuntime::LoadWeights(const std::string& gguf_path) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    GGUFLoader loader;
    if (!loader.LoadFromFile(gguf_path)) return false;
    impl_->config_ = InferConfigFromGGUF(loader);
    impl_->loaded_ = true;
    impl_->AllocateKVCache();
    return true;
}

bool TransformerRuntime::LoadWeightsFromMemory(const std::vector<uint8_t>& buffer) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    GGUFLoader loader;
    if (!loader.LoadFromMemory(buffer)) return false;
    impl_->config_ = InferConfigFromGGUF(loader);
    impl_->loaded_ = true;
    impl_->AllocateKVCache();
    return true;
}

void TransformerRuntime::SetConfig(const TransformerConfig& config) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->config_ = config;
    impl_->AllocateKVCache();
}

const TransformerConfig& TransformerRuntime::GetConfig() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->config_;
}

bool TransformerRuntime::IsLoaded() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->loaded_;
}

ForwardResult TransformerRuntime::Forward(const std::vector<uint32_t>& tokens, int start_pos) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->DoForward(tokens, start_pos);
}

ForwardResult TransformerRuntime::Forward(const std::vector<uint32_t>& tokens,
                                          std::vector<KVCacheEntry>& kv_cache,
                                          int start_pos) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->kv_cache_ = kv_cache;
    auto result = impl_->DoForward(tokens, start_pos);
    kv_cache = impl_->kv_cache_;
    return result;
}

void TransformerRuntime::ResetKVCache() {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    for (auto& entry : impl_->kv_cache_) {
        std::fill(entry.key_cache.begin(), entry.key_cache.end(), 0.0f);
        std::fill(entry.value_cache.begin(), entry.value_cache.end(), 0.0f);
    }
}

std::vector<float> TransformerRuntime::GetEmbedding(uint32_t token_id) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    std::vector<float> emb;
    if (!impl_->loaded_ || token_id >= impl_->config_.vocab_size) return emb;
    size_t hidden = impl_->config_.hidden_size;
    emb.resize(hidden);
    for (size_t i = 0; i < hidden; ++i) {
        emb[i] = impl_->weights_.token_embedding_table[token_id * hidden + i];
    }
    return emb;
}

TransformerConfig TransformerRuntime::InferConfigFromGGUF(const GGUFLoader& loader) {
    TransformerConfig config = DefaultConfig();
    auto vocab = loader.GetUint32Metadata("vocab_size");
    if (vocab) config.vocab_size = *vocab;
    auto hidden = loader.GetUint32Metadata("hidden_size");
    if (hidden) config.hidden_size = *hidden;
    auto layers = loader.GetUint32Metadata("num_hidden_layers");
    if (layers) config.num_hidden_layers = *layers;
    auto heads = loader.GetUint32Metadata("num_attention_heads");
    if (heads) config.num_attention_heads = *heads;
    auto kv_heads = loader.GetUint32Metadata("num_key_value_heads");
    if (kv_heads) {
        config.num_key_value_heads = *kv_heads;
        config.use_gqa = (*kv_heads != *heads);
    }
    auto max_pos = loader.GetUint32Metadata("max_position_embeddings");
    if (max_pos) config.max_position_embeddings = *max_pos;
    auto rope = loader.GetFloat32Metadata("rope_theta");
    if (rope) config.rope_theta = *rope;
    auto rms = loader.GetFloat32Metadata("rms_norm_eps");
    if (rms) config.rms_norm_eps = *rms;
    return config;
}

TransformerConfig TransformerRuntime::DefaultConfig() {
    TransformerConfig c;
    c.vocab_size = 32000;
    c.hidden_size = 4096;
    c.intermediate_size = 11008;
    c.num_hidden_layers = 32;
    c.num_attention_heads = 32;
    c.num_key_value_heads = 32;
    c.max_position_embeddings = 2048;
    c.rms_norm_eps = 1e-6f;
    c.rope_theta = 10000.0f;
    c.use_rope = true;
    c.use_gqa = false;
    return c;
}

bool TransformerRuntime::ExportWeights(const std::string& /*path*/) const {
    return false;
}

size_t TransformerRuntime::GetWeightBytes() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    size_t total = 0;
    auto add = [&total](const std::vector<float>& v) { total += v.size() * sizeof(float); };
    add(impl_->weights_.token_embedding_table);
    add(impl_->weights_.rms_att_weight);
    add(impl_->weights_.rms_ffn_weight);
    add(impl_->weights_.rms_final_weight);
    add(impl_->weights_.wq); add(impl_->weights_.wk); add(impl_->weights_.wv); add(impl_->weights_.wo);
    add(impl_->weights_.w1); add(impl_->weights_.w2); add(impl_->weights_.w3);
    add(impl_->weights_.freq_cis_real); add(impl_->weights_.freq_cis_imag);
    add(impl_->weights_.wcls);
    return total;
}

size_t TransformerRuntime::GetActivationBytes() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    size_t hidden = impl_->config_.hidden_size;
    size_t layers = impl_->config_.num_hidden_layers;
    return layers * hidden * sizeof(float) * 6;
}

} // namespace rawrxd
