#include "rawrxd_sampler.hpp"
#include <cmath>
#include <numeric>
#include <algorithm>
#include <random>
#include <mutex>
#include <unordered_map>

namespace rawrxd {

class Sampler::Impl {
public:
    SamplerConfig config_;
    SamplerState state_;
    std::vector<uint32_t> end_tokens_;
    std::unordered_map<uint32_t, float> token_biases_;
    mutable std::mutex mutex_;

    Impl() {
        std::random_device rd;
        state_.rng.seed(rd());
    }

    void ApplyBiases(std::vector<float>& logits) {
        for (auto& [id, bias] : token_biases_) {
            if (id < logits.size()) logits[id] += bias;
        }
    }

    void ApplyRepeatPenalty(std::vector<float>& logits) {
        if (config_.repeat_penalty == 1.0f && config_.frequency_penalty == 0.0f && config_.presence_penalty == 0.0f) return;
        size_t n = std::min(static_cast<size_t>(config_.repeat_last_n), state_.recent_tokens.size());
        std::unordered_map<uint32_t, uint32_t> counts;
        for (size_t i = state_.recent_tokens.size() - n; i < state_.recent_tokens.size(); ++i) {
            counts[state_.recent_tokens[i]]++;
        }
        for (auto& [token, count] : counts) {
            if (token >= logits.size()) continue;
            float penalty = config_.repeat_penalty;
            if (logits[token] > 0) logits[token] /= penalty;
            else logits[token] *= penalty;
            logits[token] -= config_.frequency_penalty * static_cast<float>(count);
            logits[token] -= config_.presence_penalty;
        }
    }

    void ApplyTemperature(std::vector<float>& logits) {
        if (config_.temperature <= 0.0f) return;
        for (auto& v : logits) v /= config_.temperature;
    }

    std::vector<float> Softmax(const std::vector<float>& logits) {
        float max_val = *std::max_element(logits.begin(), logits.end());
        std::vector<float> probs(logits.size());
        float sum = 0.0f;
        for (size_t i = 0; i < logits.size(); ++i) {
            probs[i] = std::exp(logits[i] - max_val);
            sum += probs[i];
        }
        if (sum > 0.0f) {
            for (auto& p : probs) p /= sum;
        }
        return probs;
    }

    uint32_t GreedySelect(const std::vector<float>& logits) {
        return static_cast<uint32_t>(std::distance(logits.begin(),
            std::max_element(logits.begin(), logits.end())));
    }

    uint32_t TopKSelect(std::vector<float>& probs, uint32_t k, std::mt19937& rng) {
        if (k >= probs.size()) return GreedySelect(probs);
        std::vector<size_t> indices(probs.size());
        std::iota(indices.begin(), indices.end(), 0);
        std::nth_element(indices.begin(), indices.begin() + k, indices.end(),
            [&probs](size_t a, size_t b) { return probs[a] > probs[b]; });
        float sum = 0.0f;
        for (uint32_t i = 0; i < k; ++i) sum += probs[indices[i]];
        if (sum <= 0.0f) return indices[0];
        std::uniform_real_distribution<float> dist(0.0f, sum);
        float r = dist(rng);
        float acc = 0.0f;
        for (uint32_t i = 0; i < k; ++i) {
            acc += probs[indices[i]];
            if (r <= acc) return static_cast<uint32_t>(indices[i]);
        }
        return static_cast<uint32_t>(indices[k - 1]);
    }

    uint32_t TopPSelect(std::vector<float>& probs, float p, std::mt19937& rng) {
        std::vector<size_t> indices(probs.size());
        std::iota(indices.begin(), indices.end(), 0);
        std::sort(indices.begin(), indices.end(),
            [&probs](size_t a, size_t b) { return probs[a] > probs[b]; });
        float cumsum = 0.0f;
        size_t cutoff = probs.size();
        for (size_t i = 0; i < probs.size(); ++i) {
            cumsum += probs[indices[i]];
            if (cumsum >= p) { cutoff = i + 1; break; }
        }
        std::vector<uint32_t> selected;
        selected.reserve(cutoff);
        std::vector<float> selected_probs;
        selected_probs.reserve(cutoff);
        for (size_t i = 0; i < cutoff; ++i) {
            selected.push_back(static_cast<uint32_t>(indices[i]));
            selected_probs.push_back(probs[indices[i]]);
        }
        float sum = std::accumulate(selected_probs.begin(), selected_probs.end(), 0.0f);
        if (sum <= 0.0f) return selected.empty() ? 0 : selected[0];
        std::uniform_real_distribution<float> dist(0.0f, sum);
        float r = dist(rng);
        float acc = 0.0f;
        for (size_t i = 0; i < selected.size(); ++i) {
            acc += selected_probs[i];
            if (r <= acc) return selected[i];
        }
        return selected.back();
    }

    uint32_t MirostatSelect(std::vector<float>& probs, float tau, float eta, float& mu, std::mt19937& rng) {
        float entropy = 0.0f;
        for (auto p : probs) {
            if (p > 0.0f) entropy -= p * std::log(p);
        }
        float error = entropy - mu;
        mu -= eta * error;
        if (mu < 0.0f) mu = 0.0f;
        std::vector<uint32_t> candidates;
        float sum = 0.0f;
        for (size_t i = 0; i < probs.size(); ++i) {
            if (probs[i] > 0.0f) {
                sum += probs[i];
                if (sum <= mu) candidates.push_back(static_cast<uint32_t>(i));
                else break;
            }
        }
        if (candidates.empty()) candidates.push_back(GreedySelect(probs));
        std::uniform_int_distribution<size_t> dist(0, candidates.size() - 1);
        return candidates[dist(rng)];
    }

    SamplerResult DoSample(const float* logits_data, size_t count) {
        SamplerResult result;
        std::vector<float> logits(logits_data, logits_data + count);
        ApplyBiases(logits);
        ApplyRepeatPenalty(logits);
        ApplyTemperature(logits);
        std::vector<float> probs = Softmax(logits);
        uint32_t selected = 0;
        switch (config_.strategy) {
            case SamplerStrategy::Greedy:
                selected = GreedySelect(logits);
                break;
            case SamplerStrategy::TopK:
                selected = TopKSelect(probs, config_.top_k, state_.rng);
                break;
            case SamplerStrategy::TopP:
                selected = TopPSelect(probs, config_.top_p, state_.rng);
                break;
            case SamplerStrategy::Mirostat:
                selected = MirostatSelect(probs, config_.mirostat_tau, config_.mirostat_eta,
                                          state_.mirostat_mu, state_.rng);
                break;
            case SamplerStrategy::Mirostat2:
                selected = MirostatSelect(probs, config_.mirostat_tau, config_.mirostat_eta,
                                          state_.mirostat_mu, state_.rng);
                break;
            case SamplerStrategy::Temperature:
                selected = TopPSelect(probs, 1.0f, state_.rng);
                break;
            default: {
                selected = TopKSelect(probs, config_.top_k, state_.rng);
                std::vector<float> filtered = probs;
                float p_sum = 0.0f;
                for (uint32_t i = 0; i < count; ++i) {
                    if (probs[i] < config_.min_p) filtered[i] = 0.0f;
                    p_sum += filtered[i];
                }
                if (p_sum > 0.0f) {
                    for (auto& v : filtered) v /= p_sum;
                    selected = TopPSelect(filtered, config_.top_p, state_.rng);
                }
            } break;
        }
        result.selected_token = selected;
        result.selected_probability = (selected < probs.size()) ? probs[selected] : 0.0f;
        result.is_end_of_text = IsEndToken(selected);
        std::vector<size_t> top_indices(probs.size());
        std::iota(top_indices.begin(), top_indices.end(), 0);
        std::partial_sort(top_indices.begin(), top_indices.begin() + std::min(size_t(10), top_indices.size()),
                          top_indices.end(), [&probs](size_t a, size_t b) { return probs[a] > probs[b]; });
        for (size_t i = 0; i < std::min(size_t(5), top_indices.size()); ++i) {
            result.top_probabilities.push_back({static_cast<uint32_t>(top_indices[i]), logits[top_indices[i]], probs[top_indices[i]]});
        }
        state_.recent_tokens.push_back(selected);
        state_.sample_count++;
        return result;
    }

    bool IsEndToken(uint32_t token) const {
        for (auto e : end_tokens_) if (e == token) return true;
        return false;
    }
};

Sampler::Sampler() : impl_(std::make_unique<Impl>()) {}
Sampler::Sampler(const SamplerConfig& config) : impl_(std::make_unique<Impl>()) {
    impl_->config_ = config;
}
Sampler::~Sampler() = default;

void Sampler::SetConfig(const SamplerConfig& config) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->config_ = config;
}
const SamplerConfig& Sampler::GetConfig() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->config_;
}

SamplerResult Sampler::Sample(const std::vector<float>& logits) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->DoSample(logits.data(), logits.size());
}
SamplerResult Sampler::Sample(const float* logits, size_t count) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->DoSample(logits, count);
}

void Sampler::SetTokenBias(uint32_t token_id, float bias) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->token_biases_[token_id] = bias;
}
void Sampler::ClearTokenBiases() {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->token_biases_.clear();
}

void Sampler::ResetState() {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->state_ = SamplerState{};
    std::random_device rd;
    impl_->state_.rng.seed(rd());
}

void Sampler::SetSeed(uint32_t seed) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->state_.rng.seed(seed);
}

void Sampler::AcceptToken(uint32_t token) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->state_.recent_tokens.push_back(token);
}

bool Sampler::IsEndToken(uint32_t token) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->IsEndToken(token);
}

void Sampler::SetEndTokens(const std::vector<uint32_t>& tokens) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->end_tokens_ = tokens;
}

float Sampler::SoftmaxTemperature(const std::vector<float>& logits, float temperature,
                                 std::vector<float>& out_probs) {
    out_probs.resize(logits.size());
    float max_val = *std::max_element(logits.begin(), logits.end());
    float sum = 0.0f;
    for (size_t i = 0; i < logits.size(); ++i) {
        out_probs[i] = std::exp((logits[i] - max_val) / std::max(temperature, 1e-6f));
        sum += out_probs[i];
    }
    if (sum > 0.0f) {
        for (auto& p : out_probs) p /= sum;
    }
    return sum;
}

uint32_t Sampler::GreedySelect(const std::vector<float>& logits) {
    return static_cast<uint32_t>(std::distance(logits.begin(),
        std::max_element(logits.begin(), logits.end())));
}

uint32_t Sampler::TopKSelect(const std::vector<float>& probs, uint32_t k, std::mt19937& rng) {
    if (k >= probs.size()) return GreedySelect(probs);
    std::vector<size_t> indices(probs.size());
    std::iota(indices.begin(), indices.end(), 0);
    std::nth_element(indices.begin(), indices.begin() + k, indices.end(),
        [&probs](size_t a, size_t b) { return probs[a] > probs[b]; });
    float sum = 0.0f;
    for (uint32_t i = 0; i < k; ++i) sum += probs[indices[i]];
    if (sum <= 0.0f) return static_cast<uint32_t>(indices[0]);
    std::uniform_real_distribution<float> dist(0.0f, sum);
    float r = dist(rng);
    float acc = 0.0f;
    for (uint32_t i = 0; i < k; ++i) {
        acc += probs[indices[i]];
        if (r <= acc) return static_cast<uint32_t>(indices[i]);
    }
    return static_cast<uint32_t>(indices[k - 1]);
}

uint32_t Sampler::TopPSelect(const std::vector<float>& probs, float p, std::mt19937& rng) {
    std::vector<size_t> indices(probs.size());
    std::iota(indices.begin(), indices.end(), 0);
    std::sort(indices.begin(), indices.end(),
        [&probs](size_t a, size_t b) { return probs[a] > probs[b]; });
    float cumsum = 0.0f;
    size_t cutoff = probs.size();
    for (size_t i = 0; i < probs.size(); ++i) {
        cumsum += probs[indices[i]];
        if (cumsum >= p) { cutoff = i + 1; break; }
    }
    std::vector<uint32_t> selected;
    selected.reserve(cutoff);
    std::vector<float> sel_probs;
    sel_probs.reserve(cutoff);
    for (size_t i = 0; i < cutoff; ++i) {
        selected.push_back(static_cast<uint32_t>(indices[i]));
        sel_probs.push_back(probs[indices[i]]);
    }
    float sum = std::accumulate(sel_probs.begin(), sel_probs.end(), 0.0f);
    if (sum <= 0.0f) return selected.empty() ? 0 : selected[0];
    std::uniform_real_distribution<float> dist(0.0f, sum);
    float r = dist(rng);
    float acc = 0.0f;
    for (size_t i = 0; i < selected.size(); ++i) {
        acc += sel_probs[i];
        if (r <= acc) return selected[i];
    }
    return selected.back();
}

uint32_t Sampler::MirostatSelect(std::vector<float>& probs, float tau, float eta,
                                 float& mu, std::mt19937& rng) {
    float entropy = 0.0f;
    for (auto p : probs) {
        if (p > 0.0f) entropy -= p * std::log(p);
    }
    float error = entropy - mu;
    mu -= eta * error;
    if (mu < 0.0f) mu = 0.0f;
    std::vector<uint32_t> candidates;
    float sum = 0.0f;
    for (size_t i = 0; i < probs.size(); ++i) {
        if (probs[i] > 0.0f) {
            sum += probs[i];
            if (sum <= mu) candidates.push_back(static_cast<uint32_t>(i));
            else break;
        }
    }
    if (candidates.empty()) candidates.push_back(GreedySelect(probs));
    std::uniform_int_distribution<size_t> dist(0, candidates.size() - 1);
    return candidates[dist(rng)];
}

} // namespace rawrxd
