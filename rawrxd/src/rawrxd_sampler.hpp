#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <random>
#include <functional>

namespace rawrxd {

enum class SamplerStrategy {
    Greedy = 0,
    TopK = 1,
    TopP = 2,
    Temperature = 3,
    Mirostat = 4,
    Mirostat2 = 5,
    TailFree = 6,
    Typical = 7,
    Combined = 8
};

struct SamplerConfig {
    SamplerStrategy strategy = SamplerStrategy::Combined;
    float temperature = 0.8f;
    uint32_t top_k = 40;
    float top_p = 0.95f;
    float min_p = 0.05f;
    float tfs_z = 1.0f;
    float typical_p = 1.0f;
    float repeat_penalty = 1.1f;
    uint32_t repeat_last_n = 64;
    float frequency_penalty = 0.0f;
    float presence_penalty = 0.0f;
    float mirostat_tau = 5.0f;
    float mirostat_eta = 0.1f;
    int mirostat_m = 100;
    uint32_t seed = 0;
    bool penalize_nl = false;
};

struct TokenProbability {
    uint32_t token_id;
    float logit;
    float probability;
};

struct SamplerState {
    std::vector<uint32_t> recent_tokens;
    float mirostat_mu = 5.0f;
    std::mt19937 rng;
    uint32_t sample_count = 0;
};

class SamplerResult {
public:
    uint32_t selected_token = 0;
    float selected_probability = 0.0f;
    std::vector<TokenProbability> top_probabilities;
    bool is_end_of_text = false;
};

class Sampler {
public:
    Sampler();
    explicit Sampler(const SamplerConfig& config);
    ~Sampler();

    void SetConfig(const SamplerConfig& config);
    const SamplerConfig& GetConfig() const;

    SamplerResult Sample(const std::vector<float>& logits);
    SamplerResult Sample(const float* logits, size_t count);

    void SetTokenBias(uint32_t token_id, float bias);
    void ClearTokenBiases();

    void ResetState();
    void SetSeed(uint32_t seed);

    void AcceptToken(uint32_t token);

    static float SoftmaxTemperature(const std::vector<float>& logits, float temperature,
                                    std::vector<float>& out_probs);
    static uint32_t GreedySelect(const std::vector<float>& logits);
    static uint32_t TopKSelect(const std::vector<float>& probs, uint32_t k, std::mt19937& rng);
    static uint32_t TopPSelect(const std::vector<float>& probs, float p, std::mt19937& rng);
    static uint32_t MirostatSelect(std::vector<float>& probs, float tau, float eta,
                                    float& mu, std::mt19937& rng);

    bool IsEndToken(uint32_t token) const;
    void SetEndTokens(const std::vector<uint32_t>& tokens);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace rawrxd