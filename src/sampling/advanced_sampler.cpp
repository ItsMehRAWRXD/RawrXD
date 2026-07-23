// RawrXD Advanced Sampling Implementation
// Phase AM: Advanced Sampling Methods

#include "advanced_sampler.hpp"
#include <algorithm>
#include <cmath>
#include <numeric>

namespace rawrxd {
namespace sampling {

// Global advanced sampler instance
static std::unique_ptr<AdvancedSampler> g_advanced_sampler;

AdvancedSampler* getAdvancedSampler() {
    return g_advanced_sampler.get();
}

void setAdvancedSampler(std::unique_ptr<AdvancedSampler> sampler) {
    g_advanced_sampler = std::move(sampler);
}

// AdvancedSampler implementation
AdvancedSampler::AdvancedSampler()
    : vocab_size_(0)
    , rng_(std::random_device{}())
    , initialized_(false) {
}

AdvancedSampler::~AdvancedSampler() = default;

bool AdvancedSampler::initialize(int vocab_size) {
    vocab_size_ = vocab_size;
    
    // Register samplers
    samplers_[SamplingMethod::GREEDY] = std::make_shared<GreedySampler>();
    samplers_[SamplingMethod::TEMPERATURE] = std::make_shared<TemperatureSampler>();
    samplers_[SamplingMethod::TOP_K] = std::make_shared<TopKSampler>();
    samplers_[SamplingMethod::TOP_P] = std::make_shared<TopPSampler>();
    samplers_[SamplingMethod::MIROSTAT] = std::make_shared<MirostatSampler>();
    
    initialized_ = true;
    return true;
}

void AdvancedSampler::setConfig(const SamplingConfig& config) {
    config_ = config;
}

SamplingConfig AdvancedSampler::getConfig() const {
    return config_;
}

SamplingResult AdvancedSampler::sample(const SamplingContext& context) {
    if (!initialized_) {
        return SamplingResult();
    }
    
    // Extract logits from context
    std::vector<float> logits;
    logits.reserve(context.logits.size());
    for (const auto& tp : context.logits) {
        logits.push_back(tp.logit);
    }
    
    // Apply penalties
    if (config_.repetition_penalty != 1.0f) {
        applyRepetitionPenalty(logits, context.tokens, config_.repetition_penalty);
    }
    if (config_.frequency_penalty != 0.0f) {
        applyFrequencyPenalty(logits, context.tokens, config_.frequency_penalty);
    }
    if (config_.presence_penalty != 0.0f) {
        applyPresencePenalty(logits, context.tokens, config_.presence_penalty);
    }
    
    // Apply temperature
    applyTemperature(logits, config_.temperature);
    
    // Compute probabilities
    std::vector<float> probabilities = softmax(logits);
    
    // Get appropriate sampler
    auto sampler = samplers_[config_.method];
    if (!sampler) {
        sampler = samplers_[SamplingMethod::TEMPERATURE];
    }
    
    SamplingResult result = sampler->sample(probabilities, context);
    result.method_used = sampler->getName();
    
    return result;
}

std::vector<SamplingResult> AdvancedSampler::sampleBatch(const std::vector<SamplingContext>& contexts) {
    std::vector<SamplingResult> results;
    results.reserve(contexts.size());
    
    for (const auto& context : contexts) {
        results.push_back(sample(context));
    }
    
    return results;
}

void AdvancedSampler::applyRepetitionPenalty(std::vector<float>& logits, 
                                              const std::vector<int>& tokens, 
                                              float penalty) {
    if (penalty == 1.0f || tokens.empty()) return;
    
    // Get unique tokens from recent history (last 64 tokens)
    size_t start_idx = tokens.size() > 64 ? tokens.size() - 64 : 0;
    std::unordered_set<int> recent_tokens(tokens.begin() + start_idx, tokens.end());
    
    for (int token_id : recent_tokens) {
        if (token_id >= 0 && token_id < static_cast<int>(logits.size())) {
            if (logits[token_id] > 0) {
                logits[token_id] /= penalty;
            } else {
                logits[token_id] *= penalty;
            }
        }
    }
}

void AdvancedSampler::applyFrequencyPenalty(std::vector<float>& logits,
                                               const std::vector<int>& tokens,
                                               float penalty) {
    if (penalty == 0.0f || tokens.empty()) return;
    
    // Count token frequencies
    std::unordered_map<int, int> token_counts;
    for (int token : tokens) {
        token_counts[token]++;
    }
    
    // Apply penalty based on frequency
    for (const auto& [token_id, count] : token_counts) {
        if (token_id >= 0 && token_id < static_cast<int>(logits.size())) {
            logits[token_id] -= penalty * count;
        }
    }
}

void AdvancedSampler::applyPresencePenalty(std::vector<float>& logits,
                                            const std::vector<int>& tokens,
                                            float penalty) {
    if (penalty == 0.0f || tokens.empty()) return;
    
    // Get unique tokens
    std::unordered_set<int> unique_tokens(tokens.begin(), tokens.end());
    
    // Apply penalty once for each unique token
    for (int token_id : unique_tokens) {
        if (token_id >= 0 && token_id < static_cast<int>(logits.size())) {
            logits[token_id] -= penalty;
        }
    }
}

void AdvancedSampler::applyTemperature(std::vector<float>& logits, float temperature) {
    if (temperature <= 0.0f) temperature = 1.0f;
    if (temperature == 1.0f) return;
    
    for (auto& logit : logits) {
        logit /= temperature;
    }
}

std::vector<float> AdvancedSampler::softmax(const std::vector<float>& logits) {
    std::vector<float> probs(logits.size());
    
    // Find max logit for numerical stability
    float max_logit = *std::max_element(logits.begin(), logits.end());
    
    // Compute exp(logit - max_logit)
    float sum = 0.0f;
    for (size_t i = 0; i < logits.size(); ++i) {
        probs[i] = std::exp(logits[i] - max_logit);
        sum += probs[i];
    }
    
    // Normalize
    for (auto& prob : probs) {
        prob /= sum;
    }
    
    return probs;
}

// ISampler static method definition
std::vector<float> ISampler::softmax(const std::vector<float>& logits) {
    // Static implementation to avoid needing an object
    std::vector<float> probs = logits;
    float max_logit = *std::max_element(probs.begin(), probs.end());
    float sum = 0.0f;
    for (auto& logit : probs) {
        logit = std::exp(logit - max_logit);
        sum += logit;
    }
    for (auto& prob : probs) {
        prob /= sum;
    }
    return probs;
}

std::string AdvancedSampler::methodToString(SamplingMethod method) {
    switch (method) {
        case SamplingMethod::GREEDY: return "Greedy";
        case SamplingMethod::TEMPERATURE: return "Temperature";
        case SamplingMethod::TOP_K: return "Top-K";
        case SamplingMethod::TOP_P: return "Top-P";
        case SamplingMethod::TYPICAL: return "Typical";
        case SamplingMethod::MIROSTAT: return "Mirostat";
        case SamplingMethod::CONTRASTIVE: return "Contrastive";
        case SamplingMethod::BEAM_SEARCH: return "Beam Search";
        case SamplingMethod::DIVERSE_BEAM: return "Diverse Beam";
        case SamplingMethod::SPECULATIVE: return "Speculative";
        case SamplingMethod::CUSTOM: return "Custom";
        default: return "Unknown";
    }
}

SamplingMethod AdvancedSampler::stringToMethod(const std::string& str) {
    if (str == "Greedy") return SamplingMethod::GREEDY;
    if (str == "Temperature") return SamplingMethod::TEMPERATURE;
    if (str == "Top-K" || str == "TopK") return SamplingMethod::TOP_K;
    if (str == "Top-P" || str == "TopP" || str == "Nucleus") return SamplingMethod::TOP_P;
    if (str == "Typical") return SamplingMethod::TYPICAL;
    if (str == "Mirostat") return SamplingMethod::MIROSTAT;
    if (str == "Contrastive") return SamplingMethod::CONTRASTIVE;
    if (str == "Beam Search" || str == "BeamSearch") return SamplingMethod::BEAM_SEARCH;
    if (str == "Diverse Beam" || str == "DiverseBeam") return SamplingMethod::DIVERSE_BEAM;
    if (str == "Speculative") return SamplingMethod::SPECULATIVE;
    return SamplingMethod::CUSTOM;
}

// GreedySampler implementation
SamplingResult GreedySampler::sample(const std::vector<float>& probabilities,
                                      const SamplingContext& context) {
    SamplingResult result;
    
    // Find token with maximum probability
    auto max_it = std::max_element(probabilities.begin(), probabilities.end());
    result.selected_token = static_cast<int>(std::distance(probabilities.begin(), max_it));
    result.confidence = *max_it;
    
    // Get top candidates
    std::vector<TokenProb> candidates;
    for (size_t i = 0; i < probabilities.size(); ++i) {
        candidates.emplace_back(static_cast<int>(i), probabilities[i], 0.0f);
    }
    
    // Sort by probability descending
    std::sort(candidates.begin(), candidates.end(),
              [](const TokenProb& a, const TokenProb& b) {
                  return a.probability > b.probability;
              });
    
    // Keep top 5
    if (candidates.size() > 5) {
        candidates.resize(5);
    }
    result.top_candidates = std::move(candidates);
    
    return result;
}

// TemperatureSampler implementation
SamplingResult TemperatureSampler::sample(const std::vector<float>& probabilities,
                                             const SamplingContext& context) {
    SamplingResult result;
    
    // Sample from the probability distribution
    static thread_local std::mt19937 gen(std::random_device{}());
    std::discrete_distribution<> dist(probabilities.begin(), probabilities.end());
    
    result.selected_token = dist(gen);
    result.confidence = probabilities[result.selected_token];
    
    // Get top candidates
    std::vector<TokenProb> candidates;
    for (size_t i = 0; i < probabilities.size(); ++i) {
        candidates.emplace_back(static_cast<int>(i), probabilities[i], 0.0f);
    }
    
    std::sort(candidates.begin(), candidates.end(),
              [](const TokenProb& a, const TokenProb& b) {
                  return a.probability > b.probability;
              });
    
    if (candidates.size() > 5) {
        candidates.resize(5);
    }
    result.top_candidates = std::move(candidates);
    
    return result;
}

// TopKSampler implementation
SamplingResult TopKSampler::sample(const std::vector<float>& probabilities,
                                    const SamplingContext& context) {
    SamplingResult result;
    
    // Create indexed probabilities
    std::vector<std::pair<int, float>> indexed_probs;
    indexed_probs.reserve(probabilities.size());
    for (size_t i = 0; i < probabilities.size(); ++i) {
        indexed_probs.push_back({static_cast<int>(i), probabilities[i]});
    }
    
    // Sort by probability descending
    std::sort(indexed_probs.begin(), indexed_probs.end(),
              [](const auto& a, const auto& b) {
                  return a.second > b.second;
              });
    
    // Keep top k
    int k = std::min(context.top_k, static_cast<int>(indexed_probs.size()));
    indexed_probs.resize(k);
    
    // Renormalize probabilities
    float sum = 0.0f;
    for (const auto& p : indexed_probs) {
        sum += p.second;
    }
    
    // Sample from top-k
    static thread_local std::mt19937 gen(std::random_device{}());
    std::uniform_real_distribution<float> dist(0.0f, sum);
    float threshold = dist(gen);
    
    float cumulative = 0.0f;
    for (const auto& p : indexed_probs) {
        cumulative += p.second;
        if (cumulative >= threshold) {
            result.selected_token = p.first;
            result.confidence = p.second;
            break;
        }
    }
    
    // Set top candidates
    for (const auto& p : indexed_probs) {
        result.top_candidates.emplace_back(p.first, p.second, 0.0f);
    }
    
    return result;
}

// TopPSampler implementation
SamplingResult TopPSampler::sample(const std::vector<float>& probabilities,
                                    const SamplingContext& context) {
    SamplingResult result;
    
    // Create indexed probabilities
    std::vector<std::pair<int, float>> indexed_probs;
    indexed_probs.reserve(probabilities.size());
    for (size_t i = 0; i < probabilities.size(); ++i) {
        indexed_probs.push_back({static_cast<int>(i), probabilities[i]});
    }
    
    // Sort by probability descending
    std::sort(indexed_probs.begin(), indexed_probs.end(),
              [](const auto& a, const auto& b) {
                  return a.second > b.second;
              });
    
    // Find nucleus (smallest set with cumulative probability >= p)
    float cumulative = 0.0f;
    size_t nucleus_size = 0;
    for (const auto& p : indexed_probs) {
        cumulative += p.second;
        nucleus_size++;
        if (cumulative >= context.top_p) {
            break;
        }
    }
    
    indexed_probs.resize(nucleus_size);
    
    // Renormalize and sample
    float sum = 0.0f;
    for (const auto& p : indexed_probs) {
        sum += p.second;
    }
    
    static thread_local std::mt19937 gen(std::random_device{}());
    std::uniform_real_distribution<float> dist(0.0f, sum);
    float threshold = dist(gen);
    
    float cumsum = 0.0f;
    for (const auto& p : indexed_probs) {
        cumsum += p.second;
        if (cumsum >= threshold) {
            result.selected_token = p.first;
            result.confidence = p.second;
            break;
        }
    }
    
    // Set top candidates
    for (const auto& p : indexed_probs) {
        result.top_candidates.emplace_back(p.first, p.second, 0.0f);
    }
    
    return result;
}

// MirostatSampler implementation
MirostatSampler::MirostatSampler()
    : target_perplexity_(5.0f)
    , learning_rate_(0.1f)
    , current_perplexity_(0.0f)
    , num_tokens_(0) {
}

SamplingResult MirostatSampler::sample(const std::vector<float>& probabilities,
                                        const SamplingContext& context) {
    SamplingResult result;
    
    // Calculate current perplexity from entropy
    float entropy = 0.0f;
    for (float p : probabilities) {
        if (p > 0) {
            entropy -= p * std::log(p);
        }
    }
    current_perplexity_ = std::exp(entropy);
    num_tokens_++;
    
    // Adjust temperature based on perplexity error
    float error = current_perplexity_ - target_perplexity_;
    float temperature = 1.0f + learning_rate_ * error;
    temperature = std::max(0.1f, std::min(temperature, 5.0f));
    
    // Apply temperature and resample
    std::vector<float> adjusted_logits;
    adjusted_logits.reserve(probabilities.size());
    for (float p : probabilities) {
        adjusted_logits.push_back(std::log(std::max(p, 1e-10f)) * temperature);
    }
    
    // Compute new probabilities
    float max_logit = *std::max_element(adjusted_logits.begin(), adjusted_logits.end());
    float sum = 0.0f;
    std::vector<float> new_probs;
    for (float logit : adjusted_logits) {
        float prob = std::exp(logit - max_logit);
        new_probs.push_back(prob);
        sum += prob;
    }
    for (auto& p : new_probs) {
        p /= sum;
    }
    
    // Sample
    static thread_local std::mt19937 gen(std::random_device{}());
    std::discrete_distribution<> dist(new_probs.begin(), new_probs.end());
    
    result.selected_token = dist(gen);
    result.confidence = new_probs[result.selected_token];
    
    // Get top candidates
    std::vector<TokenProb> candidates;
    for (size_t i = 0; i < new_probs.size(); ++i) {
        candidates.emplace_back(static_cast<int>(i), new_probs[i], 0.0f);
    }
    std::sort(candidates.begin(), candidates.end(),
              [](const TokenProb& a, const TokenProb& b) {
                  return a.probability > b.probability;
              });
    if (candidates.size() > 5) {
        candidates.resize(5);
    }
    result.top_candidates = std::move(candidates);
    
    return result;
}

} // namespace sampling
} // namespace rawrxd
