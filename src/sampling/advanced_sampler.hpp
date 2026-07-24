// RawrXD Advanced Sampling Methods
// Phase AM: Advanced Sampling Methods

#pragma once

#include <vector>
#include <string>
#include <memory>
#include <random>
#include <functional>
#include <unordered_set>
#include <unordered_map>

namespace rawrxd {
namespace sampling {

// Sampling methods
enum class SamplingMethod {
    GREEDY,              // Greedy decoding
    TEMPERATURE,         // Temperature sampling
    TOP_K,               // Top-k sampling
    TOP_P,               // Nucleus (top-p) sampling
    TYPICAL,             // Typical sampling
    MIROSTAT,            // Mirostat sampling
    CONTRASTIVE,         // Contrastive search
    BEAM_SEARCH,         // Beam search
    DIVERSE_BEAM,        // Diverse beam search
    SPECULATIVE,         // Speculative decoding
    CUSTOM
};

// Sampling configuration
struct SamplingConfig {
    SamplingMethod method;
    float temperature;
    int top_k;
    float top_p;
    float typical_p;
    float repetition_penalty;
    float frequency_penalty;
    float presence_penalty;
    int mirostat_tau;
    float mirostat_eta;
    int beam_width;
    float diversity_penalty;
    int speculative_tokens;
    
    SamplingConfig()
        : method(SamplingMethod::TEMPERATURE)
        , temperature(0.8f)
        , top_k(40)
        , top_p(0.9f)
        , typical_p(1.0f)
        , repetition_penalty(1.0f)
        , frequency_penalty(0.0f)
        , presence_penalty(0.0f)
        , mirostat_tau(5)
        , mirostat_eta(0.1f)
        , beam_width(4)
        , diversity_penalty(0.5f)
        , speculative_tokens(5) {}
};

// Token probability
struct TokenProb {
    int token_id;
    float probability;
    float logit;
    
    TokenProb(int id = 0, float prob = 0.0f, float log = 0.0f)
        : token_id(id), probability(prob), logit(log) {}
};

// Sampling context
struct SamplingContext {
    std::vector<int> tokens;
    std::vector<TokenProb> logits;
    int vocab_size;
    int current_step;
    float entropy;
    float perplexity;
    int top_k;           // Top-k parameter
    float top_p;         // Top-p (nucleus) parameter
    
    SamplingContext() 
        : vocab_size(0), current_step(0), entropy(0.0f), perplexity(0.0f)
        , top_k(40), top_p(0.9f) {}
};

// Sampling result
struct SamplingResult {
    int selected_token;
    float confidence;
    std::vector<TokenProb> top_candidates;
    std::string method_used;
    
    SamplingResult() : selected_token(0), confidence(0.0f) {}
};

// Forward declarations
class ISampler;
class AdvancedSampler;

/**
 * AdvancedSampler - Main sampling coordinator
 */
class AdvancedSampler {
public:
    AdvancedSampler();
    ~AdvancedSampler();
    
    // Initialize sampler
    bool initialize(int vocab_size);
    
    // Configure sampling
    void setConfig(const SamplingConfig& config);
    SamplingConfig getConfig() const;
    
    // Sample next token
    SamplingResult sample(const SamplingContext& context);
    
    // Batch sampling
    std::vector<SamplingResult> sampleBatch(const std::vector<SamplingContext>& contexts);
    
    // Apply penalties
    void applyRepetitionPenalty(std::vector<float>& logits, const std::vector<int>& tokens, float penalty);
    void applyFrequencyPenalty(std::vector<float>& logits, const std::vector<int>& tokens, float penalty);
    void applyPresencePenalty(std::vector<float>& logits, const std::vector<int>& tokens, float penalty);
    
    // Temperature scaling
    void applyTemperature(std::vector<float>& logits, float temperature);
    
    // Softmax computation
    std::vector<float> softmax(const std::vector<float>& logits);
    
    // Utility functions
    static std::string methodToString(SamplingMethod method);
    static SamplingMethod stringToMethod(const std::string& str);
    
private:
    SamplingConfig config_;
    int vocab_size_;
    
    std::unordered_map<SamplingMethod, std::shared_ptr<ISampler>> samplers_;
    std::mt19937 rng_;
    
    bool initialized_;
};

/**
 * ISampler - Base sampler interface
 */
class ISampler {
public:
    virtual ~ISampler() = default;
    
    virtual SamplingResult sample(const std::vector<float>& probabilities,
                                   const SamplingContext& context) = 0;
    virtual std::string getName() const = 0;
    virtual std::string getDescription() const = 0;
    
    // Reset sampler state for new conversation
    virtual void Reset() {}
    
    // Sample from logits directly (convenience method)
    virtual int Sample(const std::vector<float>& logits) {
        SamplingContext ctx;
        ctx.vocab_size = static_cast<int>(logits.size());
        auto probs = softmax(logits);
        auto result = sample(probs, ctx);
        return result.selected_token;
    }
    
    // Accept a token (for speculative decoding)
    virtual void AcceptToken(int token) {}
    
protected:
    // Helper for subclasses
    static std::vector<float> softmax(const std::vector<float>& logits);
};

/**
 * GreedySampler - Greedy decoding
 */
class GreedySampler : public ISampler {
public:
    SamplingResult sample(const std::vector<float>& probabilities,
                           const SamplingContext& context) override;
    std::string getName() const override { return "Greedy"; }
    std::string getDescription() const override {
        return "Selects the token with highest probability";
    }
};

/**
 * TemperatureSampler - Temperature-based sampling
 */
class TemperatureSampler : public ISampler {
public:
    SamplingResult sample(const std::vector<float>& probabilities,
                           const SamplingContext& context) override;
    std::string getName() const override { return "Temperature"; }
    std::string getDescription() const override {
        return "Applies temperature scaling before sampling";
    }
};

/**
 * TopKSampler - Top-k sampling
 */
class TopKSampler : public ISampler {
public:
    TopKSampler(int k = 40, float temperature = 0.8f)
        : k_(k), temperature_(temperature) {}
    
    SamplingResult sample(const std::vector<float>& probabilities,
                           const SamplingContext& context) override;
    std::string getName() const override { return "Top-K"; }
    std::string getDescription() const override {
        return "Samples from top k most likely tokens";
    }
    
    void setK(int k) { k_ = k; }
    void setTemperature(float temp) { temperature_ = temp; }
    
private:
    int k_;
    float temperature_;
};

/**
 * TopPSampler - Nucleus (top-p) sampling
 */
class TopPSampler : public ISampler {
public:
    SamplingResult sample(const std::vector<float>& probabilities,
                           const SamplingContext& context) override;
    std::string getName() const override { return "Top-P (Nucleus)"; }
    std::string getDescription() const override {
        return "Samples from smallest set of tokens with cumulative probability >= p";
    }
};

/**
 * MirostatSampler - Mirostat sampling
 */
class MirostatSampler : public ISampler {
public:
    MirostatSampler();
    
    SamplingResult sample(const std::vector<float>& probabilities,
                           const SamplingContext& context) override;
    std::string getName() const override { return "Mirostat"; }
    std::string getDescription() const override {
        return "Adaptive sampling to maintain target perplexity";
    }
    
    void setTargetPerplexity(float tau) { target_perplexity_ = tau; }
    void setLearningRate(float eta) { learning_rate_ = eta; }
    
private:
    float target_perplexity_;
    float learning_rate_;
    float current_perplexity_;
    int num_tokens_;
};

// Global advanced sampler accessor
AdvancedSampler* getAdvancedSampler();
void setAdvancedSampler(std::unique_ptr<AdvancedSampler> sampler);

} // namespace sampling
} // namespace rawrxd
