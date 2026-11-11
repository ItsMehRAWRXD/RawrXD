#pragma once

#include "../core/common.hpp"
#include <memory>

namespace rawrxd::inference {

// Draft model interface for speculative decoding
class DraftModel {
public:
    virtual ~DraftModel() = default;

    // Generate next token probabilities
    virtual std::vector<float> getNextTokenProbs(const std::vector<int>& context) = 0;

    // Generate multiple tokens
    virtual std::vector<int> generateTokens(const std::vector<int>& context,
                                           int num_tokens,
                                           float temperature = 1.0f) = 0;

    // Model info
    virtual size_t getVocabSize() const = 0;
    virtual std::string getName() const = 0;

    // Performance characteristics
    virtual float getLatencyMs() const = 0;
    virtual size_t getMemoryUsage() const = 0;
};

// Small draft model (e.g., 7B draft for 70B target)
class SmallDraftModel : public DraftModel {
public:
    explicit SmallDraftModel(const std::string& model_path);

    bool load();

    std::vector<float> getNextTokenProbs(const std::vector<int>& context) override;
    std::vector<int> generateTokens(const std::vector<int>& context,
                                   int num_tokens,
                                   float temperature) override;

    size_t getVocabSize() const override;
    std::string getName() const override { return "SmallDraftModel"; }
    float getLatencyMs() const override;
    size_t getMemoryUsage() const override;

private:
    std::string model_path_;
    std::shared_ptr<Model> model_;
    size_t vocab_size_ = 0;
};

// Self-speculative (use target model's early layers)
class SelfSpeculativeModel : public DraftModel {
public:
    SelfSpeculativeModel(std::shared_ptr<Model> target_model, int num_early_layers);

    std::vector<float> getNextTokenProbs(const std::vector<int>& context) override;
    std::vector<int> generateTokens(const std::vector<int>& context,
                                   int num_tokens,
                                   float temperature) override;

    size_t getVocabSize() const override;
    std::string getName() const override { return "SelfSpeculative"; }
    float getLatencyMs() const override;
    size_t getMemoryUsage() const override;

private:
    std::shared_ptr<Model> target_model_;
    int num_early_layers_;
};

// Prompt lookup (use prompt itself for drafting)
class PromptLookupModel : public DraftModel {
public:
    explicit PromptLookupModel(int window_size = 5);

    void setPrompt(const std::vector<int>& prompt);

    std::vector<float> getNextTokenProbs(const std::vector<int>& context) override;
    std::vector<int> generateTokens(const std::vector<int>& context,
                                   int num_tokens,
                                   float temperature) override;

    size_t getVocabSize() const override { return vocab_size_; }
    std::string getName() const override { return "PromptLookup"; }
    float getLatencyMs() const override { return 0.1f; }  // Very fast
    size_t getMemoryUsage() const override { return 0; }

private:
    int window_size_;
    std::vector<int> prompt_;
    size_t vocab_size_ = 0;

    std::vector<int> lookupMatches(const std::vector<int>& context);
};

// Draft model factory
std::shared_ptr<DraftModel> createDraftModel(const std::string& type,
                                             const std::string& model_path = "");

} // namespace rawrxd::inference
