#pragma once

#include "dataset_loader.hpp"
#include <algorithm>

namespace rawrxd::training {

// Data collator for batching
class DataCollator {
public:
    explicit DataCollator(const DatasetConfig& config);

    // Collate samples into batch
    Batch collate(const std::vector<DataSample>& samples);

    // Set padding token
    void setPaddingToken(int pad_token_id) { pad_token_id_ = pad_token_id; }
    void setIgnoreIndex(int ignore_index) { ignore_index_ = ignore_index; }

private:
    DatasetConfig config_;
    int pad_token_id_ = 0;
    int ignore_index_ = -100;

    // Padding strategies
    std::vector<int> padSequence(const std::vector<int>& seq, size_t length);
    std::vector<float> padAttentionMask(const std::vector<float>& mask, size_t length);

    // Create labels from input_ids (shifted)
    std::vector<int> createLabels(const std::vector<int>& input_ids);

    size_t getMaxLength(const std::vector<DataSample>& samples);
};

// Instruction-following collator (for chat/instruction tuning)
class InstructionCollator : public DataCollator {
public:
    explicit InstructionCollator(const DatasetConfig& config);

    Batch collate(const std::vector<DataSample>& samples) override;

    // Set template for formatting
    void setTemplate(const std::string& instruction_template,
                     const std::string& response_template);

private:
    std::string instruction_template_ = "### Instruction:\n{}\n\n### Response:\n";
    std::string response_template_ = "{}";

    std::string formatSample(const DataSample& sample);
    std::pair<std::vector<int>, std::vector<int>> tokenizeWithLabels(
        const std::string& text, const std::string& response);
};

// Completion-only collator (for pretraining)
class CompletionCollator : public DataCollator {
public:
    explicit CompletionCollator(const DatasetConfig& config);

    Batch collate(const std::vector<DataSample>& samples) override;

private:
    // Labels = input_ids shifted by 1
};

// Causal LM collator with loss masking
class CausalLMCollator : public DataCollator {
public:
    explicit CausalLMCollator(const DatasetConfig& config);

    Batch collate(const std::vector<DataSample>& samples) override;

    // Mask specific positions (e.g., for prompt masking)
    void setMaskPrompt(bool mask) { mask_prompt_ = mask; }

private:
    bool mask_prompt_ = true;
};

// Data augmentation
class DataAugmenter {
public:
    // Random token masking (for MLM-style training)
    static std::vector<int> randomMask(const std::vector<int>& tokens,
                                           float mask_prob = 0.15f,
                                           int mask_token_id = 50264,
                                           int vocab_size = 50265);

    // Random span masking
    static std::vector<int> spanMask(const std::vector<int>& tokens,
                                        float mask_prob = 0.15f,
                                        float mean_span_length = 3.0f);

    // Document rotation
    static std::string rotateDocument(const std::string& text, float rotate_prob = 0.5f);

    // Text infilling (for T5-style)
    static std::pair<std::string, std::string> textInfilling(
        const std::string& text,
        float mask_prob = 0.15f,
        float mean_span_length = 3.0f);
};

// Dynamic batching by length
class DynamicBatcher {
public:
    explicit DynamicBatcher(size_t max_tokens_per_batch = 8192);

    // Group samples into batches by similar length
    std::vector<std::vector<DataSample>> createBatches(
        std::vector<DataSample>& samples);

    void setMaxTokens(size_t max_tokens) { max_tokens_per_batch_ = max_tokens; }

private:
    size_t max_tokens_per_batch_;

    struct Bucket {
        std::vector<DataSample> samples;
        size_t total_tokens = 0;
    };
};

} // namespace rawrxd::training
