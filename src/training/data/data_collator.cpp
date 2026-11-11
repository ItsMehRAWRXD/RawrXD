#include "data_collator.hpp"
#include "../../core/logger.hpp"
#include <algorithm>

namespace rawrxd::training {

// ============================================================================
// Data Collator
// ============================================================================

DataCollator::DataCollator(const DatasetConfig& config) : config_(config) {}

Batch DataCollator::collate(const std::vector<DataSample>& samples) {
    Batch batch;
    batch.size = samples.size();

    size_t max_length = getMaxLength(samples);
    batch.max_length = max_length;

    for (const auto& sample : samples) {
        // Pad sequences
        auto padded_ids = padSequence(sample.token_ids, max_length);
        auto padded_mask = padAttentionMask(sample.attention_mask, max_length);
        auto labels = createLabels(padded_ids);

        batch.input_ids.push_back(std::move(padded_ids));
        batch.attention_masks.push_back(std::move(padded_mask));
        batch.labels.push_back(std::move(labels));
        batch.num_tokens += sample.num_tokens;
    }

    return batch;
}

std::vector<int> DataCollator::padSequence(const std::vector<int>& seq, size_t length) {
    std::vector<int> result = seq;
    if (result.size() < length) {
        if (config_.padding_side == "right") {
            result.resize(length, pad_token_id_);
        } else {
            result.insert(result.begin(), length - result.size(), pad_token_id_);
        }
    } else if (result.size() > length) {
        if (config_.truncation) {
            result.resize(length);
        }
    }
    return result;
}

std::vector<float> DataCollator::padAttentionMask(const std::vector<float>& mask, size_t length) {
    std::vector<float> result = mask;
    if (result.size() < length) {
        if (config_.padding_side == "right") {
            result.resize(length, 0.0f);  // 0 for padding
        } else {
            result.insert(result.begin(), length - result.size(), 0.0f);
        }
    }
    return result;
}

std::vector<int> DataCollator::createLabels(const std::vector<int>& input_ids) {
    // For causal LM: labels = input_ids shifted by 1
    std::vector<int> labels = input_ids;

    // Shift: labels[i] = input_ids[i+1]
    // Last token has no label
    for (size_t i = 0; i < labels.size() - 1; ++i) {
        labels[i] = input_ids[i + 1];
    }
    labels.back() = ignore_index_;

    return labels;
}

size_t DataCollator::getMaxLength(const std::vector<DataSample>& samples) {
    size_t max_len = 0;
    for (const auto& s : samples) {
        max_len = std::max(max_len, s.num_tokens);
    }

    if (config_.truncation && max_len > config_.max_length) {
        max_len = config_.max_length;
    }

    return max_len;
}

// ============================================================================
// Instruction Collator
// ============================================================================

InstructionCollator::InstructionCollator(const DatasetConfig& config)
    : DataCollator(config) {}

Batch InstructionCollator::collate(const std::vector<DataSample>& samples) {
    std::vector<DataSample> formatted_samples;

    for (const auto& sample : samples) {
        DataSample formatted = sample;
        std::string text = formatSample(sample);
        // Tokenize formatted text
        formatted.text = text;
        formatted.num_tokens = text.length() / 4;
        formatted_samples.push_back(std::move(formatted));
    }

    return DataCollator::collate(formatted_samples);
}

void InstructionCollator::setTemplate(const std::string& instruction_template,
                                         const std::string& response_template) {
    instruction_template_ = instruction_template;
    response_template_ = response_template;
}

std::string InstructionCollator::formatSample(const DataSample& sample) {
    std::string result = instruction_template_;

    // Replace {} with instruction
    size_t pos = result.find("{}");
    if (pos != std::string::npos) {
        result.replace(pos, 2, sample.instruction);
    }

    // Add input if present
    if (!sample.input.empty()) {
        result += "\n" + sample.input + "\n";
    }

    // Add response
    std::string response = response_template_;
    pos = response.find("{}");
    if (pos != std::string::npos) {
        response.replace(pos, 2, sample.output);
    }
    result += response;

    return result;
}

std::pair<std::vector<int>, std::vector<int>> InstructionCollator::tokenizeWithLabels(
    const std::string& text, const std::string& response) {
    // Tokenize full text
    // Find response position
    // Create labels: -100 for prompt, actual tokens for response
    return {{}, {}};
}

// ============================================================================
// Completion Collator
// ============================================================================

CompletionCollator::CompletionCollator(const DatasetConfig& config)
    : DataCollator(config) {}

Batch CompletionCollator::collate(const std::vector<DataSample>& samples) {
    // Standard causal LM: predict next token for all positions
    return DataCollator::collate(samples);
}

// ============================================================================
// Causal LM Collator
// ============================================================================

CausalLMCollator::CausalLMCollator(const DatasetConfig& config)
    : DataCollator(config) {}

Batch CausalLMCollator::collate(const std::vector<DataSample>& samples) {
    Batch batch = DataCollator::collate(samples);

    if (mask_prompt_) {
        // Mask prompt tokens in labels
        for (size_t i = 0; i < batch.labels.size(); ++i) {
            // Find prompt-response boundary
            // Set labels before boundary to ignore_index
        }
    }

    return batch;
}

// ============================================================================
// Data Augmentation
// ============================================================================

std::vector<int> DataAugmenter::randomMask(const std::vector<int>& tokens,
                                               float mask_prob,
                                               int mask_token_id,
                                               int vocab_size) {
    std::vector<int> result = tokens;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<float> dist(0.0f, 1.0f);
    std::uniform_int_distribution<int> token_dist(0, vocab_size - 1);

    for (size_t i = 0; i < result.size(); ++i) {
        if (dist(gen) < mask_prob) {
            float r = dist(gen);
            if (r < 0.8f) {
                // 80%: replace with [MASK]
                result[i] = mask_token_id;
            } else if (r < 0.9f) {
                // 10%: replace with random token
                result[i] = token_dist(gen);
            }
            // 10%: keep original
        }
    }

    return result;
}

std::vector<int> DataAugmenter::spanMask(const std::vector<int>& tokens,
                                            float mask_prob,
                                            float mean_span_length) {
    std::vector<int> result = tokens;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<float> dist(0.0f, 1.0f);
    std::geometric_distribution<int> span_dist(1.0f / mean_span_length);

    size_t i = 0;
    while (i < result.size()) {
        if (dist(gen) < mask_prob / mean_span_length) {
            int span_length = span_dist(gen);
            for (int j = 0; j < span_length && i + j < result.size(); ++j) {
                result[i + j] = 0;  // Mask token
            }
            i += span_length;
        } else {
            ++i;
        }
    }

    return result;
}

std::string DataAugmenter::rotateDocument(const std::string& text, float rotate_prob) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<float> dist(0.0f, 1.0f);

    if (dist(gen) >= rotate_prob) {
        return text;
    }

    // Split into sentences/paragraphs
    std::vector<std::string> parts;
    // Simple split by newlines
    size_t start = 0;
    size_t end = text.find('\n');
    while (end != std::string::npos) {
        parts.push_back(text.substr(start, end - start));
        start = end + 1;
        end = text.find('\n', start);
    }
    if (start < text.size()) {
        parts.push_back(text.substr(start));
    }

    if (parts.size() <= 1) {
        return text;
    }

    // Rotate
    std::uniform_int_distribution<size_t> rot_dist(0, parts.size() - 1);
    size_t rotation = rot_dist(gen);

    std::string result;
    for (size_t i = 0; i < parts.size(); ++i) {
        result += parts[(i + rotation) % parts.size()];
        if (i < parts.size() - 1) {
            result += "\n";
        }
    }

    return result;
}

std::pair<std::string, std::string> DataAugmenter::textInfilling(
    const std::string& text,
    float mask_prob,
    float mean_span_length) {
    // T5-style infilling: replace spans with sentinel tokens
    // Return: (infilled_text, target_spans)
    return {text, ""};
}

// ============================================================================
// Dynamic Batcher
// ============================================================================

DynamicBatcher::DynamicBatcher(size_t max_tokens_per_batch)
    : max_tokens_per_batch_(max_tokens_per_batch) {}

std::vector<std::vector<DataSample>> DynamicBatcher::createBatches(
    std::vector<DataSample>& samples) {
    // Sort by length
    std::sort(samples.begin(), samples.end(),
              [](const DataSample& a, const DataSample& b) {
                  return a.num_tokens < b.num_tokens;
              });

    std::vector<std::vector<DataSample>> batches;
    std::vector<DataSample> current_batch;
    size_t current_tokens = 0;

    for (auto& sample : samples) {
        size_t sample_tokens = sample.num_tokens;

        // Check if adding this sample would exceed limit
        if (!current_batch.empty() &&
            current_tokens + sample_tokens > max_tokens_per_batch_) {
            batches.push_back(std::move(current_batch));
            current_batch.clear();
            current_tokens = 0;
        }

        current_batch.push_back(std::move(sample));
        current_tokens += sample_tokens;
    }

    if (!current_batch.empty()) {
        batches.push_back(std::move(current_batch));
    }

    return batches;
}

} // namespace rawrxd::training
