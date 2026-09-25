#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <optional>
#include <functional>
#include "rawrxd_transformer.hpp"

namespace rawrxd {

struct BatchConfig {
    uint32_t batch_size = 1;
    uint32_t seq_len = 512;
    uint32_t padding_token_id = 0;
    bool pad_to_max = true;
    bool return_hidden_states = false;
    bool return_attention_weights = false;
};

struct BatchResult {
    std::vector<std::vector<float>> logits;          // [batch_size, seq_len, vocab_size]
    std::vector<std::vector<float>> hidden_states;     // optional
    std::vector<float> perplexities;
    bool success = false;
    std::string error_message;
};

struct BatchItem {
    std::vector<uint32_t> tokens;
    std::vector<float> weights;
    uint32_t original_length = 0;
};

class ForwardBatcher {
public:
    ForwardBatcher();
    ~ForwardBatcher();

    void SetConfig(const BatchConfig& config);
    const BatchConfig& GetConfig() const;

    void SetTransformer(TransformerRuntime* transformer);

    BatchResult ForwardBatch(const std::vector<BatchItem>& items);
    BatchResult ForwardBatchAsync(const std::vector<BatchItem>& items);

    std::vector<std::vector<uint32_t>> GenerateBatch(
        const std::vector<std::vector<uint32_t>>& prompts,
        uint32_t max_new_tokens,
        float temperature = 0.8f,
        uint32_t top_k = 40,
        float top_p = 0.95f);

    bool IsBusy() const;
    void Cancel();

    static std::vector<BatchItem> PadBatch(const std::vector<std::vector<uint32_t>>& prompts,
                                            uint32_t pad_token_id);

    static std::vector<std::vector<uint32_t>> UnpadBatch(
        const std::vector<std::vector<uint32_t>>& padded,
        const std::vector<uint32_t>& original_lengths);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace rawrxd
