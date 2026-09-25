#include "rawrxd_transformer_forwardbatch.hpp"
#include <math>
#include <numeric>
#include <algorithm>
#include <mutex>
#include <thread>
#include <condition_variable>
#include <queue>

namespace rawrxd {

class ForwardBatcher::Impl {
public:
    mutable std::mutex mutex_;
    BatchConfig config_;
    TransformerRuntime* transformer_ = nullptr;
    bool busy_ = false;
    bool cancelled_ = false;

    struct BatchTask {
        std::vector<BatchItem> items;
        std::promise<BatchResult> promise;
    };

    std::queue<BatchTask> task_queue_;
    std::vector<std::thread> workers_;

    bool IsCancelled() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return cancelled_;
    }

    BatchResult DoForwardBatch(const std::vector<BatchItem>& items) {
        BatchResult result;
        if (!transformer_) {
            result.error_message = "No transformer set";
            return result;
        }
        if (items.empty()) {
            result.error_message = "Empty batch";
            return result;
        }

        size_t batch_size = items.size();
        result.logits.resize(batch_size);
        result.perplexities.resize(batch_size);

        for (size_t b = 0; b < batch_size; ++b) {
            if (IsCancelled()) {
                result.error_message = "Cancelled";
                return result;
            }
            auto fwd = transformer_->Forward(items[b].tokens);
            if (!fwd.success) {
                result.error_message = fwd.error_message;
                return result;
            }
            result.logits[b] = fwd.logits;
            result.perplexities[b] = fwd.perplexity;
            if (config_.return_hidden_states) {
                result.hidden_states.push_back(fwd.hidden_states);
            }
        }
        result.success = true;
        return result;
    }

    uint32_t SampleLogit(const std::vector<float>& logits, float temperature,
                        uint32_t top_k, float top_p) {
        if (logits.empty()) return 0;
        float max_val = *std::max_element(logits.begin(), logits.end());
        std::vector<float> probs(logits.size());
        float sum = 0.0f;
        for (size_t i = 0; i < logits.size(); ++i) {
            probs[i] = std::exp((logits[i] - max_val) / std::max(temperature, 1e-6f));
            sum += probs[i];
        }
        if (sum > 0.0f) for (auto& p : probs) p /= sum;
        std::vector<size_t> indices(probs.size());
        std::iota(indices.begin(), indices.end(), 0);
        if (top_k > 0 && top_k < probs.size()) {
            std::nth_element(indices.begin(), indices.begin() + top_k, indices.end(),
                [&probs](size_t a, size_t b) { return probs[a] > probs[b]; });
            float k_sum = 0.0f;
            for (uint32_t i = 0; i < top_k; ++i) k_sum += probs[indices[i]];
            if (k_sum > 0.0f) {
                for (size_t i = top_k; i < indices.size(); ++i) probs[indices[i]] = 0.0f;
                for (auto& p : probs) p /= k_sum;
            }
        }
        std::sort(indices.begin(), indices.end(), [&probs](size_t a, size_t b) { return probs[a] > probs[b]; });
        float cumsum = 0.0f;
        size_t cutoff = probs.size();
        for (size_t i = 0; i < probs.size(); ++i) {
            cumsum += probs[indices[i]];
            if (cumsum >= top_p) { cutoff = i + 1; break; }
        }
        std::vector<uint32_t> candidates;
        std::vector<float> cand_probs;
        for (size_t i = 0; i < cutoff; ++i) {
            candidates.push_back(static_cast<uint32_t>(indices[i]));
            cand_probs.push_back(probs[indices[i]]);
        }
        if (candidates.empty()) candidates.push_back(static_cast<uint32_t>(indices[0]));
        float total = std::accumulate(cand_probs.begin(), cand_probs.end(), 0.0f);
        if (total <= 0.0f) return candidates[0];
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_real_distribution<float> dist(0.0f, total);
        float r = dist(gen);
        float acc = 0.0f;
        for (size_t i = 0; i < candidates.size(); ++i) {
            acc += cand_probs[i];
            if (r <= acc) return candidates[i];
        }
        return candidates.back();
    }
};

ForwardBatcher::ForwardBatcher() : impl_(std::make_unique<Impl>()) {}
ForwardBatcher::~ForwardBatcher() = default;

void ForwardBatcher::SetConfig(const BatchConfig& config) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->config_ = config;
}
const BatchConfig& ForwardBatcher::GetConfig() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->config_;
}

void ForwardBatcher::SetTransformer(TransformerRuntime* transformer) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->transformer_ = transformer;
}

BatchResult ForwardBatcher::ForwardBatch(const std::vector<BatchItem>& items) {
    {
        std::lock_guard<std::mutex> lock(impl_->mutex_);
        impl_->busy_ = true;
        impl_->cancelled_ = false;
    }
    auto result = impl_->DoForwardBatch(items);
    {
        std::lock_guard<std::mutex> lock(impl_->mutex_);
        impl_->busy_ = false;
    }
    return result;
}

BatchResult ForwardBatcher::ForwardBatchAsync(const std::vector<BatchItem>& items) {
    return ForwardBatch(items);
}

std::vector<std::vector<uint32_t>> ForwardBatcher::GenerateBatch(
    const std::vector<std::vector<uint32_t>>& prompts,
    uint32_t max_new_tokens, float temperature, uint32_t top_k, float top_p) {
    std::vector<std::vector<uint32_t>> results;
    if (!impl_->transformer_) return results;
    for (const auto& prompt : prompts) {
        std::vector<uint32_t> tokens = prompt;
        for (uint32_t i = 0; i < max_new_tokens; ++i) {
            auto fwd = impl_->transformer_->Forward(tokens);
            if (!fwd.success) break;
            uint32_t next_token = impl_->SampleLogit(fwd.logits, temperature, top_k, top_p);
            tokens.push_back(next_token);
            if (next_token == 2) break; // EOS
        }
        results.push_back(tokens);
    }
    return results;
}

bool ForwardBatcher::IsBusy() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->busy_;
}

void ForwardBatcher::Cancel() {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->cancelled_ = true;
}

std::vector<BatchItem> ForwardBatcher::PadBatch(const std::vector<std::vector<uint32_t>>& prompts,
                                                    uint32_t pad_token_id) {
    size_t max_len = 0;
    for (const auto& p : prompts) max_len = std::max(max_len, p.size());
    std::vector<BatchItem> result;
    for (const auto& p : prompts) {
        BatchItem item;
        item.tokens = p;
        item.original_length = static_cast<uint32_t>(p.size());
        while (item.tokens.size() < max_len) item.tokens.push_back(pad_token_id);
        item.weights.assign(item.tokens.size(), 1.0f);
        result.push_back(item);
    }
    return result;
}

std::vector<std::vector<uint32_t>> ForwardBatcher::UnpadBatch(
    const std::vector<std::vector<uint32_t>>& padded,
    const std::vector<uint32_t>& original_lengths) {
    std::vector<std::vector<uint32_t>> result;
    for (size_t i = 0; i < padded.size() && i < original_lengths.size(); ++i) {
        size_t len = std::min(static_cast<size_t>(original_lengths[i]), padded[i].size());
        result.push_back(std::vector<uint32_t>(padded[i].begin(), padded[i].begin() + len));
    }
    return result;
}

} // namespace rawrxd
