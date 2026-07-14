#include "dynamic_batcher.hpp"
#include "../core/logger.hpp"
#include <algorithm>

namespace rawrxd::inference {

// ============================================================================
// Sequence Group
// ============================================================================

void SequenceGroup::add(const Request& request, const std::vector<int>& tokens) {
    requests.push_back(request);
    input_ids.push_back(tokens);
    lengths.push_back(static_cast<int>(tokens.size()));
    total_tokens += tokens.size();
    max_length = std::max(max_length, static_cast<int>(tokens.size()));
}

void SequenceGroup::computePadding() {
    // Pad all sequences to max_length
    for (auto& ids : input_ids) {
        if (ids.size() < static_cast<size_t>(max_length)) {
            ids.resize(max_length, 0);  // Pad with 0
        }
    }
}

std::vector<std::vector<int>> SequenceGroup::getPaddedInputs() const {
    return input_ids;
}

std::vector<std::vector<float>> SequenceGroup::getAttentionMasks() const {
    std::vector<std::vector<float>> masks;

    for (size_t i = 0; i < input_ids.size(); ++i) {
        std::vector<float> mask(max_length, 0.0f);
        for (int j = 0; j < lengths[i]; ++j) {
            mask[j] = 1.0f;
        }
        masks.push_back(std::move(mask));
    }

    return masks;
}

// ============================================================================
// Dynamic Batcher
// ============================================================================

DynamicBatcher::DynamicBatcher(const DynamicBatchingConfig& config)
    : config_(config) {
    RAWRXD_LOG_INFO("DynamicBatcher", "Initialized with max_batch_size={}, max_tokens={}",
                    config_.max_batch_size, config_.max_tokens_per_batch);
}

void DynamicBatcher::addRequest(Request request) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Tokenize request
    std::vector<int> tokens = request.prompt_tokens;

    pending_requests_.emplace_back(std::move(request), std::move(tokens));

    stats_.total_requests++;
}

std::optional<SequenceGroup> DynamicBatcher::getBatch() {
    std::lock_guard<std::mutex> lock(mutex_);

    if (pending_requests_.empty()) {
        return std::nullopt;
    }

    // Group by length if enabled
    std::vector<std::vector<size_t>> groups;
    if (config_.sort_by_length) {
        groups = groupByLength();
    } else {
        // Single group with all requests
        std::vector<size_t> indices(pending_requests_.size());
        std::iota(indices.begin(), indices.end(), 0);
        groups.push_back(std::move(indices));
    }

    // Form batch from first group
    if (!groups.empty()) {
        auto batch = formBatch(groups[0]);

        // Remove batched requests from pending
        std::vector<size_t> to_remove = groups[0];
        std::sort(to_remove.rbegin(), to_remove.rend());
        for (size_t idx : to_remove) {
            pending_requests_.erase(pending_requests_.begin() + idx);
        }

        stats_.total_batches++;
        stats_.avg_batch_size = static_cast<float>(stats_.total_requests) / stats_.total_batches;

        return batch;
    }

    return std::nullopt;
}

bool DynamicBatcher::canAccept() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return pending_requests_.size() < static_cast<size_t>(config_.max_batch_size * 2);
}

std::vector<std::vector<size_t>> DynamicBatcher::groupByLength() {
    // Sort by length
    std::vector<size_t> indices(pending_requests_.size());
    std::iota(indices.begin(), indices.end(), 0);

    std::sort(indices.begin(), indices.end(),
              [this](size_t a, size_t b) {
                  return pending_requests_[a].second.size() < pending_requests_[b].second.size();
              });

    // Group similar lengths
    std::vector<std::vector<size_t>> groups;
    std::vector<size_t> current_group;
    int current_tokens = 0;

    for (size_t idx : indices) {
        int len = static_cast<int>(pending_requests_[idx].second.size());

        if (current_group.size() >= static_cast<size_t>(config_.max_batch_size) ||
            current_tokens + len > config_.max_tokens_per_batch) {
            if (!current_group.empty()) {
                groups.push_back(std::move(current_group));
                current_group.clear();
                current_tokens = 0;
            }
        }

        current_group.push_back(idx);
        current_tokens += len;
    }

    if (!current_group.empty()) {
        groups.push_back(std::move(current_group));
    }

    return groups;
}

SequenceGroup DynamicBatcher::formBatch(const std::vector<size_t>& indices) {
    SequenceGroup group;

    for (size_t idx : indices) {
        group.add(pending_requests_[idx].first, pending_requests_[idx].second);
    }

    group.computePadding();

    return group;
}

float DynamicBatcher::calculatePaddingWaste(const SequenceGroup& group) const {
    if (group.total_tokens == 0) return 0.0f;

    int padded_tokens = group.max_length * static_cast<int>(group.requests.size());
    return 1.0f - static_cast<float>(group.total_tokens) / padded_tokens;
}

// ============================================================================
// Length Bucketer
// ============================================================================

LengthBucketer::LengthBucketer(const std::vector<int>& bucket_boundaries)
    : boundaries_(bucket_boundaries) {
    std::sort(boundaries_.begin(), boundaries_.end());
}

int LengthBucketer::getBucket(int length) const {
    for (size_t i = 0; i < boundaries_.size(); ++i) {
        if (length <= boundaries_[i]) {
            return static_cast<int>(i);
        }
    }
    return static_cast<int>(boundaries_.size());
}

int LengthBucketer::padToBucket(int length) const {
    for (int boundary : boundaries_) {
        if (length <= boundary) {
            return boundary;
        }
    }
    return length;
}

// ============================================================================
// Token Budget Batcher
// ============================================================================

TokenBudgetBatcher::TokenBudgetBatcher(int max_tokens_per_batch)
    : max_tokens_(max_tokens_per_batch) {}

bool TokenBudgetBatcher::tryAdd(const Request& request, const std::vector<int>& tokens) {
    int len = static_cast<int>(tokens.size());

    if (current_tokens_ + len > max_tokens_) {
        return false;
    }

    current_batch_.add(request, tokens);
    current_tokens_ += len;

    return true;
}

SequenceGroup TokenBudgetBatcher::finalize() {
    SequenceGroup result = std::move(current_batch_);
    current_batch_ = SequenceGroup();
    current_tokens_ = 0;
    return result;
}

// ============================================================================
// Adaptive Batch Controller
// ============================================================================

AdaptiveBatchController::AdaptiveBatchController(int min_batch_size, int max_batch_size)
    : min_batch_size_(min_batch_size)
    , max_batch_size_(max_batch_size)
    , current_batch_size_(min_batch_size) {}

void AdaptiveBatchController::updateMetrics(float throughput, float latency, float gpu_utilization) {
    recordBatchResult(current_batch_size_, throughput);
    adjustBatchSize();
}

void AdaptiveBatchController::recordBatchResult(int batch_size, float throughput) {
    HistoryEntry entry;
    entry.batch_size = batch_size;
    entry.throughput = throughput;
    entry.latency = 0.0f;  // Not tracked here

    history_.push_back(entry);

    if (history_.size() > MAX_HISTORY) {
        history_.pop_front();
    }
}

void AdaptiveBatchController::adjustBatchSize() {
    if (history_.size() < 3) return;

    // Simple heuristic: if throughput increasing, increase batch size
    float avg_recent = 0.0f;
    float avg_older = 0.0f;

    size_t mid = history_.size() / 2;
    for (size_t i = 0; i < history_.size(); ++i) {
        if (i < mid) {
            avg_older += history_[i].throughput;
        } else {
            avg_recent += history_[i].throughput;
        }
    }

    avg_recent /= (history_.size() - mid);
    avg_older /= mid;

    if (avg_recent > avg_older * 1.1f) {
        // Throughput improving, try larger batch
        current_batch_size_ = std::min(current_batch_size_ + 1, max_batch_size_);
    } else if (avg_recent < avg_older * 0.9f) {
        // Throughput degrading, reduce batch
        current_batch_size_ = std::max(current_batch_size_ - 1, min_batch_size_);
    }
}

} // namespace rawrxd::inference
