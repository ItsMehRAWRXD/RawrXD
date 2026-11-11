#pragma once

#include "../core/common.hpp"
#include "request_queue.hpp"
#include <vector>
#include <algorithm>

namespace rawrxd::inference {

// Dynamic batching configuration
struct DynamicBatchingConfig {
    int max_batch_size = 16;
    int max_tokens_per_batch = 8192;
    int padding_token_id = 0;
    bool pad_to_multiple_of = true;
    int pad_multiple = 8;
    bool sort_by_length = true;
    float batch_formation_timeout_ms = 5.0f;
};

// Sequence group for dynamic batching
struct SequenceGroup {
    std::vector<Request> requests;
    std::vector<std::vector<int>> input_ids;
    std::vector<int> lengths;
    int max_length = 0;
    int total_tokens = 0;
    bool is_prefill = true;

    void add(const Request& request, const std::vector<int>& tokens);
    void computePadding();
    std::vector<std::vector<int>> getPaddedInputs() const;
    std::vector<std::vector<float>> getAttentionMasks() const;
};

// Dynamic batcher
class DynamicBatcher {
public:
    explicit DynamicBatcher(const DynamicBatchingConfig& config);

    // Add request to batching queue
    void addRequest(Request request);

    // Get optimally-sized batch
    std::optional<SequenceGroup> getBatch();

    // Return whether we can add more requests
    bool canAccept() const;

    // Get queue statistics
    struct Stats {
        uint64_t total_requests = 0;
        uint64_t total_batches = 0;
        float avg_batch_size = 0.0f;
        float avg_padding_ratio = 0.0f;
        float avg_tokens_per_batch = 0.0f;
    };

    Stats getStats() const { return stats_; }

private:
    DynamicBatchingConfig config_;
    std::vector<std::pair<Request, std::vector<int>>> pending_requests_;
    mutable std::mutex mutex_;

    Stats stats_;

    // Group requests by similar length
    std::vector<std::vector<size_t>> groupByLength();

    // Form batch from grouped requests
    SequenceGroup formBatch(const std::vector<size_t>& indices);

    // Calculate padding waste
    float calculatePaddingWaste(const SequenceGroup& group) const;
};

// Bucketing strategy for dynamic batching
class LengthBucketer {
public:
    explicit LengthBucketer(const std::vector<int>& bucket_boundaries);

    // Get bucket for sequence length
    int getBucket(int length) const;

    // Get all bucket boundaries
    std::vector<int> getBoundaries() const { return boundaries_; }

    // Pad length to bucket boundary
    int padToBucket(int length) const;

private:
    std::vector<int> boundaries_;
};

// Memory-efficient batching with token budget
class TokenBudgetBatcher {
public:
    explicit TokenBudgetBatcher(int max_tokens_per_batch);

    // Try to add request within budget
    bool tryAdd(const Request& request, const std::vector<int>& tokens);

    // Get current batch
    SequenceGroup getBatch() const { return current_batch_; }

    // Finalize and reset
    SequenceGroup finalize();

    // Check if empty
    bool empty() const { return current_batch_.requests.empty(); }

    // Get remaining budget
    int getRemainingBudget() const { return max_tokens_ - current_tokens_; }

private:
    int max_tokens_;
    int current_tokens_ = 0;
    SequenceGroup current_batch_;
};

// Adaptive batch size controller
class AdaptiveBatchController {
public:
    AdaptiveBatchController(int min_batch_size, int max_batch_size);

    // Update based on performance metrics
    void updateMetrics(float throughput, float latency, float gpu_utilization);

    // Get current optimal batch size
    int getOptimalBatchSize() const { return current_batch_size_; }

    // Record batch result
    void recordBatchResult(int batch_size, float throughput);

private:
    int min_batch_size_;
    int max_batch_size_;
    int current_batch_size_;

    struct HistoryEntry {
        int batch_size;
        float throughput;
        float latency;
    };
    std::deque<HistoryEntry> history_;
    static constexpr size_t MAX_HISTORY = 10;

    void adjustBatchSize();
};

} // namespace rawrxd::inference
