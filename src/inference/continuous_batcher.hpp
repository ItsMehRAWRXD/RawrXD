#pragma once

#include "../core/common.hpp"
#include "request_queue.hpp"
#include <memory>
#include <thread>
#include <atomic>

namespace rawrxd::inference {

// Continuous batching configuration
struct ContinuousBatchingConfig {
    int max_batch_size = 16;            // Maximum sequences in batch
    int max_tokens_per_batch = 8192;   // Maximum total tokens
    int max_sequence_length = 4096;    // Maximum sequence length
    float batch_timeout_ms = 10.0f;     // Wait time for batch formation
    bool enable_chunking = true;         // Enable request chunking
    int chunk_size = 512;               // Tokens per chunk
};

// Batch entry
struct BatchEntry {
    Request request;
    int num_tokens = 0;
    bool is_prefill = true;
    std::chrono::steady_clock::time_point arrival_time;
};

// Continuous batching scheduler
class ContinuousBatcher {
public:
    explicit ContinuousBatcher(const ContinuousBatchingConfig& config);
    ~ContinuousBatcher();

    // Initialize
    bool initialize(std::shared_ptr<Model> model);

    // Start/stop batching loop
    void start();
    void stop();

    // Submit request
    void submitRequest(Request request);

    // Get next batch (called by inference engine)
    std::vector<BatchEntry> getNextBatch();

    // Mark request complete
    void completeRequest(const Request& request, const std::vector<int>& output);

    // Statistics
    struct Stats {
        uint64_t total_requests = 0;
        uint64_t total_batches = 0;
        uint64_t total_tokens = 0;
        float avg_batch_size = 0.0f;
        float avg_latency_ms = 0.0f;
        float throughput_tokens_per_sec = 0.0f;
    };

    Stats getStats() const { return stats_; }

private:
    ContinuousBatchingConfig config_;
    std::shared_ptr<Model> model_;
    std::unique_ptr<RequestQueue> request_queue_;

    std::atomic<bool> running_{false};
    std::thread batching_thread_;

    Stats stats_;
    mutable std::mutex stats_mutex_;

    // Active requests
    std::unordered_map<std::string, BatchEntry> active_requests_;
    mutable std::mutex active_mutex_;

    // Batching logic
    void batchingLoop();
    std::vector<BatchEntry> formBatch();
    bool canAddToBatch(const std::vector<BatchEntry>& current_batch,
                       const Request& new_request);
    int estimateTokens(const Request& request);

    // Scheduling
    void scheduleRequests();
    std::vector<Request> getPendingRequests();
};

// PagedAttention memory manager for continuous batching
class PagedAttentionManager {
public:
    struct Page {
        static constexpr size_t PAGE_SIZE = 256;  // Tokens per page
        int page_id = -1;
        bool allocated = false;
        std::vector<int> sequence_ids;
    };

    explicit PagedAttentionManager(size_t num_pages);

    // Allocate pages for sequence
    std::vector<int> allocatePages(int sequence_id, int num_tokens);

    // Free pages for sequence
    void freePages(int sequence_id);

    // Append token to sequence
    bool appendToken(int sequence_id, int token_id);

    // Get KV cache indices for sequence
    std::vector<int> getKVCacheIndices(int sequence_id);

    // Memory stats
    size_t getFreePages() const;
    size_t getTotalPages() const { return pages_.size(); }
    float getUtilization() const;

private:
    std::vector<Page> pages_;
    std::unordered_map<int, std::vector<int>> sequence_pages_;
    std::vector<int> free_list_;
    mutable std::mutex mutex_;
};

// Request scheduler with priority support
class PriorityScheduler {
public:
    enum class Priority {
        LOW = 0,
        NORMAL = 1,
        HIGH = 2,
        CRITICAL = 3
    };

    void enqueue(Request request, Priority priority);
    std::optional<Request> dequeue();

    size_t size() const;
    bool empty() const;

private:
    std::array<std::queue<Request>, 4> priority_queues_;
    mutable std::mutex mutex_;
};

// Token budget manager
class TokenBudgetManager {
public:
    explicit TokenBudgetManager(int max_tokens_per_minute);

    // Check if request can be processed
    bool canProcess(int num_tokens);

    // Consume tokens
    void consume(int num_tokens);

    // Get remaining budget
    int getRemainingBudget() const;

    // Reset budget (called periodically)
    void resetBudget();

private:
    int max_tokens_per_minute_;
    std::atomic<int> current_budget_;
    std::chrono::steady_clock::time_point last_reset_;
};

} // namespace rawrxd::inference
