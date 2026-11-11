#pragma once

#include "../core/common.hpp"
#include <queue>
#include <mutex>
#include <condition_variable>

namespace rawrxd::inference {

// Request status
enum class RequestStatus {
    PENDING,        // Waiting in queue
    PREFILL,        // Computing initial KV cache
    DECODING,       // Generating tokens
    CHUNKED,        // Paused for chunked processing
    COMPLETED,      // Finished successfully
    FAILED,         // Error occurred
    CANCELLED       // Cancelled by user
};

// Generation request
struct Request {
    std::string id;
    std::vector<int> prompt_tokens;
    int max_new_tokens = 256;
    float temperature = 0.7f;
    float top_p = 0.9f;
    int top_k = 50;
    float repetition_penalty = 1.0f;
    std::vector<int> stop_sequences;

    // Streaming
    bool stream = false;
    std::function<void(const std::vector<int>&)> stream_callback;

    // Priority
    int priority = 0;
    std::chrono::steady_clock::time_point arrival_time;

    // State
    RequestStatus status = RequestStatus::PENDING;
    std::vector<int> generated_tokens;
    float current_prob = 0.0f;

    // Timeout
    float timeout_ms = 60000.0f;

    Request() {
        arrival_time = std::chrono::steady_clock::now();
        id = generateRequestId();
    }

private:
    static std::string generateRequestId() {
        static std::atomic<uint64_t> counter{0};
        auto now = std::chrono::steady_clock::now().time_since_epoch().count();
        return "req_" + std::to_string(now) + "_" + std::to_string(counter++);
    }
};

// Request queue with blocking operations
class RequestQueue {
public:
    RequestQueue() = default;

    // Add request to queue
    void enqueue(Request request);

    // Get next request (blocks if empty)
    Request dequeue();

    // Try to get next request (non-blocking)
    std::optional<Request> tryDequeue();

    // Get next request with timeout
    std::optional<Request> dequeueWithTimeout(float timeout_ms);

    // Peek at next request without removing
    std::optional<Request> peek() const;

    // Get queue size
    size_t size() const;
    bool empty() const;

    // Clear queue
    void clear();

    // Cancel request
    bool cancelRequest(const std::string& request_id);

    // Get request status
    std::optional<RequestStatus> getRequestStatus(const std::string& request_id) const;

    // Update request status
    void updateRequestStatus(const std::string& request_id, RequestStatus status);

    // Get all pending requests
    std::vector<Request> getPendingRequests() const;

    // Wait for specific request to complete
    bool waitForRequest(const std::string& request_id, float timeout_ms);

private:
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::queue<Request> queue_;
    std::unordered_map<std::string, Request> active_requests_;
    std::unordered_map<std::string, std::condition_variable> request_cvs_;
};

// Request batch
struct RequestBatch {
    std::vector<Request> requests;
    int total_tokens = 0;
    int max_sequence_length = 0;
    bool requires_padding = false;

    void add(Request request);
    void clear();
    size_t size() const { return requests.size(); }
    bool empty() const { return requests.empty(); }
};

// Batch builder
class BatchBuilder {
public:
    explicit BatchBuilder(int max_batch_size, int max_tokens);

    // Try to add request to batch
    bool tryAdd(Request request);

    // Get current batch
    RequestBatch getBatch() const { return current_batch_; }

    // Finalize and return batch
    RequestBatch finalize();

    // Check if batch is full
    bool isFull() const;

    // Reset builder
    void reset();

private:
    int max_batch_size_;
    int max_tokens_;
    RequestBatch current_batch_;
    int current_tokens_ = 0;
};

// Request metrics
struct RequestMetrics {
    uint64_t total_requests = 0;
    uint64_t completed_requests = 0;
    uint64_t failed_requests = 0;
    uint64_t cancelled_requests = 0;
    uint64_t timeout_requests = 0;

    float avg_latency_ms = 0.0f;
    float p50_latency_ms = 0.0f;
    float p99_latency_ms = 0.0f;

    float avg_time_to_first_token_ms = 0.0f;
    float avg_tokens_per_second = 0.0f;

    void recordCompletion(float latency_ms, int num_tokens);
    void recordFailure();
    void recordCancellation();
    void recordTimeout();
};

} // namespace rawrxd::inference
