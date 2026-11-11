// RawrXD Batch Processor
// Phase AQ: Model Serving Infrastructure

#pragma once

#include <vector>
#include <queue>
#include <memory>
#include <functional>
#include <future>
#include <mutex>
#include <condition_variable>
#include <chrono>

namespace rawrxd {
namespace serving {

// Batch request
struct BatchRequest {
    std::string id;
    std::string model_id;
    std::string input;
    std::vector<float> input_embeddings;
    size_t max_tokens;
    float temperature;
    std::chrono::system_clock::time_point submitted_at;
    std::chrono::system_clock::time_point deadline;
    std::promise<std::string> result_promise;
    
    BatchRequest()
        : max_tokens(512)
        , temperature(0.7f) {
        submitted_at = std::chrono::system_clock::now();
        deadline = submitted_at + std::chrono::seconds(30);
    }
};

// Batch result
struct BatchResult {
    std::string request_id;
    bool success;
    std::string output;
    std::string error_message;
    size_t tokens_generated;
    std::chrono::milliseconds processing_time;
    
    BatchResult()
        : success(false)
        , tokens_generated(0) {}
};

// Batch configuration
struct BatchConfig {
    size_t max_batch_size;
    size_t min_batch_size;
    std::chrono::milliseconds max_wait_time;
    std::chrono::milliseconds timeout;
    bool dynamic_batching;
    float batch_timeout_multiplier;
    size_t max_queue_size;
    bool priority_queue;
    
    BatchConfig()
        : max_batch_size(32)
        , min_batch_size(1)
        , max_wait_time(std::chrono::milliseconds(10))
        , timeout(std::chrono::milliseconds(30000))
        , dynamic_batching(true)
        , batch_timeout_multiplier(1.5f)
        , max_queue_size(1000)
        , priority_queue(false) {}
};

// Batch statistics
struct BatchStats {
    size_t total_batches;
    size_t total_requests;
    size_t total_tokens;
    double average_batch_size;
    double average_latency_ms;
    double throughput_rps;
    size_t queue_depth;
    size_t timeouts;
    size_t errors;
    
    BatchStats()
        : total_batches(0)
        , total_requests(0)
        , total_tokens(0)
        , average_batch_size(0.0)
        , average_latency_ms(0.0)
        , throughput_rps(0.0)
        , queue_depth(0)
        , timeouts(0)
        , errors(0) {}
};

// Priority levels
enum class RequestPriority {
    LOW = 0,
    NORMAL = 1,
    HIGH = 2,
    CRITICAL = 3
};

// Priority batch request
struct PriorityBatchRequest : BatchRequest {
    RequestPriority priority;
    
    PriorityBatchRequest() : priority(RequestPriority::NORMAL) {}
};

// Forward declarations
class BatchProcessor;
class QueueManager;

/**
 * BatchProcessor - Dynamic batching for inference
 */
class BatchProcessor {
public:
    BatchProcessor();
    ~BatchProcessor();
    
    // Initialize
    bool initialize(const BatchConfig& config);
    void shutdown();
    
    // Submit request
    std::future<std::string> submit(const BatchRequest& request);
    std::future<std::string> submit(const BatchRequest& request, RequestPriority priority);
    
    // Batch processing
    void processBatch(const std::vector<BatchRequest>& requests);
    void setBatchHandler(std::function<std::vector<BatchResult>(const std::vector<BatchRequest>&)> handler);
    
    // Configuration
    void updateConfig(const BatchConfig& config);
    BatchConfig getConfig() const;
    
    // Statistics
    BatchStats getStats() const;
    void resetStats();
    
    // Queue management
    size_t getQueueSize() const;
    size_t getPendingCount() const;
    void clearQueue();
    bool isProcessing() const;
    
    // Timeout handling
    void setTimeout(std::chrono::milliseconds timeout);
    void handleTimeouts();
    
private:
    BatchConfig config_;
    std::queue<BatchRequest> request_queue_;
    std::priority_queue<
        std::pair<int, BatchRequest>,
        std::vector<std::pair<int, BatchRequest>>,
        std::greater<std::pair<int, BatchRequest>>
    > priority_queue_;
    
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    bool running_;
    bool initialized_;
    
    std::function<std::vector<BatchResult>(const std::vector<BatchRequest>&)> batch_handler_;
    
    BatchStats stats_;
    std::thread processing_thread_;
    
    // Internal methods
    void processingLoop();
    std::vector<BatchRequest> collectBatch();
    void executeBatch(const std::vector<BatchRequest>& requests);
    void updateStats(const std::vector<BatchRequest>& requests, 
                     const std::vector<BatchResult>& results,
                     std::chrono::milliseconds processing_time);
};

/**
 * QueueManager - Request queue management
 */
class QueueManager {
public:
    QueueManager();
    ~QueueManager();
    
    // Initialize
    bool initialize(size_t max_size);
    void shutdown();
    
    // Queue operations
    bool enqueue(const BatchRequest& request);
    bool enqueue(const BatchRequest& request, RequestPriority priority);
    bool tryEnqueue(const BatchRequest& request, std::chrono::milliseconds timeout);
    
    std::shared_ptr<BatchRequest> dequeue();
    std::shared_ptr<BatchRequest> tryDequeue(std::chrono::milliseconds timeout);
    
    // Batch dequeue
    std::vector<std::shared_ptr<BatchRequest>> dequeueBatch(size_t max_size);
    std::vector<std::shared_ptr<BatchRequest>> dequeueBatch(size_t max_size, 
                                                               std::chrono::milliseconds wait_time);
    
    // Queue state
    size_t size() const;
    size_t capacity() const;
    bool empty() const;
    bool full() const;
    void clear();
    
    // Statistics
    size_t getTotalEnqueued() const;
    size_t getTotalDequeued() const;
    size_t getDroppedCount() const;
    
    // Priority management
    void setPriorityEnabled(bool enabled);
    bool isPriorityEnabled() const;
    
private:
    size_t max_size_;
    std::queue<std::shared_ptr<BatchRequest>> normal_queue_;
    std::priority_queue<
        std::pair<int, std::shared_ptr<BatchRequest>>,
        std::vector<std::pair<int, std::shared_ptr<BatchRequest>>>,
        std::greater<std::pair<int, std::shared_ptr<BatchRequest>>>
    > priority_queue_;
    
    mutable std::mutex mutex_;
    std::condition_variable not_empty_;
    std::condition_variable not_full_;
    
    bool priority_enabled_;
    size_t total_enqueued_;
    size_t total_dequeued_;
    size_t dropped_count_;
};

// Global accessor
BatchProcessor* getBatchProcessor();
void setBatchProcessor(std::unique_ptr<BatchProcessor> processor);

QueueManager* getQueueManager();
void setQueueManager(std::unique_ptr<QueueManager> manager);

// Utility functions
int priorityToInt(RequestPriority priority);
std::string priorityToString(RequestPriority priority);

} // namespace serving
} // namespace rawrxd
