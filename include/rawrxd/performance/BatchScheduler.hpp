#pragma once

#include <vector>
#include <queue>
#include <memory>
#include <functional>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <future>

namespace rawrxd {
namespace performance {

// Batch processing configuration
struct BatchConfig {
    int maxBatchSize = 8;
    int maxSequenceLength = 4096;
    int maxWaitTimeMs = 10;  // Max time to wait for batch to fill
    bool dynamicBatching = true;  // Adjust batch size based on sequence lengths
    bool priorityScheduling = false;  // Prioritize certain requests
    float memoryThreshold = 0.9f;  // Pause batching at 90% memory
};

// Inference request
struct InferenceRequest {
    int id;
    std::vector<int> tokens;
    int maxNewTokens = 128;
    float temperature = 0.7f;
    float topP = 0.9f;
    int priority = 0;  // Higher = more important
    std::chrono::system_clock::time_point submitTime;
    std::promise<std::string> promise;
};

// Batch result
struct BatchResult {
    int requestId;
    std::string generatedText;
    int tokensGenerated = 0;
    float inferenceTimeMs = 0.0f;
    bool success = false;
    std::string errorMessage;
};

// Batch scheduler for efficient inference
class BatchScheduler {
public:
    BatchScheduler();
    ~BatchScheduler();

    // Initialize with configuration
    bool Initialize(const BatchConfig& config);
    
    // Submit a request
    std::future<std::string> Submit(const std::vector<int>& tokens, 
                                     int maxNewTokens = 128,
                                     int priority = 0);
    
    // Start/stop processing
    void Start();
    void Stop();
    bool IsRunning() const { return running_; }
    
    // Get statistics
    struct Stats {
        int totalRequests = 0;
        int completedRequests = 0;
        int failedRequests = 0;
        float avgLatencyMs = 0.0f;
        float avgBatchSize = 0.0f;
        float throughputTokensPerSec = 0.0f;
        int currentQueueSize = 0;
    };
    Stats GetStats() const;
    
    // Update configuration
    void UpdateConfig(const BatchConfig& config);
    
    // Clear pending requests
    void ClearQueue();
    
    // Get queue size
    int GetQueueSize() const;

private:
    BatchConfig config_;
    bool running_ = false;
    
    std::queue<std::shared_ptr<InferenceRequest>> requestQueue_;
    mutable std::mutex queueMutex_;
    std::condition_variable queueCV_;
    
    std::thread processingThread_;
    
    // Statistics
    Stats stats_;
    mutable std::mutex statsMutex_;
    
    // Processing
    void ProcessingLoop();
    std::vector<std::shared_ptr<InferenceRequest>> FormBatch();
    std::vector<BatchResult> ProcessBatch(const std::vector<std::shared_ptr<InferenceRequest>>& batch);
    void UpdateStats(const std::vector<BatchResult>& results, int batchSize, float processingTimeMs);
};

// Continuous batching (inflight batching) for maximum throughput
class ContinuousBatchingScheduler {
public:
    ContinuousBatchingScheduler();
    ~ContinuousBatchingScheduler();

    bool Initialize(const BatchConfig& config);
    
    // Add request to continuous batch
    int AddRequest(const std::vector<int>& tokens, int maxNewTokens = 128);
    
    // Step the batch forward (generate one token for all active sequences)
    std::vector<BatchResult> Step();
    
    // Check if a request is complete
    bool IsComplete(int requestId);
    
    // Get result for completed request
    BatchResult GetResult(int requestId);
    
    // Remove completed requests
    void CleanupCompleted();
    
    // Get active request count
    int GetActiveCount() const;
    
    // Get statistics
    struct Stats {
        int totalBatches = 0;
        float avgBatchSize = 0.0f;
        float tokensPerSecond = 0.0f;
        int maxConcurrentRequests = 0;
    };
    Stats GetStats() const;

private:
    BatchConfig config_;
    
    struct ActiveRequest {
        int id;
        std::shared_ptr<InferenceRequest> request;
        int tokensGenerated = 0;
        bool completed = false;
        std::string generatedText;
    };
    
    std::unordered_map<int, std::shared_ptr<ActiveRequest>> activeRequests_;
    mutable std::mutex requestsMutex_;
    
    int nextRequestId_ = 1;
    Stats stats_;
};

} // namespace performance
} // namespace rawrxd
