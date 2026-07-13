#include "rawrxd/performance/BatchScheduler.hpp"
#include <chrono>
#include <algorithm>

namespace rawrxd {
namespace performance {

// BatchScheduler implementation
BatchScheduler::BatchScheduler() = default;

BatchScheduler::~BatchScheduler() {
    Stop();
}

bool BatchScheduler::Initialize(const BatchConfig& config) {
    config_ = config;
    return true;
}

std::future<std::string> BatchScheduler::Submit(const std::vector<int>& tokens, 
                                               int maxNewTokens,
                                               int priority) {
    auto request = std::make_shared<InferenceRequest>();
    request->id = ++stats_.totalRequests;
    request->tokens = tokens;
    request->maxNewTokens = maxNewTokens;
    request->priority = priority;
    request->submitTime = std::chrono::system_clock::now();
    
    std::future<std::string> future = request->promise.get_future();
    
    {
        std::lock_guard<std::mutex> lock(queueMutex_);
        requestQueue_.push(request);
    }
    
    queueCV_.notify_one();
    return future;
}

void BatchScheduler::Start() {
    if (running_) return;
    running_ = true;
    processingThread_ = std::thread(&BatchScheduler::ProcessingLoop, this);
}

void BatchScheduler::Stop() {
    running_ = false;
    queueCV_.notify_all();
    if (processingThread_.joinable()) {
        processingThread_.join();
    }
}

void BatchScheduler::ProcessingLoop() {
    while (running_) {
        auto batch = FormBatch();
        if (!batch.empty()) {
            auto startTime = std::chrono::high_resolution_clock::now();
            auto results = ProcessBatch(batch);
            auto endTime = std::chrono::high_resolution_clock::now();
            
            float processingTimeMs = std::chrono::duration<float, std::milli>(
                endTime - startTime).count();
            
            UpdateStats(results, static_cast<int>(batch.size()), processingTimeMs);
            
            // Fulfill promises
            for (size_t i = 0; i < results.size() && i < batch.size(); ++i) {
                if (results[i].success) {
                    batch[i]->promise.set_value(results[i].generatedText);
                } else {
                    batch[i]->promise.set_exception(
                        std::make_exception_ptr(std::runtime_error(results[i].errorMessage)));
                }
            }
        } else {
            // Wait for more requests
            std::unique_lock<std::mutex> lock(queueMutex_);
            queueCV_.wait_for(lock, std::chrono::milliseconds(10));
        }
    }
}

std::vector<std::shared_ptr<InferenceRequest>> BatchScheduler::FormBatch() {
    std::vector<std::shared_ptr<InferenceRequest>> batch;
    
    std::unique_lock<std::mutex> lock(queueMutex_);
    
    auto startWait = std::chrono::high_resolution_clock::now();
    
    while (batch.size() < static_cast<size_t>(config_.maxBatchSize)) {
        if (!requestQueue_.empty()) {
            batch.push_back(requestQueue_.front());
            requestQueue_.pop();
        } else {
            // Wait for more requests or timeout
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::high_resolution_clock::now() - startWait);
            
            if (elapsed.count() >= config_.maxWaitTimeMs || batch.empty()) {
                break;
            }
            
            queueCV_.wait_for(lock, std::chrono::milliseconds(1));
        }
    }
    
    return batch;
}

std::vector<BatchResult> BatchScheduler::ProcessBatch(
    const std::vector<std::shared_ptr<InferenceRequest>>& batch) {
    
    std::vector<BatchResult> results;
    results.reserve(batch.size());
    
    // In a real implementation, this would:
    // 1. Pad sequences to same length
    // 2. Run batched inference
    // 3. Return results
    
    for (const auto& request : batch) {
        BatchResult result;
        result.requestId = request->id;
        result.generatedText = "Generated text for request " + std::to_string(request->id);
        result.tokensGenerated = request->maxNewTokens;
        result.success = true;
        results.push_back(result);
    }
    
    return results;
}

void BatchScheduler::UpdateStats(const std::vector<BatchResult>& results, 
                                int batchSize, 
                                float processingTimeMs) {
    std::lock_guard<std::mutex> lock(statsMutex_);
    
    stats_.completedRequests += static_cast<int>(results.size());
    
    int failed = 0;
    float totalLatency = 0.0f;
    int totalTokens = 0;
    
    for (const auto& result : results) {
        if (!result.success) {
            failed++;
        }
        totalLatency += result.inferenceTimeMs;
        totalTokens += result.tokensGenerated;
    }
    
    stats_.failedRequests += failed;
    
    // Update averages
    if (stats_.completedRequests > 0) {
        stats_.avgLatencyMs = (stats_.avgLatencyMs * (stats_.completedRequests - results.size()) 
                              + totalLatency) / stats_.completedRequests;
    }
    
    if (stats_.totalRequests > 0) {
        stats_.avgBatchSize = (stats_.avgBatchSize * (stats_.totalRequests - batchSize) 
                              + batchSize) / stats_.totalRequests;
    }
    
    if (processingTimeMs > 0) {
        stats_.throughputTokensPerSec = totalTokens / (processingTimeMs / 1000.0f);
    }
}

BatchScheduler::Stats BatchScheduler::GetStats() const {
    std::lock_guard<std::mutex> lock(statsMutex_);
    Stats stats = stats_;
    stats.currentQueueSize = GetQueueSize();
    return stats;
}

void BatchScheduler::UpdateConfig(const BatchConfig& config) {
    config_ = config;
}

void BatchScheduler::ClearQueue() {
    std::lock_guard<std::mutex> lock(queueMutex_);
    while (!requestQueue_.empty()) {
        auto request = requestQueue_.front();
        request->promise.set_exception(
            std::make_exception_ptr(std::runtime_error("Queue cleared")));
        requestQueue_.pop();
    }
}

int BatchScheduler::GetQueueSize() const {
    std::lock_guard<std::mutex> lock(queueMutex_);
    return static_cast<int>(requestQueue_.size());
}

// ContinuousBatchingScheduler implementation
ContinuousBatchingScheduler::ContinuousBatchingScheduler() = default;

ContinuousBatchingScheduler::~ContinuousBatchingScheduler() {
    // Cleanup
}

bool ContinuousBatchingScheduler::Initialize(const BatchConfig& config) {
    config_ = config;
    return true;
}

int ContinuousBatchingScheduler::AddRequest(const std::vector<int>& tokens, 
                                           int maxNewTokens) {
    std::lock_guard<std::mutex> lock(requestsMutex_);
    
    auto request = std::make_shared<InferenceRequest>();
    request->id = nextRequestId_++;
    request->tokens = tokens;
    request->maxNewTokens = maxNewTokens;
    
    auto activeRequest = std::make_shared<ActiveRequest>();
    activeRequest->id = request->id;
    activeRequest->request = request;
    
    activeRequests_[request->id] = activeRequest;
    
    return request->id;
}

std::vector<BatchResult> ContinuousBatchingScheduler::Step() {
    std::lock_guard<std::mutex> lock(requestsMutex_);
    
    std::vector<BatchResult> results;
    
    // In continuous batching, we generate one token for all active sequences
    // and remove completed ones
    for (auto& pair : activeRequests_) {
        auto& activeReq = pair.second;
        if (activeReq->completed) continue;
        
        // Generate one token
        activeReq->tokensGenerated++;
        activeReq->generatedText += " token";
        
        // Check if complete
        if (activeReq->tokensGenerated >= activeReq->request->maxNewTokens) {
            activeReq->completed = true;
            
            BatchResult result;
            result.requestId = activeReq->id;
            result.generatedText = activeReq->generatedText;
            result.tokensGenerated = activeReq->tokensGenerated;
            result.success = true;
            results.push_back(result);
        }
    }
    
    // Update stats
    stats_.totalBatches++;
    stats_.avgBatchSize = (stats_.avgBatchSize * (stats_.totalBatches - 1) 
                          + activeRequests_.size()) / stats_.totalBatches;
    
    return results;
}

bool ContinuousBatchingScheduler::IsComplete(int requestId) {
    std::lock_guard<std::mutex> lock(requestsMutex_);
    auto it = activeRequests_.find(requestId);
    if (it != activeRequests_.end()) {
        return it->second->completed;
    }
    return true;  // Unknown ID is considered complete
}

BatchResult ContinuousBatchingScheduler::GetResult(int requestId) {
    std::lock_guard<std::mutex> lock(requestsMutex_);
    auto it = activeRequests_.find(requestId);
    if (it != activeRequests_.end() && it->second->completed) {
        BatchResult result;
        result.requestId = it->second->id;
        result.generatedText = it->second->generatedText;
        result.tokensGenerated = it->second->tokensGenerated;
        result.success = true;
        return result;
    }
    return BatchResult();  // Empty result
}

void ContinuousBatchingScheduler::CleanupCompleted() {
    std::lock_guard<std::mutex> lock(requestsMutex_);
    
    for (auto it = activeRequests_.begin(); it != activeRequests_.end();) {
        if (it->second->completed) {
            it = activeRequests_.erase(it);
        } else {
            ++it;
        }
    }
}

int ContinuousBatchingScheduler::GetActiveCount() const {
    std::lock_guard<std::mutex> lock(requestsMutex_);
    return static_cast<int>(activeRequests_.size());
}

ContinuousBatchingScheduler::Stats ContinuousBatchingScheduler::GetStats() const {
    return stats_;
}

} // namespace performance
} // namespace rawrxd
