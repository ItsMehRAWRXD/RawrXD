// RawrXD Batch Processor Implementation
// Phase AQ: Model Serving Infrastructure

#include "batch_processor.hpp"
#include <iostream>
#include <algorithm>

namespace rawrxd {
namespace serving {

// Global instances
static std::unique_ptr<BatchProcessor> g_batch_processor;
static std::unique_ptr<QueueManager> g_queue_manager;

BatchProcessor* getBatchProcessor() {
    return g_batch_processor.get();
}

void setBatchProcessor(std::unique_ptr<BatchProcessor> processor) {
    g_batch_processor = std::move(processor);
}

QueueManager* getQueueManager() {
    return g_queue_manager.get();
}

void setQueueManager(std::unique_ptr<QueueManager> manager) {
    g_queue_manager = std::move(manager);
}

// BatchProcessor implementation
BatchProcessor::BatchProcessor()
    : running_(false)
    , initialized_(false) {
}

BatchProcessor::~BatchProcessor() {
    shutdown();
}

bool BatchProcessor::initialize(const BatchConfig& config) {
    config_ = config;
    running_ = true;
    initialized_ = true;
    
    // Start processing thread
    processing_thread_ = std::thread(&BatchProcessor::processingLoop, this);
    
    std::cout << "Batch processor initialized (max_size=" << config_.max_batch_size << ")" << std::endl;
    return true;
}

void BatchProcessor::shutdown() {
    if (!initialized_) return;
    
    running_ = false;
    cv_.notify_all();
    
    if (processing_thread_.joinable()) {
        processing_thread_.join();
    }
    
    initialized_ = false;
    std::cout << "Batch processor shutdown" << std::endl;
}

std::future<std::string> BatchProcessor::submit(const BatchRequest& request) {
    return submit(request, RequestPriority::NORMAL);
}

std::future<std::string> BatchProcessor::submit(const BatchRequest& request, RequestPriority priority) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!initialized_) {
        std::promise<std::string> promise;
        promise.set_exception(std::make_exception_ptr(std::runtime_error("Processor not initialized")));
        return promise.get_future();
    }
    
    if (config_.priority_queue) {
        priority_queue_.emplace(priorityToInt(priority), request);
    } else {
        request_queue_.push(request);
    }
    
    cv_.notify_one();
    
    // Return future from the request's promise
    // Note: In real implementation, we'd need to store and retrieve the promise
    std::promise<std::string> promise;
    auto future = promise.get_future();
    return future;
}

void BatchProcessor::processBatch(const std::vector<BatchRequest>& requests) {
    if (batch_handler_) {
        auto results = batch_handler_(requests);
        
        // Fulfill promises with results
        for (size_t i = 0; i < requests.size() && i < results.size(); ++i) {
            // In real implementation, would fulfill the promise here
        }
    }
}

void BatchProcessor::setBatchHandler(std::function<std::vector<BatchResult>(const std::vector<BatchRequest>&)> handler) {
    batch_handler_ = handler;
}

void BatchProcessor::updateConfig(const BatchConfig& config) {
    std::lock_guard<std::mutex> lock(mutex_);
    config_ = config;
}

BatchConfig BatchProcessor::getConfig() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return config_;
}

BatchStats BatchProcessor::getStats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_;
}

void BatchProcessor::resetStats() {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_ = BatchStats();
}

size_t BatchProcessor::getQueueSize() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return request_queue_.size() + priority_queue_.size();
}

size_t BatchProcessor::getPendingCount() const {
    // In real implementation, would track pending requests
    return getQueueSize();
}

void BatchProcessor::clearQueue() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    while (!request_queue_.empty()) {
        request_queue_.pop();
    }
    
    while (!priority_queue_.empty()) {
        priority_queue_.pop();
    }
}

bool BatchProcessor::isProcessing() const {
    return running_ && initialized_;
}

void BatchProcessor::setTimeout(std::chrono::milliseconds timeout) {
    std::lock_guard<std::mutex> lock(mutex_);
    config_.timeout = timeout;
}

void BatchProcessor::handleTimeouts() {
    // In real implementation, would check for timed out requests
    auto now = std::chrono::system_clock::now();
    
    // Check queue for expired requests
    // This would require storing deadline with each request
}

void BatchProcessor::processingLoop() {
    while (running_) {
        auto batch = collectBatch();
        
        if (!batch.empty()) {
            executeBatch(batch);
        } else {
            // Wait for more requests
            std::unique_lock<std::mutex> lock(mutex_);
            cv_.wait_for(lock, config_.max_wait_time);
        }
    }
}

std::vector<BatchRequest> BatchProcessor::collectBatch() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<BatchRequest> batch;
    auto start_time = std::chrono::system_clock::now();
    
    // Collect from priority queue first
    while (!priority_queue_.empty() && batch.size() < config_.max_batch_size) {
        batch.push_back(priority_queue_.top().second);
        priority_queue_.pop();
    }
    
    // Then from normal queue
    while (!request_queue_.empty() && batch.size() < config_.max_batch_size) {
        batch.push_back(request_queue_.front());
        request_queue_.pop();
    }
    
    return batch;
}

void BatchProcessor::executeBatch(const std::vector<BatchRequest>& requests) {
    auto start = std::chrono::high_resolution_clock::now();
    
    if (batch_handler_) {
        auto results = batch_handler_(requests);
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        
        updateStats(requests, results, duration);
    }
}

void BatchProcessor::updateStats(const std::vector<BatchRequest>& requests,
                                  const std::vector<BatchResult>& results,
                                  std::chrono::milliseconds processing_time) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    stats_.total_batches++;
    stats_.total_requests += requests.size();
    
    // Update average batch size
    stats_.average_batch_size = 
        (stats_.average_batch_size * (stats_.total_batches - 1) + requests.size()) / stats_.total_batches;
    
    // Update average latency
    stats_.average_latency_ms = 
        (stats_.average_latency_ms * (stats_.total_batches - 1) + processing_time.count()) / stats_.total_batches;
    
    // Calculate throughput
    if (processing_time.count() > 0) {
        stats_.throughput_rps = 1000.0 * requests.size() / processing_time.count();
    }
    
    // Count errors
    for (const auto& result : results) {
        if (!result.success) {
            stats_.errors++;
        }
        stats_.total_tokens += result.tokens_generated;
    }
}

// QueueManager implementation
QueueManager::QueueManager()
    : max_size_(1000)
    , priority_enabled_(false)
    , total_enqueued_(0)
    , total_dequeued_(0)
    , dropped_count_(0) {
}

QueueManager::~QueueManager() {
    shutdown();
}

bool QueueManager::initialize(size_t max_size) {
    max_size_ = max_size;
    return true;
}

void QueueManager::shutdown() {
    clear();
}

bool QueueManager::enqueue(const BatchRequest& request) {
    return enqueue(request, RequestPriority::NORMAL);
}

bool QueueManager::enqueue(const BatchRequest& request, RequestPriority priority) {
    std::unique_lock<std::mutex> lock(mutex_);
    
    if (normal_queue_.size() + priority_queue_.size() >= max_size_) {
        dropped_count_++;
        return false;
    }
    
    auto request_ptr = std::make_shared<BatchRequest>(request);
    
    if (priority_enabled_) {
        priority_queue_.emplace(priorityToInt(priority), request_ptr);
    } else {
        normal_queue_.push(request_ptr);
    }
    
    total_enqueued_++;
    not_empty_.notify_one();
    
    return true;
}

bool QueueManager::tryEnqueue(const BatchRequest& request, std::chrono::milliseconds timeout) {
    std::unique_lock<std::mutex> lock(mutex_);
    
    if (!not_full_.wait_for(lock, timeout, [this] { 
        return normal_queue_.size() + priority_queue_.size() < max_size_; 
    })) {
        return false;
    }
    
    auto request_ptr = std::make_shared<BatchRequest>(request);
    normal_queue_.push(request_ptr);
    total_enqueued_++;
    not_empty_.notify_one();
    
    return true;
}

std::shared_ptr<BatchRequest> QueueManager::dequeue() {
    std::unique_lock<std::mutex> lock(mutex_);
    
    not_empty_.wait(lock, [this] { 
        return !normal_queue_.empty() || !priority_queue_.empty(); 
    });
    
    std::shared_ptr<BatchRequest> result;
    
    if (priority_enabled_ && !priority_queue_.empty()) {
        result = priority_queue_.top().second;
        priority_queue_.pop();
    } else if (!normal_queue_.empty()) {
        result = normal_queue_.front();
        normal_queue_.pop();
    }
    
    if (result) {
        total_dequeued_++;
        not_full_.notify_one();
    }
    
    return result;
}

std::shared_ptr<BatchRequest> QueueManager::tryDequeue(std::chrono::milliseconds timeout) {
    std::unique_lock<std::mutex> lock(mutex_);
    
    if (!not_empty_.wait_for(lock, timeout, [this] { 
        return !normal_queue_.empty() || !priority_queue_.empty(); 
    })) {
        return nullptr;
    }
    
    std::shared_ptr<BatchRequest> result;
    
    if (priority_enabled_ && !priority_queue_.empty()) {
        result = priority_queue_.top().second;
        priority_queue_.pop();
    } else if (!normal_queue_.empty()) {
        result = normal_queue_.front();
        normal_queue_.pop();
    }
    
    if (result) {
        total_dequeued_++;
        not_full_.notify_one();
    }
    
    return result;
}

std::vector<std::shared_ptr<BatchRequest>> QueueManager::dequeueBatch(size_t max_size) {
    std::vector<std::shared_ptr<BatchRequest>> batch;
    
    std::unique_lock<std::mutex> lock(mutex_);
    
    while (batch.size() < max_size && (!normal_queue_.empty() || !priority_queue_.empty())) {
        std::shared_ptr<BatchRequest> request;
        
        if (priority_enabled_ && !priority_queue_.empty()) {
            request = priority_queue_.top().second;
            priority_queue_.pop();
        } else if (!normal_queue_.empty()) {
            request = normal_queue_.front();
            normal_queue_.pop();
        }
        
        if (request) {
            batch.push_back(request);
            total_dequeued_++;
        }
    }
    
    if (!batch.empty()) {
        not_full_.notify_one();
    }
    
    return batch;
}

std::vector<std::shared_ptr<BatchRequest>> QueueManager::dequeueBatch(size_t max_size, 
                                                                     std::chrono::milliseconds wait_time) {
    std::vector<std::shared_ptr<BatchRequest>> batch;
    
    std::unique_lock<std::mutex> lock(mutex_);
    
    // Wait for at least one item or timeout
    not_empty_.wait_for(lock, wait_time, [this] { 
        return !normal_queue_.empty() || !priority_queue_.empty(); 
    });
    
    // Collect batch
    while (batch.size() < max_size && (!normal_queue_.empty() || !priority_queue_.empty())) {
        std::shared_ptr<BatchRequest> request;
        
        if (priority_enabled_ && !priority_queue_.empty()) {
            request = priority_queue_.top().second;
            priority_queue_.pop();
        } else if (!normal_queue_.empty()) {
            request = normal_queue_.front();
            normal_queue_.pop();
        }
        
        if (request) {
            batch.push_back(request);
            total_dequeued_++;
        }
    }
    
    if (!batch.empty()) {
        not_full_.notify_one();
    }
    
    return batch;
}

size_t QueueManager::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return normal_queue_.size() + priority_queue_.size();
}

size_t QueueManager::capacity() const {
    return max_size_;
}

bool QueueManager::empty() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return normal_queue_.empty() && priority_queue_.empty();
}

bool QueueManager::full() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return normal_queue_.size() + priority_queue_.size() >= max_size_;
}

void QueueManager::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    while (!normal_queue_.empty()) {
        normal_queue_.pop();
    }
    
    while (!priority_queue_.empty()) {
        priority_queue_.pop();
    }
    
    not_full_.notify_all();
}

size_t QueueManager::getTotalEnqueued() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return total_enqueued_;
}

size_t QueueManager::getTotalDequeued() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return total_dequeued_;
}

size_t QueueManager::getDroppedCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return dropped_count_;
}

void QueueManager::setPriorityEnabled(bool enabled) {
    std::lock_guard<std::mutex> lock(mutex_);
    priority_enabled_ = enabled;
}

bool QueueManager::isPriorityEnabled() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return priority_enabled_;
}

// Utility functions
int priorityToInt(RequestPriority priority) {
    return static_cast<int>(priority);
}

std::string priorityToString(RequestPriority priority) {
    switch (priority) {
        case RequestPriority::LOW: return "LOW";
        case RequestPriority::NORMAL: return "NORMAL";
        case RequestPriority::HIGH: return "HIGH";
        case RequestPriority::CRITICAL: return "CRITICAL";
        default: return "UNKNOWN";
    }
}

} // namespace serving
} // namespace rawrxd
