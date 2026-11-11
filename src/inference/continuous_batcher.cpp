#include "continuous_batcher.hpp"
#include "../core/logger.hpp"
#include <chrono>

namespace rawrxd::inference {

// ============================================================================
// Continuous Batcher
// ============================================================================

ContinuousBatcher::ContinuousBatcher(const ContinuousBatchingConfig& config)
    : config_(config) {
    RAWRXD_LOG_INFO("ContinuousBatcher", "Initialized with max_batch_size={}, max_tokens={}",
                    config_.max_batch_size, config_.max_tokens_per_batch);
}

ContinuousBatcher::~ContinuousBatcher() {
    stop();
}

bool ContinuousBatcher::initialize(std::shared_ptr<Model> model) {
    model_ = model;
    request_queue_ = std::make_unique<RequestQueue>();
    
    RAWRXD_LOG_INFO("ContinuousBatcher", "Initialized with model");
    return true;
}

void ContinuousBatcher::start() {
    if (running_) return;
    
    running_ = true;
    batching_thread_ = std::thread(&ContinuousBatcher::batchingLoop, this);
    
    RAWRXD_LOG_INFO("ContinuousBatcher", "Started batching loop");
}

void ContinuousBatcher::stop() {
    running_ = false;
    
    if (batching_thread_.joinable()) {
        batching_thread_.join();
    }
    
    RAWRXD_LOG_INFO("ContinuousBatcher", "Stopped batching loop");
}

void ContinuousBatcher::submitRequest(Request request) {
    if (!request_queue_) return;
    
    request_queue_->enqueue(std::move(request));
    
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_.total_requests++;
}

std::vector<BatchEntry> ContinuousBatcher::getNextBatch() {
    return formBatch();
}

void ContinuousBatcher::completeRequest(const Request& request, 
                                        const std::vector<int>& output) {
    std::lock_guard<std::mutex> lock(active_mutex_);
    
    auto it = active_requests_.find(request.id);
    if (it != active_requests_.end()) {
        active_requests_.erase(it);
    }
    
    // Update stats
    std::lock_guard<std::mutex> stats_lock(stats_mutex_);
    stats_.total_tokens += output.size();
}

void ContinuousBatcher::batchingLoop() {
    while (running_) {
        auto batch = formBatch();
        
        if (!batch.empty()) {
            // Process batch
            processBatch(batch);
        } else {
            // Sleep briefly if no requests
            std::this_thread::sleep_for(
                std::chrono::milliseconds(static_cast<int>(config_.batch_timeout_ms))
            );
        }
    }
}

std::vector<BatchEntry> ContinuousBatcher::formBatch() {
    std::vector<BatchEntry> batch;
    int current_tokens = 0;
    
    auto start_time = std::chrono::steady_clock::now();
    auto timeout = std::chrono::milliseconds(static_cast<int>(config_.batch_timeout_ms));
    
    while (batch.size() < static_cast<size_t>(config_.max_batch_size)) {
        // Check timeout
        auto elapsed = std::chrono::steady_clock::now() - start_time;
        if (elapsed > timeout && !batch.empty()) {
            break;
        }
        
        // Try to get next request
        auto request_opt = request_queue_->tryDequeue();
        if (!request_opt) {
            if (batch.empty()) {
                // Wait for at least one request
                request_opt = request_queue_->dequeueWithTimeout(100.0f);
                if (!request_opt) continue;
            } else {
                break;
            }
        }
        
        auto& request = *request_opt;
        int tokens = estimateTokens(request);
        
        // Check if we can add to batch
        if (current_tokens + tokens > config_.max_tokens_per_batch) {
            // Put back in queue
            request_queue_->enqueue(std::move(request));
            break;
        }
        
        BatchEntry entry;
        entry.request = std::move(request);
        entry.num_tokens = tokens;
        entry.is_prefill = true;
        entry.arrival_time = std::chrono::steady_clock::now();
        
        batch.push_back(std::move(entry));
        current_tokens += tokens;
        
        // Add to active requests
        {
            std::lock_guard<std::mutex> lock(active_mutex_);
            active_requests_[entry.request.id] = batch.back();
        }
    }
    
    if (!batch.empty()) {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.total_batches++;
        stats_.avg_batch_size = static_cast<float>(stats_.total_requests) / 
                                static_cast<float>(stats_.total_batches);
    }
    
    return batch;
}

bool ContinuousBatcher::canAddToBatch(const std::vector<BatchEntry>& current_batch,
                                        const Request& new_request) {
    if (current_batch.size() >= static_cast<size_t>(config_.max_batch_size)) {
        return false;
    }
    
    int current_tokens = 0;
    for (const auto& entry : current_batch) {
        current_tokens += entry.num_tokens;
    }
    
    int new_tokens = estimateTokens(new_request);
    return current_tokens + new_tokens <= config_.max_tokens_per_batch;
}

int ContinuousBatcher::estimateTokens(const Request& request) {
    return static_cast<int>(request.prompt_tokens.size()) + request.max_new_tokens;
}

void ContinuousBatcher::processBatch(const std::vector<BatchEntry>& batch) {
    // This would integrate with the actual inference engine
    RAWRXD_LOG_DEBUG("ContinuousBatcher", "Processing batch of {} requests", batch.size());
    
    // Simulate processing
    for (const auto& entry : batch) {
        // Mark as decoding
        request_queue_->updateRequestStatus(entry.request.id, RequestStatus::DECODING);
        
        // In real implementation: run inference
        std::vector<int> output;
        // output = model_->generate(entry.request.prompt_tokens, entry.request.max_new_tokens);
        
        // Complete request
        completeRequest(entry.request, output);
    }
}

// ============================================================================
// Paged Attention Manager
// ============================================================================

PagedAttentionManager::PagedAttentionManager(size_t num_pages) {
    pages_.resize(num_pages);
    for (size_t i = 0; i < num_pages; ++i) {
        pages_[i].page_id = static_cast<int>(i);
        pages_[i].allocated = false;
        free_list_.push_back(static_cast<int>(i));
    }
    
    RAWRXD_LOG_INFO("PagedAttentionManager", "Initialized with {} pages", num_pages);
}

std::vector<int> PagedAttentionManager::allocatePages(int sequence_id, int num_tokens) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    int num_pages_needed = (num_tokens + Page::PAGE_SIZE - 1) / Page::PAGE_SIZE;
    std::vector<int> allocated_pages;
    
    for (int i = 0; i < num_pages_needed && !free_list_.empty(); ++i) {
        int page_id = free_list_.back();
        free_list_.pop_back();
        
        pages_[page_id].allocated = true;
        pages_[page_id].sequence_ids.push_back(sequence_id);
        allocated_pages.push_back(page_id);
    }
    
    sequence_pages_[sequence_id] = allocated_pages;
    return allocated_pages;
}

void PagedAttentionManager::freePages(int sequence_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = sequence_pages_.find(sequence_id);
    if (it == sequence_pages_.end()) return;
    
    for (int page_id : it->second) {
        pages_[page_id].allocated = false;
        pages_[page_id].sequence_ids.clear();
        free_list_.push_back(page_id);
    }
    
    sequence_pages_.erase(it);
}

bool PagedAttentionManager::appendToken(int sequence_id, int token_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = sequence_pages_.find(sequence_id);
    if (it == sequence_pages_.end()) return false;
    
    // Check if we need a new page
    // This is simplified - real implementation would track tokens per page
    
    return true;
}

std::vector<int> PagedAttentionManager::getKVCacheIndices(int sequence_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = sequence_pages_.find(sequence_id);
    if (it == sequence_pages_.end()) return {};
    
    return it->second;
}

size_t PagedAttentionManager::getFreePages() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return free_list_.size();
}

float PagedAttentionManager::getUtilization() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return 1.0f - static_cast<float>(free_list_.size()) / pages_.size();
}

// ============================================================================
// Priority Scheduler
// ============================================================================

void PriorityScheduler::enqueue(Request request, Priority priority) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    int idx = static_cast<int>(priority);
    priority_queues_[idx].push(std::move(request));
}

std::optional<Request> PriorityScheduler::dequeue() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Check from highest priority first
    for (int i = static_cast<int>(Priority::CRITICAL); i >= 0; --i) {
        if (!priority_queues_[i].empty()) {
            Request req = std::move(priority_queues_[i].front());
            priority_queues_[i].pop();
            return req;
        }
    }
    
    return std::nullopt;
}

size_t PriorityScheduler::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    size_t total = 0;
    for (const auto& queue : priority_queues_) {
        total += queue.size();
    }
    return total;
}

bool PriorityScheduler::empty() const {
    return size() == 0;
}

// ============================================================================
// Token Budget Manager
// ============================================================================

TokenBudgetManager::TokenBudgetManager(int max_tokens_per_minute)
    : max_tokens_per_minute_(max_tokens_per_minute)
    , current_budget_(max_tokens_per_minute) {
    last_reset_ = std::chrono::steady_clock::now();
}

bool TokenBudgetManager::canProcess(int num_tokens) {
    resetBudget();
    return current_budget_.load() >= num_tokens;
}

void TokenBudgetManager::consume(int num_tokens) {
    current_budget_ -= num_tokens;
}

int TokenBudgetManager::getRemainingBudget() const {
    return current_budget_.load();
}

void TokenBudgetManager::resetBudget() {
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::minutes>(now - last_reset_);
    
    if (elapsed.count() >= 1) {
        current_budget_ = max_tokens_per_minute_;
        last_reset_ = now;
    }
}

} // namespace rawrxd::inference
