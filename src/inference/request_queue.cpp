#include "request_queue.hpp"
#include "../core/logger.hpp"

namespace rawrxd::inference {

// ============================================================================
// Request Queue
// ============================================================================

void RequestQueue::enqueue(Request request) {
    std::lock_guard<std::mutex> lock(mutex_);

    queue_.push(std::move(request));
    active_requests_[queue_.back().id] = queue_.back();

    cv_.notify_one();
}

Request RequestQueue::dequeue() {
    std::unique_lock<std::mutex> lock(mutex_);

    cv_.wait(lock, [this] { return !queue_.empty(); });

    Request request = std::move(queue_.front());
    queue_.pop();

    request.status = RequestStatus::PREFILL;
    active_requests_[request.id] = request;

    return request;
}

std::optional<Request> RequestQueue::tryDequeue() {
    std::lock_guard<std::mutex> lock(mutex_);

    if (queue_.empty()) {
        return std::nullopt;
    }

    Request request = std::move(queue_.front());
    queue_.pop();

    request.status = RequestStatus::PREFILL;
    active_requests_[request.id] = request;

    return request;
}

std::optional<Request> RequestQueue::dequeueWithTimeout(float timeout_ms) {
    std::unique_lock<std::mutex> lock(mutex_);

    auto timeout = std::chrono::milliseconds(static_cast<int>(timeout_ms));
    bool has_request = cv_.wait_for(lock, timeout, [this] { return !queue_.empty(); });

    if (!has_request) {
        return std::nullopt;
    }

    Request request = std::move(queue_.front());
    queue_.pop();

    request.status = RequestStatus::PREFILL;
    active_requests_[request.id] = request;

    return request;
}

std::optional<Request> RequestQueue::peek() const {
    std::lock_guard<std::mutex> lock(mutex_);

    if (queue_.empty()) {
        return std::nullopt;
    }

    return queue_.front();
}

size_t RequestQueue::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return queue_.size();
}

bool RequestQueue::empty() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return queue_.empty();
}

void RequestQueue::clear() {
    std::lock_guard<std::mutex> lock(mutex_);

    while (!queue_.empty()) {
        queue_.pop();
    }

    active_requests_.clear();
}

bool RequestQueue::cancelRequest(const std::string& request_id) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = active_requests_.find(request_id);
    if (it != active_requests_.end()) {
        it->second.status = RequestStatus::CANCELLED;

        // Notify waiters
        auto cv_it = request_cvs_.find(request_id);
        if (cv_it != request_cvs_.end()) {
            cv_it->second.notify_all();
        }

        return true;
    }

    return false;
}

std::optional<RequestStatus> RequestQueue::getRequestStatus(const std::string& request_id) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = active_requests_.find(request_id);
    if (it != active_requests_.end()) {
        return it->second.status;
    }

    return std::nullopt;
}

void RequestQueue::updateRequestStatus(const std::string& request_id, RequestStatus status) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = active_requests_.find(request_id);
    if (it != active_requests_.end()) {
        it->second.status = status;

        // Notify waiters if completed or failed
        if (status == RequestStatus::COMPLETED || status == RequestStatus::FAILED) {
            auto cv_it = request_cvs_.find(request_id);
            if (cv_it != request_cvs_.end()) {
                cv_it->second.notify_all();
            }
        }
    }
}

std::vector<Request> RequestQueue::getPendingRequests() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<Request> pending;
    for (const auto& [id, request] : active_requests_) {
        if (request.status == RequestStatus::PENDING ||
            request.status == RequestStatus::PREFILL ||
            request.status == RequestStatus::DECODING) {
            pending.push_back(request);
        }
    }

    return pending;
}

bool RequestQueue::waitForRequest(const std::string& request_id, float timeout_ms) {
    std::unique_lock<std::mutex> lock(mutex_);

    // Create condition variable for this request if not exists
    auto& cv = request_cvs_[request_id];

    auto timeout = std::chrono::milliseconds(static_cast<int>(timeout_ms));

    bool completed = cv.wait_for(lock, timeout, [&request_id, this] {
        auto it = active_requests_.find(request_id);
        if (it == active_requests_.end()) return false;
        return it->second.status == RequestStatus::COMPLETED ||
               it->second.status == RequestStatus::FAILED ||
               it->second.status == RequestStatus::CANCELLED;
    });

    // Clean up
    request_cvs_.erase(request_id);

    return completed;
}

// ============================================================================
// Request Batch
// ============================================================================

void RequestBatch::add(Request request) {
    requests.push_back(std::move(request));
    total_tokens += static_cast<int>(request.prompt_tokens.size());
    max_sequence_length = std::max(max_sequence_length,
                                    static_cast<int>(request.prompt_tokens.size()));
}

void RequestBatch::clear() {
    requests.clear();
    total_tokens = 0;
    max_sequence_length = 0;
    requires_padding = false;
}

// ============================================================================
// Batch Builder
// ============================================================================

BatchBuilder::BatchBuilder(int max_batch_size, int max_tokens)
    : max_batch_size_(max_batch_size), max_tokens_(max_tokens) {}

bool BatchBuilder::tryAdd(Request request) {
    int tokens = static_cast<int>(request.prompt_tokens.size());

    if (current_batch_.size() >= static_cast<size_t>(max_batch_size_) ||
        current_batch_.total_tokens + tokens > max_tokens_) {
        return false;
    }

    current_batch_.add(std::move(request));
    return true;
}

RequestBatch BatchBuilder::finalize() {
    RequestBatch result = std::move(current_batch_);
    current_batch_ = RequestBatch();
    return result;
}

bool BatchBuilder::isFull() const {
    return current_batch_.size() >= static_cast<size_t>(max_batch_size_) ||
           current_batch_.total_tokens >= max_tokens_;
}

void BatchBuilder::reset() {
    current_batch_ = RequestBatch();
}

// ============================================================================
// Request Metrics
// ============================================================================

void RequestMetrics::recordCompletion(float latency_ms, int num_tokens) {
    total_requests++;
    completed_requests++;

    // Update average latency
    avg_latency_ms = (avg_latency_ms * (completed_requests - 1) + latency_ms) /
                     completed_requests;

    // Update tokens per second
    if (latency_ms > 0) {
        float tps = num_tokens / (latency_ms / 1000.0f);
        avg_tokens_per_second = (avg_tokens_per_second * (completed_requests - 1) + tps) /
                                 completed_requests;
    }
}

void RequestMetrics::recordFailure() {
    total_requests++;
    failed_requests++;
}

void RequestMetrics::recordCancellation() {
    total_requests++;
    cancelled_requests++;
}

void RequestMetrics::recordTimeout() {
    total_requests++;
    timeout_requests++;
}

} // namespace rawrxd::inference
