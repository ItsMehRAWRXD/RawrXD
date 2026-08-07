// ============================================================================
// Blocker #21: RawrXD Engine Adapter Async Condition Variable Queue
// Fixes the async condition variable queue in RawrXDInferenceAdapter
// to properly handle backpressure and cancellation.
// ============================================================================
#pragma once
#include <condition_variable>
#include <mutex>
#include <queue>
#include <functional>
#include <atomic>
#include <chrono>

namespace rawr {

// Thread-safe token queue with backpressure and cancellation
template<typename T>
class AsyncTokenQueue {
public:
    AsyncTokenQueue(size_t maxSize = 1024)
        : maxSize_(maxSize), cancelled_(false), closed_(false) {}

    // Push a token - blocks if queue is full (backpressure)
    bool Push(const T& token, uint32_t timeoutMs = 5000) {
        std::unique_lock<std::mutex> lock(mutex_);
        
        // Wait for space or cancellation
        bool hasSpace = cvProducer_.wait_for(lock, std::chrono::milliseconds(timeoutMs),
            [this]() { return queue_.size() < maxSize_ || cancelled_; });
        
        if (!hasSpace || cancelled_) return false;
        
        queue_.push(token);
        cvConsumer_.notify_one();
        return true;
    }

    // Non-blocking push (drops if full)
    bool TryPush(const T& token) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (queue_.size() >= maxSize_ || cancelled_) return false;
        queue_.push(token);
        cvConsumer_.notify_one();
        return true;
    }

    // Pop a token - blocks until available or cancelled
    bool Pop(T& token, uint32_t timeoutMs = 5000) {
        std::unique_lock<std::mutex> lock(mutex_);
        
        bool hasData = cvConsumer_.wait_for(lock, std::chrono::milliseconds(timeoutMs),
            [this]() { return !queue_.empty() || cancelled_ || closed_; });
        
        if (!hasData || (queue_.empty() && (cancelled_ || closed_))) return false;
        
        token = queue_.front();
        queue_.pop();
        cvProducer_.notify_one();
        return true;
    }

    // Cancel all pending operations
    void Cancel() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            cancelled_ = true;
            // Clear queue on cancel
            std::queue<T> empty;
            std::swap(queue_, empty);
        }
        cvProducer_.notify_all();
        cvConsumer_.notify_all();
    }

    void Reset() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            cancelled_ = false;
            closed_ = false;
            std::queue<T> empty;
            std::swap(queue_, empty);
        }
    }

    void Close() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            closed_ = true;
        }
        cvConsumer_.notify_all();
    }

    size_t Size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.size();
    }

    bool IsCancelled() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return cancelled_;
    }

private:
    std::queue<T> queue_;
    mutable std::mutex mutex_;
    std::condition_variable cvProducer_;
    std::condition_variable cvConsumer_;
    size_t maxSize_;
    std::atomic<bool> cancelled_;
    std::atomic<bool> closed_;
};

// Specific token type for inference
typedef AsyncTokenQueue<std::string> InferenceTokenQueue;

} // namespace rawr
