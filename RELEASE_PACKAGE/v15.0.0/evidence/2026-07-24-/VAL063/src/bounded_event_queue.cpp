#include "bounded_event_queue.hpp"
#include <algorithm>

namespace val063 {

// ============================================================================
// BoundedEventQueue Implementation
// ============================================================================

template<typename T>
BoundedEventQueue<T>::BoundedEventQueue(const Config& config) 
    : config_(config) {
    // Validate configuration
    if (config_.high_watermark >= config_.capacity) {
        config_.high_watermark = config_.capacity * 3 / 4;
    }
    if (config_.low_watermark >= config_.high_watermark) {
        config_.low_watermark = config_.capacity / 4;
    }
}

template<typename T>
BoundedEventQueue<T>::~BoundedEventQueue() {
    cancel();
}

template<typename T>
bool BoundedEventQueue<T>::push(T event) {
    return push_with_timeout(std::move(event), config_.block_timeout);
}

template<typename T>
bool BoundedEventQueue<T>::push_with_timeout(T event, std::chrono::milliseconds timeout) {
    if (cancelled_.load()) {
        return false;
    }
    
    std::unique_lock<std::mutex> lock(mutex_);
    
    // Wait until not full or cancelled
    bool has_space = not_full_.wait_for(lock, timeout, [this] {
        return queue_.size() < config_.capacity || cancelled_.load();
    });
    
    if (!has_space || cancelled_.load()) {
        // Timeout or cancelled - drop event
        std::lock_guard<std::mutex> stats_lock(stats_mutex_);
        ++stats_.events_dropped;
        return false;
    }
    
    // Check if we need to apply backpressure policy
    if (queue_.size() >= config_.capacity) {
        switch (config_.policy) {
            case BackpressurePolicy::DropOldest:
                drop_oldest_internal();
                break;
            case BackpressurePolicy::DropNewest:
                std::lock_guard<std::mutex> stats_lock(stats_mutex_);
                ++stats_.events_dropped;
                return false;
            case BackpressurePolicy::Block:
            case BackpressurePolicy::ApplyBackpressure:
                // Should not reach here due to wait above
                break;
        }
    }
    
    // Enqueue event
    queue_.push(std::move(event));
    
    // Update stats
    {
        std::lock_guard<std::mutex> stats_lock(stats_mutex_);
        ++stats_.events_enqueued;
        stats_.current_depth = queue_.size();
        if (stats_.current_depth > stats_.max_observed_depth) {
            stats_.max_observed_depth = stats_.current_depth;
        }
        update_state(stats_.current_depth);
    }
    
    not_empty_.notify_one();
    return true;
}

template<typename T>
bool BoundedEventQueue<T>::try_push(T event) {
    if (cancelled_.load()) {
        return false;
    }
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (queue_.size() >= config_.capacity) {
        std::lock_guard<std::mutex> stats_lock(stats_mutex_);
        ++stats_.events_dropped;
        ++stats_.full_count;
        return false;
    }
    
    queue_.push(std::move(event));
    
    {
        std::lock_guard<std::mutex> stats_lock(stats_mutex_);
        ++stats_.events_enqueued;
        stats_.current_depth = queue_.size();
        if (stats_.current_depth > stats_.max_observed_depth) {
            stats_.max_observed_depth = stats_.current_depth;
        }
        update_state(stats_.current_depth);
    }
    
    not_empty_.notify_one();
    return true;
}

template<typename T>
std::optional<T> BoundedEventQueue<T>::pop() {
    return pop_with_timeout(std::chrono::milliseconds::max());
}

template<typename T>
std::optional<T> BoundedEventQueue<T>::pop_with_timeout(std::chrono::milliseconds timeout) {
    std::unique_lock<std::mutex> lock(mutex_);
    
    // Wait until not empty or cancelled/shutdown
    bool has_data = not_empty_.wait_for(lock, timeout, [this] {
        return !queue_.empty() || cancelled_.load() || 
               (shutdown_.load() && queue_.empty());
    });
    
    if (!has_data || (queue_.empty() && (cancelled_.load() || shutdown_.load()))) {
        return std::nullopt;
    }
    
    // Dequeue event
    T event = std::move(queue_.front());
    queue_.pop();
    
    // Update stats
    {
        std::lock_guard<std::mutex> stats_lock(stats_mutex_);
        ++stats_.events_dequeued;
        stats_.current_depth = queue_.size();
        update_state(stats_.current_depth);
    }
    
    not_full_.notify_one();
    return event;
}

template<typename T>
std::optional<T> BoundedEventQueue<T>::try_pop() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (queue_.empty()) {
        return std::nullopt;
    }
    
    T event = std::move(queue_.front());
    queue_.pop();
    
    {
        std::lock_guard<std::mutex> stats_lock(stats_mutex_);
        ++stats_.events_dequeued;
        stats_.current_depth = queue_.size();
        update_state(stats_.current_depth);
    }
    
    not_full_.notify_one();
    return event;
}

template<typename T>
std::optional<T> BoundedEventQueue<T>::peek() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (queue_.empty()) {
        return std::nullopt;
    }
    
    return queue_.front();
}

template<typename T>
void BoundedEventQueue<T>::cancel() {
    cancelled_.store(true);
    not_full_.notify_all();
    not_empty_.notify_all();
}

template<typename T>
void BoundedEventQueue<T>::shutdown() {
    shutdown_.store(true);
    not_empty_.notify_all();
}

template<typename T>
size_t BoundedEventQueue<T>::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return queue_.size();
}

template<typename T>
bool BoundedEventQueue<T>::empty() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return queue_.empty();
}

template<typename T>
bool BoundedEventQueue<T>::full() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return queue_.size() >= config_.capacity;
}

template<typename T>
QueueState BoundedEventQueue<T>::state() const {
    std::lock_guard<std::mutex> stats_lock(stats_mutex_);
    return stats_.current_state;
}

template<typename T>
float BoundedEventQueue<T>::utilization() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return static_cast<float>(queue_.size()) / static_cast<float>(config_.capacity);
}

template<typename T>
typename BoundedEventQueue<T>::Stats BoundedEventQueue<T>::get_stats() const {
    std::lock_guard<std::mutex> stats_lock(stats_mutex_);
    return stats_;
}

template<typename T>
void BoundedEventQueue<T>::reset_stats() {
    std::lock_guard<std::mutex> stats_lock(stats_mutex_);
    stats_ = Stats{};
}

template<typename T>
void BoundedEventQueue<T>::set_backpressure_callback(BackpressureCallback callback) {
    backpressure_callback_ = std::move(callback);
}

template<typename T>
void BoundedEventQueue<T>::update_state(size_t depth) {
    QueueState new_state;
    
    if (depth >= config_.capacity) {
        new_state = QueueState::Full;
        ++stats_.full_count;
    } else if (depth >= config_.high_watermark) {
        new_state = QueueState::HighWatermark;
        ++stats_.high_watermark_hits;
    } else if (depth <= config_.low_watermark) {
        new_state = QueueState::LowWatermark;
        ++stats_.low_watermark_hits;
    } else {
        new_state = QueueState::Normal;
    }
    
    if (cancelled_.load()) {
        new_state = QueueState::Shutdown;
    }
    
    if (new_state != stats_.current_state) {
        stats_.current_state = new_state;
        notify_backpressure(new_state);
    }
    
    // Update average depth (simple moving average)
    stats_.average_depth = (stats_.average_depth * 0.9f) + (depth * 0.1f);
}

template<typename T>
void BoundedEventQueue<T>::notify_backpressure(QueueState new_state) {
    if (backpressure_callback_) {
        backpressure_callback_(new_state, stats_);
    }
}

template<typename T>
bool BoundedEventQueue<T>::should_drop_oldest() const {
    return config_.policy == BackpressurePolicy::DropOldest && !queue_.empty();
}

template<typename T>
void BoundedEventQueue<T>::drop_oldest_internal() {
    if (!queue_.empty()) {
        queue_.pop();
        ++stats_.events_dropped;
    }
}

// Explicit instantiation for StreamingEvent
template class BoundedEventQueue<StreamingEvent>;

// ============================================================================
// Factory Functions
// ============================================================================

std::unique_ptr<StreamingEventQueue> create_event_queue(
    size_t capacity,
    BackpressurePolicy policy
) {
    StreamingEventQueue::Config config;
    config.capacity = capacity;
    config.high_watermark = capacity * 3 / 4;
    config.low_watermark = capacity / 4;
    config.policy = policy;
    
    return std::make_unique<StreamingEventQueue>(config);
}

bool validate_queue_config(const BoundedEventQueue<>::Config& config) {
    if (config.capacity == 0) return false;
    if (config.high_watermark > config.capacity) return false;
    if (config.low_watermark >= config.high_watermark) return false;
    if (config.low_watermark == 0) return false;
    return true;
}

} // namespace val063
