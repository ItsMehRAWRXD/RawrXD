#pragma once

#include "streaming_event.hpp"
#include <queue>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <optional>

namespace val063 {

// Queue state for backpressure signaling
enum class QueueState {
    Normal,           // Operating normally
    HighWatermark,    // Above high watermark, apply backpressure
    LowWatermark,     // Below low watermark, release backpressure
    Full,             // Queue is full
    Shutdown          // Queue is shutting down
};

// Backpressure policy
enum class BackpressurePolicy {
    Block,            // Block producer until space available
    DropOldest,       // Drop oldest events to make room
    DropNewest,       // Drop new events if queue full
    ApplyBackpressure   // Signal consumer to speed up
};

// Bounded event queue with backpressure
// 
// CONTRACT:
// - Memory is bounded (capacity * sizeof(StreamingEvent))
// - Events are ordered by sequence_id
// - No event loss under normal operation
// - Backpressure signals when consumer is slow
// - Cancellation stops queue immediately
//
template<typename T = StreamingEvent>
class BoundedEventQueue {
public:
    struct Config {
        size_t capacity{1024};
        size_t high_watermark{768};  // 75% of capacity
        size_t low_watermark{256};   // 25% of capacity
        BackpressurePolicy policy{BackpressurePolicy::Block};
        std::chrono::milliseconds block_timeout{std::chrono::seconds(30)};
    };

    struct Stats {
        uint64_t events_enqueued{0};
        uint64_t events_dequeued{0};
        uint64_t events_dropped{0};
        uint64_t blocks_applied{0};
        uint64_t blocks_released{0};
        uint64_t high_watermark_hits{0};
        uint64_t low_watermark_hits{0};
        uint64_t full_count{0};
        
        size_t current_depth{0};
        QueueState current_state{QueueState::Normal};
        
        float average_depth{0.0f};
        uint64_t max_observed_depth{0};
    };

    explicit BoundedEventQueue(const Config& config = Config{});
    ~BoundedEventQueue();

    // Non-copyable, non-movable (contains mutex)
    BoundedEventQueue(const BoundedEventQueue&) = delete;
    BoundedEventQueue& operator=(const BoundedEventQueue&) = delete;

    // Producer interface
    
    // Push event with backpressure handling
    // Returns: true if event was queued, false if dropped/cancelled
    bool push(T event);
    
    // Push with timeout
    // Returns: true if queued, false if timeout/cancelled
    bool push_with_timeout(T event, std::chrono::milliseconds timeout);
    
    // Try push (non-blocking)
    // Returns: true if queued, false if full
    bool try_push(T event);

    // Consumer interface
    
    // Pop event (blocks until available or cancelled)
    std::optional<T> pop();
    
    // Pop with timeout
    std::optional<T> pop_with_timeout(std::chrono::milliseconds timeout);
    
    // Try pop (non-blocking)
    std::optional<T> try_pop();
    
    // Peek at next event without removing
    std::optional<T> peek() const;

    // Control interface
    
    // Signal cancellation - stops all operations
    void cancel();
    
    // Check if cancelled
    bool is_cancelled() const { return cancelled_.load(); }
    
    // Shutdown gracefully (process remaining events)
    void shutdown();
    
    // Query interface
    
    size_t size() const;
    bool empty() const;
    bool full() const;
    size_t capacity() const { return config_.capacity; }
    
    QueueState state() const;
    float utilization() const;
    
    Stats get_stats() const;
    void reset_stats();

    // Backpressure signaling
    
    // Register callback for backpressure events
    using BackpressureCallback = std::function<void(QueueState, const Stats&)>;
    void set_backpressure_callback(BackpressureCallback callback);

private:
    Config config_;
    
    std::queue<T> queue_;
    mutable std::mutex mutex_;
    std::condition_variable not_full_;
    std::condition_variable not_empty_;
    
    std::atomic<bool> cancelled_{false};
    std::atomic<bool> shutdown_{false};
    
    mutable Stats stats_;
    mutable std::mutex stats_mutex_;
    
    BackpressureCallback backpressure_callback_;
    
    void update_state(size_t depth);
    void notify_backpressure(QueueState new_state);
    bool should_drop_oldest() const;
    void drop_oldest_internal();
};

// Type alias for streaming events
using StreamingEventQueue = BoundedEventQueue<StreamingEvent>;

// Queue factory with validation
std::unique_ptr<StreamingEventQueue> create_event_queue(
    size_t capacity = 1024,
    BackpressurePolicy policy = BackpressurePolicy::Block
);

// Validate queue configuration
bool validate_queue_config(const BoundedEventQueue<>::Config& config);

} // namespace val063
