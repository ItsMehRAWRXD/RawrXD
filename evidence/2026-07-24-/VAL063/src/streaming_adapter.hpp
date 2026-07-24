#pragma once

#include "bounded_event_queue.hpp"
#include "execution_gateway.hpp"
#include <thread>
#include <atomic>

namespace val063 {

// Streaming adapter - bridges v1.0 runtime to Gateway
// 
// RESPONSIBILITY: Preserve temporal integrity of execution stream
// CONTRACT:
//   - Events are ordered by sequence_id
//   - Memory is bounded (configurable capacity)
//   - No event loss under normal operation
//   - Backpressure signals when consumer is slow
//   - Cancellation stops stream immediately
//
class StreamingAdapter {
public:
    struct Config {
        size_t queue_capacity{1024};
        size_t high_watermark{768};
        size_t low_watermark{256};
        BackpressurePolicy backpressure_policy{BackpressurePolicy::Block};
        std::chrono::milliseconds producer_timeout{std::chrono::seconds(30)};
        std::chrono::milliseconds consumer_timeout{std::chrono::seconds(30)};
        bool enable_heartbeat{true};
        std::chrono::milliseconds heartbeat_interval{std::chrono::seconds(5)};
    };

    struct Stats {
        uint64_t events_produced{0};
        uint64_t events_consumed{0};
        uint64_t events_dropped{0};
        uint64_t sequences_completed{0};
        uint64_t sequences_cancelled{0};
        uint64_t backpressure_events{0};
        uint64_t heartbeat_events{0};
        
        std::chrono::nanoseconds total_streaming_time{0};
        float average_events_per_second{0.0f};
    };

    explicit StreamingAdapter(const Config& config = Config{});
    ~StreamingAdapter();

    // Non-copyable
    StreamingAdapter(const StreamingAdapter&) = delete;
    StreamingAdapter& operator=(const StreamingAdapter&) = delete;

    // Initialize with execution context
    void initialize(
        ExecutionId execution_id,
        std::function<void(const StreamingEvent&)> consumer_callback
    );

    // Producer interface (called by v1.0 runtime)
    
    // Emit a token event
    bool emit_token(const TokenPayload& token);
    
    // Emit lifecycle event
    bool emit_event(EventType type, EventPayload payload = std::monostate{});
    
    // Signal execution started
    bool signal_started();
    
    // Signal execution completed
    bool signal_completed();
    
    // Signal execution failed
    bool signal_failed(const std::string& error);
    
    // Signal execution cancelled
    bool signal_cancelled();

    // Consumer control
    
    // Start consumer thread
    void start_consumer();
    
    // Stop consumer (graceful shutdown)
    void stop_consumer();
    
    // Cancel immediately
    void cancel();
    
    // Wait for completion
    bool wait_for_completion(std::chrono::milliseconds timeout);

    // Query interface
    Stats get_stats() const;
    bool is_active() const { return active_.load(); }
    bool is_cancelled() const { return cancelled_.load(); }
    
    // Get current sequence ID
    uint64_t current_sequence() const { return next_sequence_.load(); }

    // Validation
    bool validate_stream_integrity() const;

private:
    Config config_;
    
    std::unique_ptr<StreamingEventQueue> queue_;
    
    ExecutionId execution_id_;
    std::function<void(const StreamingEvent&)> consumer_callback_;
    
    std::atomic<uint64_t> next_sequence_{0};
    std::atomic<bool> active_{false};
    std::atomic<bool> cancelled_{false};
    std::atomic<bool> consumer_running_{false};
    
    std::thread consumer_thread_;
    mutable std::mutex stats_mutex_;
    Stats stats_;
    
    Timestamp stream_start_time_;
    std::optional<Timestamp> stream_end_time_;
    
    // Event history for validation (bounded)
    mutable std::mutex history_mutex_;
    std::vector<StreamingEvent> event_history_;
    static constexpr size_t MAX_HISTORY = 10000;
    
    void consumer_loop();
    bool push_event(StreamingEvent event);
    void record_event(const StreamingEvent& event);
    void update_stats(const StreamingEvent& event);
};

// Factory
std::unique_ptr<StreamingAdapter> create_streaming_adapter(
    const StreamingAdapter::Config& config = StreamingAdapter::Config{}
);

// Stream validator
bool validate_stream(
    std::span<const StreamingEvent> events,
    const ExecutionId& expected_execution_id
);

// Stream comparison for replay verification
bool compare_streams(
    std::span<const StreamingEvent> original,
    std::span<const StreamingEvent> replay
);

} // namespace val063
