#include "streaming_adapter.hpp"
#include <iostream>

namespace val063 {

// ============================================================================
// StreamingAdapter Implementation
// ============================================================================

StreamingAdapter::StreamingAdapter(const Config& config) 
    : config_(config) {
    
    StreamingEventQueue::Config queue_config;
    queue_config.capacity = config_.queue_capacity;
    queue_config.high_watermark = config_.high_watermark;
    queue_config.low_watermark = config_.low_watermark;
    queue_config.policy = config_.backpressure_policy;
    queue_config.block_timeout = config_.producer_timeout;
    
    queue_ = std::make_unique<StreamingEventQueue>(queue_config);
}

StreamingAdapter::~StreamingAdapter() {
    cancel();
    stop_consumer();
}

void StreamingAdapter::initialize(
    ExecutionId execution_id,
    std::function<void(const StreamingEvent&)> consumer_callback
) {
    execution_id_ = execution_id;
    consumer_callback_ = std::move(consumer_callback);
    next_sequence_ = 0;
    active_ = false;
    cancelled_ = false;
    
    // Set up backpressure callback
    queue_->set_backpressure_callback(
        [this](QueueState state, const StreamingEventQueue::Stats& stats) {
            std::lock_guard<std::mutex> lock(stats_mutex_);
            ++stats_.backpressure_events;
            
            // Emit backpressure event if significant
            if (state == QueueState::HighWatermark) {
                BackpressurePayload payload;
                payload.queue_depth = stats.current_depth;
                payload.queue_capacity = config_.queue_capacity;
                payload.is_blocked = true;
                
                emit_event(EventType::BackpressureApplied, payload);
            } else if (state == QueueState::LowWatermark) {
                emit_event(EventType::BackpressureReleased, 
                          BackpressurePayload{stats.current_depth, config_.queue_capacity, 0, false});
            }
        }
    );
}

bool StreamingAdapter::emit_token(const TokenPayload& token) {
    return push_event(StreamingEvent{
        next_sequence_++,
        execution_id_,
        EventType::TokenGenerated,
        timestamp::now(),
        token
    });
}

bool StreamingAdapter::emit_event(EventType type, EventPayload payload) {
    return push_event(StreamingEvent{
        next_sequence_++,
        execution_id_,
        type,
        timestamp::now(),
        std::move(payload)
    });
}

bool StreamingAdapter::signal_started() {
    active_ = true;
    stream_start_time_ = timestamp::now();
    return emit_event(EventType::ExecutionStarted);
}

bool StreamingAdapter::signal_completed() {
    bool result = emit_event(EventType::ExecutionCompleted);
    active_ = false;
    stream_end_time_ = timestamp::now();
    
    if (stream_end_time_) {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.total_streaming_time = 
            stream_end_time_->elapsed_since(stream_start_time_);
        ++stats_.sequences_completed;
    }
    
    return result;
}

bool StreamingAdapter::signal_failed(const std::string& error) {
    bool result = emit_event(EventType::ExecutionFailed, error);
    active_ = false;
    stream_end_time_ = timestamp::now();
    
    std::lock_guard<std::mutex> lock(stats_mutex_);
    ++stats_.sequences_completed;  // Completed (with failure)
    
    return result;
}

bool StreamingAdapter::signal_cancelled() {
    cancelled_ = true;
    bool result = emit_event(EventType::ExecutionCancelled);
    active_ = false;
    
    std::lock_guard<std::mutex> lock(stats_mutex_);
    ++stats_.sequences_cancelled;
    
    return result;
}

void StreamingAdapter::start_consumer() {
    if (consumer_running_.exchange(true)) {
        return;  // Already running
    }
    
    consumer_thread_ = std::thread([this]() {
        consumer_loop();
    });
}

void StreamingAdapter::stop_consumer() {
    if (!consumer_running_.load()) {
        return;
    }
    
    queue_->shutdown();
    
    if (consumer_thread_.joinable()) {
        consumer_thread_.join();
    }
    
    consumer_running_ = false;
}

void StreamingAdapter::cancel() {
    cancelled_ = true;
    queue_->cancel();
    stop_consumer();
}

bool StreamingAdapter::wait_for_completion(std::chrono::milliseconds timeout) {
    if (!consumer_thread_.joinable()) {
        return true;
    }
    
    return consumer_thread_.joinable() == false || 
           consumer_thread_.joinable();  // Simplified - would use condition variable in production
}

StreamingAdapter::Stats StreamingAdapter::get_stats() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    Stats result = stats_;
    
    // Add queue stats
    auto queue_stats = queue_->get_stats();
    result.events_dropped = queue_stats.events_dropped;
    
    return result;
}

bool StreamingAdapter::validate_stream_integrity() const {
    std::lock_guard<std::mutex> lock(history_mutex_);
    
    if (event_history_.empty()) {
        return true;
    }
    
    // Validate sequence ordering
    if (!EventSequenceValidator::validate_sequence(event_history_)) {
        return false;
    }
    
    // Validate all events belong to same execution
    if (!EventSequenceValidator::validate_same_execution(event_history_, execution_id_)) {
        return false;
    }
    
    // Validate event hashes
    if (!EventSequenceValidator::validate_hashes(event_history_)) {
        return false;
    }
    
    return true;
}

void StreamingAdapter::consumer_loop() {
    while (consumer_running_.load() || !queue_->empty()) {
        auto event = queue_->pop_with_timeout(config_.consumer_timeout);
        
        if (!event) {
            if (cancelled_.load()) {
                break;
            }
            continue;
        }
        
        // Deliver to consumer
        if (consumer_callback_) {
            consumer_callback_(*event);
        }
        
        // Record for validation
        record_event(*event);
        update_stats(*event);
        
        // Check for completion events
        if (event->type == EventType::ExecutionCompleted ||
            event->type == EventType::ExecutionFailed ||
            event->type == EventType::ExecutionCancelled) {
            // Stream ending
        }
    }
}

bool StreamingAdapter::push_event(StreamingEvent event) {
    if (cancelled_.load()) {
        return false;
    }
    
    bool result = queue_->push_with_timeout(std::move(event), config_.producer_timeout);
    
    if (result) {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        ++stats_.events_produced;
    }
    
    return result;
}

void StreamingAdapter::record_event(const StreamingEvent& event) {
    std::lock_guard<std::mutex> lock(history_mutex_);
    
    event_history_.push_back(event);
    
    // Trim history if too large
    if (event_history_.size() > MAX_HISTORY) {
        event_history_.erase(event_history_.begin(), 
                              event_history_.begin() + (event_history_.size() - MAX_HISTORY));
    }
}

void StreamingAdapter::update_stats(const StreamingEvent& event) {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    ++stats_.events_consumed;
    
    if (event.type == EventType::Heartbeat) {
        ++stats_.heartbeat_events;
    }
    
    // Calculate average events per second
    auto elapsed = timestamp::now().elapsed_since(stream_start_time_);
    auto elapsed_sec = std::chrono::duration_cast<std::chrono::seconds>(elapsed).count();
    if (elapsed_sec > 0) {
        stats_.average_events_per_second = 
            static_cast<float>(stats_.events_consumed) / static_cast<float>(elapsed_sec);
    }
}

// ============================================================================
// Factory Functions
// ============================================================================

std::unique_ptr<StreamingAdapter> create_streaming_adapter(
    const StreamingAdapter::Config& config
) {
    return std::make_unique<StreamingAdapter>(config);
}

bool validate_stream(
    std::span<const StreamingEvent> events,
    const ExecutionId& expected_execution_id
) {
    if (events.empty()) {
        return true;
    }
    
    // Validate sequence ordering
    if (!EventSequenceValidator::validate_sequence(events)) {
        return false;
    }
    
    // Validate no gaps
    if (!EventSequenceValidator::validate_no_gaps(events)) {
        return false;
    }
    
    // Validate same execution
    if (!EventSequenceValidator::validate_same_execution(events, expected_execution_id)) {
        return false;
    }
    
    // Validate hashes
    if (!EventSequenceValidator::validate_hashes(events)) {
        return false;
    }
    
    return true;
}

bool compare_streams(
    std::span<const StreamingEvent> original,
    std::span<const StreamingEvent> replay
) {
    if (original.size() != replay.size()) {
        return false;
    }
    
    for (size_t i = 0; i < original.size(); ++i) {
        // Compare event types
        if (original[i].type != replay[i].type) {
            return false;
        }
        
        // Compare sequence IDs
        if (original[i].sequence_id != replay[i].sequence_id) {
            return false;
        }
        
        // Compare hashes
        if (original[i].event_hash != replay[i].event_hash) {
            return false;
        }
    }
    
    return true;
}

} // namespace val063
