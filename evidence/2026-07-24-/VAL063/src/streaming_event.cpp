#include "streaming_event.hpp"
#include <sstream>
#include <iomanip>

namespace val063 {

// ============================================================================
// EventType
// ============================================================================

std::string to_string(EventType type) {
    switch (type) {
        case EventType::ExecutionStarted: return "execution_started";
        case EventType::ExecutionCompleted: return "execution_completed";
        case EventType::ExecutionFailed: return "execution_failed";
        case EventType::ExecutionCancelled: return "execution_cancelled";
        case EventType::TokenGenerated: return "token_generated";
        case EventType::TokenAccepted: return "token_accepted";
        case EventType::TokenRejected: return "token_rejected";
        case EventType::ContextUpdated: return "context_updated";
        case EventType::SamplingStarted: return "sampling_started";
        case EventType::SamplingCompleted: return "sampling_completed";
        case EventType::ProgressUpdate: return "progress_update";
        case EventType::MemoryPressure: return "memory_pressure";
        case EventType::BackpressureApplied: return "backpressure_applied";
        case EventType::BackpressureReleased: return "backpressure_released";
        case EventType::Heartbeat: return "heartbeat";
        case EventType::StreamResumed: return "stream_resumed";
        case EventType::StreamTerminated: return "stream_terminated";
    }
    return "unknown";
}

// ============================================================================
// TokenPayload
// ============================================================================

Hash256 TokenPayload::token_hash() const {
    HashProvider provider;
    provider.update(reinterpret_cast<const uint8_t*>(token_text.data()), token_text.size());
    provider.update(reinterpret_cast<const uint8_t*>(&token_id), sizeof(token_id));
    provider.update(reinterpret_cast<const uint8_t*>(&logit_score), sizeof(logit_score));
    return provider.finalize();
}

// ============================================================================
// StreamingEvent
// ============================================================================

StreamingEvent::StreamingEvent(
    uint64_t seq,
    ExecutionId exec_id,
    EventType evt_type,
    Timestamp ts,
    EventPayload evt_payload
) : sequence_id(seq)
  , execution_id(exec_id)
  , type(evt_type)
  , timestamp(ts)
  , payload(std::move(evt_payload))
{
    event_hash = compute_hash();
}

Hash256 StreamingEvent::compute_hash() const {
    HashProvider provider;
    
    // Hash sequence ID
    provider.update(reinterpret_cast<const uint8_t*>(&sequence_id), sizeof(sequence_id));
    
    // Hash execution ID
    provider.update(execution_id.bytes.data(), execution_id.bytes.size());
    
    // Hash event type
    uint32_t type_val = static_cast<uint32_t>(type);
    provider.update(reinterpret_cast<const uint8_t*>(&type_val), sizeof(type_val));
    
    // Hash timestamp (monotonic for ordering)
    auto mono_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
        timestamp.monotonic.time_since_epoch()
    ).count();
    provider.update(reinterpret_cast<const uint8_t*>(&mono_ns), sizeof(mono_ns));
    
    return provider.finalize();
}

bool StreamingEvent::verify_integrity() const {
    return event_hash == compute_hash();
}

std::string StreamingEvent::to_json() const {
    std::ostringstream oss;
    oss << "{\n";
    oss << "  \"sequence_id\": " << sequence_id << ",\n";
    oss << "  \"execution_id\": \"" << execution_id.to_string() << "\",\n";
    oss << "  \"type\": \"" << to_string(type) << "\",\n";
    oss << "  \"timestamp\": \"" << timestamp.iso8601() << "\",\n";
    oss << "  \"event_hash\": \"" << event_hash.hex() << "\"";
    
    // Add payload if present
    std::visit([&oss](const auto& p) {
        using T = std::decay_t<decltype(p)>;
        if constexpr (!std::is_same_v<T, std::monostate>) {
            oss << ",\n  \"payload\": ";
            if constexpr (std::is_same_v<T, TokenPayload>) {
                oss << "{\"token\": \"" << p.token_text << "\", "
                    << "\"token_id\": " << p.token_id << "}";
            } else if constexpr (std::is_same_v<T, ProgressPayload>) {
                oss << "{\"tokens_generated\": " << p.tokens_generated << "}";
            } else if constexpr (std::is_same_v<T, std::string>) {
                oss << "\"" << p << "\"";
            } else {
                oss << "{}";
            }
        }
    }, payload);
    
    oss << "\n}";
    return oss.str();
}

// ============================================================================
// EventSequenceValidator
// ============================================================================

bool EventSequenceValidator::validate_sequence(std::span<const StreamingEvent> events) {
    if (events.empty()) return true;
    
    for (size_t i = 1; i < events.size(); ++i) {
        // Strictly increasing sequence IDs
        if (events[i].sequence_id <= events[i-1].sequence_id) {
            return false;
        }
        // Monotonic timestamps
        if (!TimestampProvider::is_monotonic(events[i-1].timestamp, events[i].timestamp)) {
            return false;
        }
    }
    return true;
}

bool EventSequenceValidator::validate_no_gaps(std::span<const StreamingEvent> events) {
    if (events.size() < 2) return true;
    
    for (size_t i = 1; i < events.size(); ++i) {
        // Sequence IDs must be consecutive
        if (events[i].sequence_id != events[i-1].sequence_id + 1) {
            return false;
        }
    }
    return true;
}

bool EventSequenceValidator::validate_same_execution(
    std::span<const StreamingEvent> events,
    const ExecutionId& expected_id
) {
    for (const auto& event : events) {
        if (event.execution_id != expected_id) {
            return false;
        }
    }
    return true;
}

bool EventSequenceValidator::validate_hashes(std::span<const StreamingEvent> events) {
    for (const auto& event : events) {
        if (!event.verify_integrity()) {
            return false;
        }
    }
    return true;
}

// ============================================================================
// GateCEvidence
// ============================================================================

std::string GateCEvidence::to_json() const {
    std::ostringstream oss;
    oss << "{\n";
    oss << "  \"gate\": \"" << gate << "\",\n";
    oss << "  \"name\": \"" << name << "\",\n";
    oss << "  \"status\": \"" << status << "\",\n";
    oss << "  \"guarantees\": {\n";
    oss << "    \"ordering\": " << (guarantees.ordering ? "true" : "false") << ",\n";
    oss << "    \"bounded_memory\": " << (guarantees.bounded_memory ? "true" : "false") << ",\n";
    oss << "    \"backpressure\": " << (guarantees.backpressure ? "true" : "false") << ",\n";
    oss << "    \"cancellation\": " << (guarantees.cancellation ? "true" : "false") << "\n";
    oss << "  },\n";
    oss << "  \"queue_capacity\": " << queue_capacity << ",\n";
    oss << "  \"high_watermark\": " << high_watermark << ",\n";
    oss << "  \"low_watermark\": " << low_watermark << ",\n";
    oss << "  \"captured_at\": \"" << captured_at.iso8601() << "\"\n";
    oss << "}";
    return oss.str();
}

} // namespace val063
