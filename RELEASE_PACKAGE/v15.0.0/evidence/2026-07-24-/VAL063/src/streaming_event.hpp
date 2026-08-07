#pragma once

#include "execution_types.hpp"
#include <vector>
#include <string>
#include <variant>

namespace val063 {

// Event types in the streaming timeline
enum class EventType {
    // Lifecycle events
    ExecutionStarted,      // Execution began
    ExecutionCompleted,    // Execution finished successfully
    ExecutionFailed,       // Execution failed
    ExecutionCancelled,    // Execution was cancelled
    
    // Token events
    TokenGenerated,        // A token was produced
    TokenAccepted,         // Token passed validation
    TokenRejected,         // Token failed validation
    
    // State events
    ContextUpdated,        // Context window changed
    SamplingStarted,       // Sampling began for next token
    SamplingCompleted,     // Sampling finished
    
    // Telemetry events
    ProgressUpdate,        // Periodic progress report
    MemoryPressure,        // Memory threshold crossed
    BackpressureApplied,   // Consumer is slower than producer
    BackpressureReleased,  // Consumer caught up
    
    // Special
    Heartbeat,             // Keepalive for long streams
    StreamResumed,         // After reconnect/pause
    StreamTerminated       // Final event, stream closed
};

std::string to_string(EventType type);

// Token payload for TokenGenerated events
struct TokenPayload {
    std::string token_text;
    uint32_t token_id{0};
    float logit_score{0.0f};
    float probability{0.0f};
    
    // Hash of token for verification
    Hash256 token_hash() const;
};

// Progress payload for telemetry
struct ProgressPayload {
    uint64_t tokens_generated{0};
    uint64_t tokens_remaining{0};
    float completion_ratio{0.0f};
    uint64_t estimated_ms_remaining{0};
};

// Memory pressure payload
struct MemoryPayload {
    uint64_t bytes_used{0};
    uint64_t bytes_available{0};
    float utilization_ratio{0.0f};
    bool is_critical{false};
};

// Backpressure payload
struct BackpressurePayload {
    uint64_t queue_depth{0};
    uint64_t queue_capacity{0};
    uint64_t consumer_lag_ms{0};
    bool is_blocked{false};
};

// Event payload variant
using EventPayload = std::variant<
    std::monostate,           // No payload
    TokenPayload,             // Token data
    ProgressPayload,          // Progress data
    MemoryPayload,            // Memory data
    BackpressurePayload,      // Backpressure data
    std::string               // Generic message
>;

// Streaming event - immutable once created
struct StreamingEvent {
    // Sequence ordering (strictly monotonic per execution)
    uint64_t sequence_id{0};
    
    // Execution correlation (from Gate A)
    ExecutionId execution_id;
    
    // Event classification
    EventType type{EventType::Heartbeat};
    
    // Temporal marker
    Timestamp timestamp;
    
    // Event data
    EventPayload payload;
    
    // Integrity hash (covers sequence_id, execution_id, type, timestamp)
    Hash256 event_hash;
    
    StreamingEvent() = default;
    StreamingEvent(
        uint64_t seq,
        ExecutionId exec_id,
        EventType evt_type,
        Timestamp ts,
        EventPayload evt_payload = std::monostate{}
    );
    
    // Compute integrity hash
    Hash256 compute_hash() const;
    
    // Verify event integrity
    bool verify_integrity() const;
    
    // JSON serialization
    std::string to_json() const;
    
    // Ordering comparison (for sequence validation)
    bool operator<(const StreamingEvent& other) const {
        return sequence_id < other.sequence_id;
    }
};

// Event sequence validator
class EventSequenceValidator {
public:
    // Validate that events are in strict sequence order
    static bool validate_sequence(std::span<const StreamingEvent> events);
    
    // Validate no gaps in sequence
    static bool validate_no_gaps(std::span<const StreamingEvent> events);
    
    // Validate all events belong to same execution
    static bool validate_same_execution(
        std::span<const StreamingEvent> events,
        const ExecutionId& expected_id
    );
    
    // Validate event hashes
    static bool validate_hashes(std::span<const StreamingEvent> events);
};

// Gate C evidence structure
struct GateCEvidence {
    std::string gate{"C"};
    std::string name{"Streaming Adapter"};
    std::string status{"PENDING"};
    
    struct Guarantees {
        bool ordering{false};
        bool bounded_memory{false};
        bool backpressure{false};
        bool cancellation{false};
    } guarantees;
    
    uint64_t queue_capacity{1024};
    uint64_t high_watermark{768};
    uint64_t low_watermark{256};
    
    Timestamp captured_at;
    
    std::string to_json() const;
    bool all_passed() const {
        return guarantees.ordering && 
               guarantees.bounded_memory && 
               guarantees.backpressure && 
               guarantees.cancellation;
    }
};

} // namespace val063
