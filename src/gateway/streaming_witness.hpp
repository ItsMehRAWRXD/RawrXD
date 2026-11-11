// VAL-063 Streaming: Service Contract Witnesses
// Proves streaming behavior under real operating conditions

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <queue>
#include <mutex>
#include <chrono>

namespace RawrXD {
namespace Gateway {

// ============================================================================
// Streaming Event Schema
// ============================================================================

enum class StreamingEventType {
    REQUEST_START,
    PROMPT_BEGIN,
    PROMPT_END,
    TOKEN_GENERATED,
    TOKEN_DELIVERED,
    GENERATION_COMPLETE,
    REQUEST_END,
    BACKPRESSURE_APPLIED,
    BACKPRESSURE_RELEASED,
    ERROR
};

struct StreamingEvent {
    std::string execution_id;
    uint64_t sequence_number;
    StreamingEventType type;
    uint64_t timestamp_ns;
    
    // Token-specific fields
    int32_t token_id;
    std::string token_text;
    uint32_t position;
    
    // Backpressure fields
    uint32_t queue_depth;
    uint32_t queue_capacity;
    
    // Error fields
    std::string error_code;
    std::string error_message;
    
    std::string Serialize() const;
    std::string ComputeHash() const;
};

// ============================================================================
// Streaming Contract Witness (VAL-063D)
// ============================================================================

class StreamingContractWitness {
public:
    struct ContractValidation {
        bool event_ordering_valid = false;
        bool sequence_continuity_valid = false;
        bool timestamp_monotonic = false;
        bool execution_id_consistent = false;
        
        bool IsValid() const {
            return event_ordering_valid && 
                   sequence_continuity_valid && 
                   timestamp_monotonic && 
                   execution_id_consistent;
        }
    };
    
    void RecordEvent(const StreamingEvent& event);
    ContractValidation ValidateContract() const;
    std::string GenerateEvidence() const;
    
    // Invariant checks
    bool CheckEventOrdering() const;
    bool CheckSequenceContinuity() const;
    bool CheckTimestampMonotonicity() const;
    bool CheckExecutionIdConsistency() const;

private:
    std::vector<StreamingEvent> events_;
    mutable std::mutex mutex_;
};

// ============================================================================
// Backpressure Witness (VAL-063E)
// ============================================================================

class BackpressureWitness {
public:
    struct BackpressureMetrics {
        uint64_t tokens_produced = 0;
        uint64_t tokens_consumed = 0;
        uint64_t tokens_dropped = 0;
        uint64_t tokens_duplicated = 0;
        
        uint64_t backpressure_events = 0;
        uint64_t max_queue_depth = 0;
        uint64_t total_stall_ms = 0;
        
        bool IsValid() const {
            return tokens_dropped == 0 && 
                   tokens_duplicated == 0;
        }
    };
    
    void RecordProduction(uint64_t count);
    void RecordConsumption(uint64_t count);
    void RecordBackpressureEvent(uint32_t queue_depth, uint32_t capacity);
    void RecordStall(uint64_t duration_ms);
    
    BackpressureMetrics GetMetrics() const;
    std::string GenerateEvidence() const;
    
    // Invariant checks
    bool CheckNoDroppedTokens() const;
    bool CheckNoDuplicateTokens() const;
    bool CheckBoundedMemory() const;
    bool CheckDeterministicStall() const;

private:
    BackpressureMetrics metrics_;
    mutable std::mutex mutex_;
};

// ============================================================================
// Correlation Witness (VAL-063F)
// ============================================================================

class CorrelationWitness {
public:
    struct ExecutionChain {
        std::string request_hash;
        std::string model_hash;
        std::string runtime_hash;
        std::string token_sequence_hash;
        std::string output_hash;
        std::string execution_id;
        
        std::string ComputeChainHash() const;
        bool Validate() const;
    };
    
    void SealExecutionChain(const ExecutionChain& chain);
    bool VerifyChainIntegrity(const std::string& execution_id) const;
    std::string GenerateEvidence(const std::string& execution_id) const;
    
    // Chain proof
    std::string GetChainProof(const std::string& execution_id) const;

private:
    std::unordered_map<std::string, ExecutionChain> chains_;
    mutable std::mutex mutex_;
};

// ============================================================================
// Live Evidence Capture
// ============================================================================

class LiveEvidenceCapture {
public:
    struct EvidenceSnapshot {
        std::string request_hash;
        std::string model_artifact_hash;
        std::string runtime_binary_hash;
        std::string token_sequence_hash;
        std::string output_text_hash;
        
        uint64_t timestamp_start_ns;
        uint64_t timestamp_end_ns;
        
        bool Validate() const;
        std::string Serialize() const;
    };
    
    // Capture at execution boundaries
    EvidenceSnapshot CaptureAtStart(
        const std::string& request_data,
        const std::string& model_path,
        const std::string& runtime_path
    );
    
    EvidenceSnapshot CaptureAtEnd(
        const std::vector<int32_t>& tokens,
        const std::string& output_text
    );
    
    // Hash computation
    static std::string ComputeSHA256(const std::string& data);
    static std::string ComputeFileSHA256(const std::string& path);
    static std::string ComputeTokenHash(const std::vector<int32_t>& tokens);
    
    // Evidence sealing
    std::string SealEvidence(const EvidenceSnapshot& snapshot);
};

// ============================================================================
// CLI Gateway Binding
// ============================================================================

class GatewayEnforcer {
public:
    // Execution context required for all inference calls
    struct ExecutionContext {
        std::string execution_id;
        std::string gateway_attestation_hash;
        uint64_t issued_at_ns;
        uint64_t expires_at_ns;
        
        bool IsValid() const;
        std::string ComputeHash() const;
    };
    
    // Singleton enforcement
    static GatewayEnforcer& Instance();
    
    // Context lifecycle
    ExecutionContext IssueContext(const std::string& request_hash);
    bool ValidateContext(const ExecutionContext& ctx);
    void RevokeContext(const std::string& execution_id);
    
    // Enforcement
    bool RequireGatewayEntry();
    bool RejectDirectRuntimeAccess();
    
    // Status
    bool IsGatewayBound() const;
    uint64_t GetEnforcedRequestCount() const;
    uint64_t GetRejectedBypassAttempts() const;

private:
    GatewayEnforcer() = default;
    
    std::unordered_map<std::string, ExecutionContext> active_contexts_;
    std::atomic<uint64_t> enforced_count_{0};
    std::atomic<uint64_t> rejected_count_{0};
    std::atomic<bool> gateway_bound_{false};
    mutable std::mutex mutex_;
};

// ============================================================================
// C API
// ============================================================================

extern "C" {

// Streaming witness
typedef struct Val063StreamingWitness* Val063StreamingHandle;

Val063StreamingHandle val063_streaming_create();
void val063_streaming_destroy(Val063StreamingHandle handle);
void val063_streaming_record_event(
    Val063StreamingHandle handle,
    const char* execution_id,
    int event_type,
    uint64_t timestamp_ns,
    int32_t token_id,
    const char* token_text,
    uint32_t position
);
int val063_streaming_validate(Val063StreamingHandle handle);
const char* val063_streaming_get_evidence(Val063StreamingHandle handle);

// Backpressure witness
typedef struct Val063BackpressureWitness* Val063BackpressureHandle;

Val063BackpressureHandle val063_backpressure_create();
void val063_backpressure_destroy(Val063BackpressureHandle handle);
void val063_backpressure_record_production(Val063BackpressureHandle handle, uint64_t count);
void val063_backpressure_record_consumption(Val063BackpressureHandle handle, uint64_t count);
void val063_backpressure_record_stall(Val063BackpressureHandle handle, uint64_t duration_ms);
int val063_backpressure_validate(Val063BackpressureHandle handle);
const char* val063_backpressure_get_evidence(Val063BackpressureHandle handle);

// Correlation witness
typedef struct Val063CorrelationWitness* Val063CorrelationHandle;

Val063CorrelationHandle val063_correlation_create();
void val063_correlation_destroy(Val063CorrelationHandle handle);
void val063_correlation_seal_chain(
    Val063CorrelationHandle handle,
    const char* request_hash,
    const char* model_hash,
    const char* runtime_hash,
    const char* token_hash,
    const char* output_hash,
    const char* execution_id
);
int val063_correlation_verify(Val063CorrelationHandle handle, const char* execution_id);
const char* val063_correlation_get_proof(Val063CorrelationHandle handle, const char* execution_id);

// Gateway enforcement
int val063_gateway_bind();
int val063_gateway_require_context(const char* execution_id, const char* attestation_hash);
int val063_gateway_is_bound();
uint64_t val063_gateway_get_enforced_count();
uint64_t val063_gateway_get_rejected_count();

} // extern "C"

} // namespace Gateway
} // namespace RawrXD
