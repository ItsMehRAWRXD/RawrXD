#pragma once

#include "execution_types.hpp"
#include <optional>
#include <string>

namespace val063 {

// Backend identifier for execution attestation
enum class BackendID {
    Native,      // v1.0 certified runtime
    Vulkan,      // Vulkan compute backend
    CUDA,        // CUDA backend
    CPU,         // CPU fallback
    Unknown      // Unspecified/unsupported
};

std::string to_string(BackendID backend);
std::optional<BackendID> backend_from_string(std::string_view str);

// Execution status lifecycle
enum class ExecutionStatus {
    Pending,     // Request received, not yet started
    Running,     // Actively executing
    Completed,   // Finished successfully
    Failed,      // Execution error
    Cancelled,   // User/system cancellation
    Timeout      // Exceeded time limit
};

std::string to_string(ExecutionStatus status);

// Telemetry summary (hashed for attestation)
struct TelemetrySummary {
    uint64_t tokens_generated{0};
    uint64_t tokens_per_second{0};
    uint64_t memory_bytes_used{0};
    uint64_t context_tokens{0};
    
    // Hash of full telemetry data
    Hash256 telemetry_hash;
    
    bool operator==(const TelemetrySummary& other) const;
    Hash256 combined_hash() const;
};

// The attestation record produced by Gate B
// This is the bridge between Gate A identity and execution observation
struct AttestationRecord {
    // Execution correlation (from Gate A)
    ExecutionId execution_id;
    
    // Identity substrate (consumed from Gate A, never modified)
    ExecutionIdentity identity;
    
    // Gateway observations
    Timestamp started_at;
    std::optional<Timestamp> completed_at;
    
    BackendID backend{BackendID::Unknown};
    ExecutionStatus status{ExecutionStatus::Pending};
    
    // Optional error information for failed executions
    std::optional<std::string> error_message;
    
    // Telemetry (hashed for integrity)
    TelemetrySummary telemetry;
    
    // Final output hash (if execution completed)
    Hash256 output_hash;
    
    // Attestation metadata
    RuntimeVersion gateway_version;
    Timestamp attested_at;
    
    AttestationRecord() = default;
    AttestationRecord(
        ExecutionId exec_id,
        ExecutionIdentity exec_identity,
        Timestamp start,
        BackendID exec_backend,
        RuntimeVersion gw_version
    );

    // Mark execution as completed
    void mark_completed(Timestamp end_time, Hash256 output);
    
    // Mark execution as failed
    void mark_failed(Timestamp end_time, std::string error);
    
    // Mark execution as cancelled
    void mark_cancelled(Timestamp end_time);
    
    // Verify identity integrity (matches Gate A)
    bool verify_identity(const ExecutionIdentity& expected) const;
    
    // Canonical JSON serialization
    std::string to_json() const;
    
    // Deserialize from JSON
    static std::optional<AttestationRecord> from_json(std::string_view json);
    
    // Compute attestation hash (for verification chains)
    Hash256 attestation_hash() const;
};

// Gate B evidence structure
struct GateBEvidence {
    std::string gate{"B"};
    std::string name{"Gateway Binding"};
    std::string status{"PENDING"};
    
    bool observes_identity{false};
    bool mutates_identity{false};
    
    struct ExecutionAttestation {
        std::string uuid;
        std::string timestamp;
        std::string backend{"native"};
    } execution_attestation;
    
    std::string identity_source{"Gate_A"};
    
    Timestamp captured_at;
    
    std::string to_json() const;
    bool all_passed() const { return status == "PASS"; }
};

} // namespace val063
