#include "attestation_record.hpp"
#include <sstream>
#include <iomanip>

namespace val063 {

// ============================================================================
// BackendID
// ============================================================================

std::string to_string(BackendID backend) {
    switch (backend) {
        case BackendID::Native: return "native";
        case BackendID::Vulkan: return "vulkan";
        case BackendID::CUDA: return "cuda";
        case BackendID::CPU: return "cpu";
        case BackendID::Unknown: return "unknown";
    }
    return "unknown";
}

std::optional<BackendID> backend_from_string(std::string_view str) {
    if (str == "native") return BackendID::Native;
    if (str == "vulkan") return BackendID::Vulkan;
    if (str == "cuda") return BackendID::CUDA;
    if (str == "cpu") return BackendID::CPU;
    if (str == "unknown") return BackendID::Unknown;
    return std::nullopt;
}

// ============================================================================
// ExecutionStatus
// ============================================================================

std::string to_string(ExecutionStatus status) {
    switch (status) {
        case ExecutionStatus::Pending: return "pending";
        case ExecutionStatus::Running: return "running";
        case ExecutionStatus::Completed: return "completed";
        case ExecutionStatus::Failed: return "failed";
        case ExecutionStatus::Cancelled: return "cancelled";
        case ExecutionStatus::Timeout: return "timeout";
    }
    return "unknown";
}

// ============================================================================
// TelemetrySummary
// ============================================================================

bool TelemetrySummary::operator==(const TelemetrySummary& other) const {
    return tokens_generated == other.tokens_generated &&
           tokens_per_second == other.tokens_per_second &&
           memory_bytes_used == other.memory_bytes_used &&
           context_tokens == other.context_tokens &&
           telemetry_hash == other.telemetry_hash;
}

Hash256 TelemetrySummary::combined_hash() const {
    // Combine all telemetry fields into a hash
    HashProvider provider;
    
    // Hash each field
    provider.update(reinterpret_cast<const uint8_t*>(&tokens_generated), sizeof(tokens_generated));
    provider.update(reinterpret_cast<const uint8_t*>(&tokens_per_second), sizeof(tokens_per_second));
    provider.update(reinterpret_cast<const uint8_t*>(&memory_bytes_used), sizeof(memory_bytes_used));
    provider.update(reinterpret_cast<const uint8_t*>(&context_tokens), sizeof(context_tokens));
    provider.update(telemetry_hash.bytes.data(), telemetry_hash.bytes.size());
    
    return provider.finalize();
}

// ============================================================================
// AttestationRecord
// ============================================================================

AttestationRecord::AttestationRecord(
    ExecutionId exec_id,
    ExecutionIdentity exec_identity,
    Timestamp start,
    BackendID exec_backend,
    RuntimeVersion gw_version
) : execution_id(exec_id)
  , identity(exec_identity)
  , started_at(start)
  , backend(exec_backend)
  , status(ExecutionStatus::Running)
  , gateway_version(gw_version)
  , attested_at(Timestamp::now())
{}

void AttestationRecord::mark_completed(Timestamp end_time, Hash256 output) {
    completed_at = end_time;
    output_hash = output;
    status = ExecutionStatus::Completed;
    attested_at = Timestamp::now();
}

void AttestationRecord::mark_failed(Timestamp end_time, std::string error) {
    completed_at = end_time;
    error_message = std::move(error);
    status = ExecutionStatus::Failed;
    attested_at = Timestamp::now();
}

void AttestationRecord::mark_cancelled(Timestamp end_time) {
    completed_at = end_time;
    status = ExecutionStatus::Cancelled;
    attested_at = Timestamp::now();
}

bool AttestationRecord::verify_identity(const ExecutionIdentity& expected) const {
    // Constant-time comparison of all identity components
    return identity.prompt_hash == expected.prompt_hash &&
           identity.configuration_hash == expected.configuration_hash &&
           identity.model_hash == expected.model_hash &&
           identity.runtime_hash == expected.runtime_hash;
}

std::string AttestationRecord::to_json() const {
    std::ostringstream oss;
    oss << "{\n";
    
    // Execution correlation
    oss << "  \"execution_id\": \"" << execution_id.to_string() << "\",\n";
    
    // Identity (from Gate A - never modified)
    oss << "  \"identity\": {\n";
    oss << "    \"prompt_hash\": \"" << identity.prompt_hash.hex() << "\",\n";
    oss << "    \"configuration_hash\": \"" << identity.configuration_hash.hex() << "\",\n";
    oss << "    \"model_hash\": \"" << identity.model_hash.hex() << "\",\n";
    oss << "    \"runtime_hash\": \"" << identity.runtime_hash.hex() << "\"\n";
    oss << "  },\n";
    
    // Gateway observations
    oss << "  \"started_at\": \"" << started_at.iso8601() << "\",\n";
    if (completed_at) {
        oss << "  \"completed_at\": \"" << completed_at->iso8601() << "\",\n";
    }
    oss << "  \"backend\": \"" << to_string(backend) << "\",\n";
    oss << "  \"status\": \"" << to_string(status) << "\",\n";
    
    if (error_message) {
        oss << "  \"error_message\": \"" << *error_message << "\",\n";
    }
    
    // Telemetry
    oss << "  \"telemetry\": {\n";
    oss << "    \"tokens_generated\": " << telemetry.tokens_generated << ",\n";
    oss << "    \"tokens_per_second\": " << telemetry.tokens_per_second << ",\n";
    oss << "    \"memory_bytes_used\": " << telemetry.memory_bytes_used << ",\n";
    oss << "    \"context_tokens\": " << telemetry.context_tokens << ",\n";
    oss << "    \"telemetry_hash\": \"" << telemetry.telemetry_hash.hex() << "\"\n";
    oss << "  },\n";
    
    // Output
    oss << "  \"output_hash\": \"" << output_hash.hex() << "\",\n";
    
    // Attestation metadata
    oss << "  \"gateway_version\": \"" << gateway_version.to_string() << "\",\n";
    oss << "  \"attested_at\": \"" << attested_at.iso8601() << "\"\n";
    
    oss << "}";
    return oss.str();
}

std::optional<AttestationRecord> AttestationRecord::from_json(std::string_view json) {
    // Simplified parsing - production would use proper JSON parser
    // For now, return nullopt to indicate not implemented in Gate A/B
    return std::nullopt;
}

Hash256 AttestationRecord::attestation_hash() const {
    // Compute hash of the complete attestation for verification chains
    HashProvider provider;
    
    // Include all fixed fields
    provider.update(execution_id.bytes.data(), execution_id.bytes.size());
    provider.update(identity.to_canonical_bytes().data(), 128);
    provider.update(reinterpret_cast<const uint8_t*>(&started_at.wall_ns_since_epoch()), sizeof(int64_t));
    if (completed_at) {
        provider.update(reinterpret_cast<const uint8_t*>(&completed_at->wall_ns_since_epoch()), sizeof(int64_t));
    }
    provider.update(output_hash.bytes.data(), output_hash.bytes.size());
    
    return provider.finalize();
}

// ============================================================================
// GateBEvidence
// ============================================================================

std::string GateBEvidence::to_json() const {
    std::ostringstream oss;
    oss << "{\n";
    oss << "  \"gate\": \"" << gate << "\",\n";
    oss << "  \"name\": \"" << name << "\",\n";
    oss << "  \"status\": \"" << status << "\",\n";
    oss << "  \"observes_identity\": " << (observes_identity ? "true" : "false") << ",\n";
    oss << "  \"mutates_identity\": " << (mutates_identity ? "true" : "false") << ",\n";
    oss << "  \"execution_attestation\": {\n";
    oss << "    \"uuid\": \"" << execution_attestation.uuid << "\",\n";
    oss << "    \"timestamp\": \"" << execution_attestation.timestamp << "\",\n";
    oss << "    \"backend\": \"" << execution_attestation.backend << "\"\n";
    oss << "  },\n";
    oss << "  \"identity_source\": \"" << identity_source << "\",\n";
    oss << "  \"captured_at\": \"" << captured_at.iso8601() << "\"\n";
    oss << "}";
    return oss.str();
}

} // namespace val063
