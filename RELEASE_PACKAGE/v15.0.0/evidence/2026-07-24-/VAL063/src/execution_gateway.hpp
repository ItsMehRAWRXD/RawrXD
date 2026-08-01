#pragma once

#include "attestation_record.hpp"
#include <functional>
#include <future>

namespace val063 {

// Forward declaration of v1.0 runtime interface
// The gateway wraps this without modification
struct V10Runtime;

// Execution request (input to gateway)
struct ExecutionRequest {
    // Input text (will be hashed by identity provider)
    std::string prompt;
    
    // Configuration (will be hashed by identity provider)
    struct Configuration {
        float temperature{0.8f};
        float top_p{0.95f};
        int top_k{40};
        int max_tokens{256};
        uint32_t seed{0};  // 0 = random
        std::string stop_sequences;
        
        // Canonical hash of configuration
        Hash256 hash() const;
    } configuration;
    
    // Model identifier (path or identifier, will be hashed)
    std::string model_path;
    
    // Backend preference
    BackendID preferred_backend{BackendID::Native};
    
    // Timeout
    std::chrono::milliseconds timeout{std::chrono::seconds(30)};
};

// Execution result (output from gateway)
struct ExecutionResult {
    // The attestation record (evidence)
    AttestationRecord attestation;
    
    // Success flag
    bool success{false};
    
    // Output data (if successful)
    std::string output_text;
    
    // Error message (if failed)
    std::string error;
    
    // Timing
    std::chrono::nanoseconds duration{0};
};

// Token streaming callback
using TokenCallback = std::function<void(const std::string& token, uint64_t token_index)>;

// The Gateway Binding (Gate B)
// 
// RESPONSIBILITY: Observe and attest execution without redefining identity
// CONSTRAINT: Never modifies identity components from Gate A
// CONTRACT: Consumes identity, attaches execution UUID, emits attestation
//
class ExecutionGateway {
public:
    ExecutionGateway();
    ~ExecutionGateway();

    // Non-copyable (holds runtime reference)
    ExecutionGateway(const ExecutionGateway&) = delete;
    ExecutionGateway& operator=(const ExecutionGateway&) = delete;

    // Movable
    ExecutionGateway(ExecutionGateway&&) noexcept;
    ExecutionGateway& operator=(ExecutionGateway&&) noexcept;

    // Initialize with v1.0 runtime reference
    // The gateway wraps the runtime without modification
    void initialize(V10Runtime* runtime, RuntimeVersion version);

    // Execute with full attestation
    // This is the primary entry point for VAL-063 certified execution
    ExecutionResult execute(const ExecutionRequest& request);

    // Execute with streaming
    ExecutionResult execute_streaming(
        const ExecutionRequest& request,
        TokenCallback callback
    );

    // Async execution
    std::future<ExecutionResult> execute_async(const ExecutionRequest& request);

    // Get last attestation (for verification)
    std::optional<AttestationRecord> last_attestation() const;

    // Verify gateway integrity
    // Checks that identity is never mutated
    bool verify_integrity() const;

    // Get gateway statistics
    struct Statistics {
        uint64_t executions_total{0};
        uint64_t executions_completed{0};
        uint64_t executions_failed{0};
        uint64_t executions_cancelled{0};
        uint64_t identity_verifications_passed{0};
        uint64_t identity_verifications_failed{0};
    };
    Statistics get_statistics() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// Gateway factory
// Creates a gateway bound to the certified v1.0 runtime
std::unique_ptr<ExecutionGateway> create_gateway(
    V10Runtime* runtime,
    RuntimeVersion version
);

// Gateway validation
// Verifies that a gateway instance respects the non-invasive constraint
bool validate_gateway(const ExecutionGateway& gateway);

} // namespace val063
