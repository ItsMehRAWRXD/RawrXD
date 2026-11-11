#include "execution_gateway.hpp"
#include <thread>
#include <atomic>

namespace val063 {

// ============================================================================
// ExecutionRequest::Configuration
// ============================================================================

Hash256 ExecutionRequest::Configuration::hash() const {
    HashProvider provider;
    
    // Canonical serialization (fixed order, no JSON ambiguity)
    provider.update(reinterpret_cast<const uint8_t*>(&temperature), sizeof(temperature));
    provider.update(reinterpret_cast<const uint8_t*>(&top_p), sizeof(top_p));
    provider.update(reinterpret_cast<const uint8_t*>(&top_k), sizeof(top_k));
    provider.update(reinterpret_cast<const uint8_t*>(&max_tokens), sizeof(max_tokens));
    provider.update(reinterpret_cast<const uint8_t*>(&seed), sizeof(seed));
    provider.update(reinterpret_cast<const uint8_t*>(stop_sequences.data()), stop_sequences.size());
    
    return provider.finalize();
}

// ============================================================================
// V10Runtime Stub
// ============================================================================

// Stub for v1.0 runtime interface
// In production, this would be the actual certified runtime ABI
struct V10Runtime {
    virtual ~V10Runtime() = default;
    virtual bool initialize() = 0;
    virtual std::string execute(const std::string& prompt, const ExecutionRequest::Configuration& config) = 0;
    virtual Hash256 get_runtime_hash() const = 0;
};

// ============================================================================
// ExecutionGateway Implementation
// ============================================================================

class ExecutionGateway::Impl {
public:
    V10Runtime* runtime_{nullptr};
    RuntimeVersion version_;
    std::optional<AttestationRecord> last_attestation_;
    
    // Statistics
    std::atomic<uint64_t> executions_total_{0};
    std::atomic<uint64_t> executions_completed_{0};
    std::atomic<uint64_t> executions_failed_{0};
    std::atomic<uint64_t> executions_cancelled_{0};
    std::atomic<uint64_t> identity_verifications_passed_{0};
    std::atomic<uint64_t> identity_verifications_failed_{0};
    
    // Integrity verification
    mutable std::vector<ExecutionIdentity> identity_log_;
    mutable std::mutex identity_mutex_;

    void initialize(V10Runtime* runtime, RuntimeVersion version) {
        runtime_ = runtime;
        version_ = std::move(version);
    }

    ExecutionResult execute(const ExecutionRequest& request) {
        ++executions_total_;
        
        // Step 1: Build identity from Gate A primitives (NEVER modify)
        ExecutionIdentity identity;
        identity.prompt_hash = hash::of_string(request.prompt);
        identity.configuration_hash = request.configuration.hash();
        identity.model_hash = hash::of_string(request.model_path);
        
        // Get runtime hash from certified v1.0 runtime
        if (runtime_) {
            identity.runtime_hash = runtime_->get_runtime_hash();
        }
        
        // Verify identity completeness
        if (!identity.is_complete()) {
            ExecutionResult result;
            result.success = false;
            result.error = "Identity incomplete - cannot attest";
            ++identity_verifications_failed_;
            return result;
        }
        
        // Step 2: Generate execution UUID (gateway responsibility)
        ExecutionId execution_id = uuid::generate();
        
        // Step 3: Capture start timestamp
        Timestamp start_time = timestamp::now();
        
        // Step 4: Create attestation record
        AttestationRecord record(
            execution_id,
            identity,
            start_time,
            request.preferred_backend,
            version_
        );
        
        // Log identity for integrity verification
        {
            std::lock_guard<std::mutex> lock(identity_mutex_);
            identity_log_.push_back(identity);
        }
        
        // Step 5: Execute via v1.0 runtime (non-invasive wrapper)
        ExecutionResult result;
        result.attestation = record;
        
        if (!runtime_) {
            result.success = false;
            result.error = "Runtime not initialized";
            record.mark_failed(timestamp::now(), "Runtime not initialized");
            ++executions_failed_;
            last_attestation_ = record;
            return result;
        }
        
        try {
            // Call certified v1.0 runtime (NO MODIFICATION)
            std::string output = runtime_->execute(request.prompt, request.configuration);
            
            // Step 6: Capture completion
            Timestamp end_time = timestamp::now();
            Hash256 output_hash = hash::of_string(output);
            
            record.mark_completed(end_time, output_hash);
            record.telemetry.tokens_generated = output.empty() ? 0 : 1; // Simplified
            
            // Populate result
            result.success = true;
            result.output_text = std::move(output);
            result.duration = end_time.elapsed_since(start_time);
            
            ++executions_completed_;
            ++identity_verifications_passed_;
            
        } catch (const std::exception& e) {
            Timestamp end_time = timestamp::now();
            record.mark_failed(end_time, e.what());
            
            result.success = false;
            result.error = e.what();
            result.duration = end_time.elapsed_since(start_time);
            
            ++executions_failed_;
        }
        
        last_attestation_ = record;
        result.attestation = record;
        return result;
    }

    ExecutionResult execute_streaming(
        const ExecutionRequest& request,
        TokenCallback callback
    ) {
        // For Gate B, streaming is stubbed
        // Full implementation in Gate C (Streaming Adapter)
        auto result = execute(request);
        
        // Simulate token callback with full output
        if (result.success && callback) {
            callback(result.output_text, 0);
        }
        
        return result;
    }

    bool verify_identity_integrity() const {
        std::lock_guard<std::mutex> lock(identity_mutex_);
        
        // Verify no identity was modified
        // In a real implementation, this would check that all logged identities
        // match their expected values from Gate A
        
        for (const auto& identity : identity_log_) {
            if (!identity.is_complete()) {
                return false;
            }
        }
        
        return true;
    }

    Statistics get_statistics() const {
        return {
            executions_total_.load(),
            executions_completed_.load(),
            executions_failed_.load(),
            executions_cancelled_.load(),
            identity_verifications_passed_.load(),
            identity_verifications_failed_.load()
        };
    }
};

// ============================================================================
// ExecutionGateway Public Interface
// ============================================================================

ExecutionGateway::ExecutionGateway() : impl_(std::make_unique<Impl>()) {}
ExecutionGateway::~ExecutionGateway() = default;

ExecutionGateway::ExecutionGateway(ExecutionGateway&&) noexcept = default;
ExecutionGateway& ExecutionGateway::operator=(ExecutionGateway&&) noexcept = default;

void ExecutionGateway::initialize(V10Runtime* runtime, RuntimeVersion version) {
    impl_->initialize(runtime, std::move(version));
}

ExecutionResult ExecutionGateway::execute(const ExecutionRequest& request) {
    return impl_->execute(request);
}

ExecutionResult ExecutionGateway::execute_streaming(
    const ExecutionRequest& request,
    TokenCallback callback
) {
    return impl_->execute_streaming(request, std::move(callback));
}

std::future<ExecutionResult> ExecutionGateway::execute_async(const ExecutionRequest& request) {
    return std::async(std::launch::async, [this, request]() {
        return execute(request);
    });
}

std::optional<AttestationRecord> ExecutionGateway::last_attestation() const {
    return impl_->last_attestation_;
}

bool ExecutionGateway::verify_integrity() const {
    return impl_->verify_identity_integrity();
}

ExecutionGateway::Statistics ExecutionGateway::get_statistics() const {
    return impl_->get_statistics();
}

// ============================================================================
// Factory Functions
// ============================================================================

std::unique_ptr<ExecutionGateway> create_gateway(
    V10Runtime* runtime,
    RuntimeVersion version
) {
    auto gateway = std::make_unique<ExecutionGateway>();
    gateway->initialize(runtime, std::move(version));
    return gateway;
}

bool validate_gateway(const ExecutionGateway& gateway) {
    // Verify gateway respects non-invasive constraint
    
    // 1. Check integrity
    if (!gateway.verify_integrity()) {
        return false;
    }
    
    // 2. Check statistics
    auto stats = gateway.get_statistics();
    if (stats.identity_verifications_failed > 0) {
        return false;
    }
    
    return true;
}

} // namespace val063
