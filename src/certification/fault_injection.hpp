// VAL-076: Runtime Fault Injection
// Resilience validation through controlled failures

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <functional>

namespace RawrXD {
namespace Certification {

// ============================================================================
// Fault Types
// ============================================================================

enum class FaultType {
    // Data corruption
    CORRUPTED_TENSOR,
    TRUNCATED_GGUF,
    INVALID_TOKENIZER_ENTRY,
    
    // Resource exhaustion
    KV_CACHE_EXHAUSTION,
    MEMORY_ALLOCATION_FAILURE,
    
    // Backend failures
    KERNEL_DISPATCH_FAILURE,
    BACKEND_CRASH,
    DEVICE_LOST,
    
    // Input validation
    MALFORMED_TELEMETRY,
    INVALID_SAMPLING_PARAMS,
    OVERSIZED_PROMPT,
    
    // Network/IO (for distributed)
    MODEL_LOAD_TIMEOUT,
    CHECKPOINT_CORRUPTION
};

enum class FaultSeverity {
    INFO,       // Logged but continue
    WARNING,    // Degraded operation
    ERROR,      // Graceful shutdown
    CRITICAL    // Immediate termination
};

struct FaultSpecification {
    FaultType type;
    FaultSeverity severity;
    std::string description;
    std::string target_component;
    
    // Injection parameters
    double injection_probability;  // 0.0 - 1.0
    uint64_t trigger_after_n_calls;  // Inject after N invocations
    bool deterministic;            // Reproducible injection
    
    std::string Serialize() const;
};

// ============================================================================
// Fault Injection Point
// ============================================================================

struct FaultInjectionPoint {
    std::string component;
    std::string operation;
    std::string file;
    int line;
    
    bool ShouldInject(const FaultSpecification& spec) const;
    std::string Serialize() const;
};

// ============================================================================
// Fault Event
// ============================================================================

struct FaultEvent {
    uint64_t event_id;
    FaultType type;
    FaultSeverity severity;
    std::string timestamp;
    
    // Context
    FaultInjectionPoint injection_point;
    std::string execution_context;
    std::string stack_trace;
    
    // Response
    std::string detection_mechanism;
    std::string response_action;
    bool controlled_failure;
    
    // Evidence
    std::string evidence_path;
    std::string error_code;
    
    std::string Serialize() const;
};

// ============================================================================
// Fault Injector
// ============================================================================

class FaultInjector {
public:
    FaultInjector();
    ~FaultInjector();
    
    // Configuration
    void EnableFaultInjection(bool enable);
    void AddFaultSpecification(const FaultSpecification& spec);
    void ClearFaultSpecifications();
    
    // Injection points
    bool MaybeInjectFault(
        const FaultInjectionPoint& point,
        const std::string& context
    );
    
    // Force injection (for testing)
    void ForceInjectFault(FaultType type, const std::string& component);
    
    // Get fault history
    std::vector<FaultEvent> GetFaultHistory() const;
    void ClearFaultHistory();
    
    // Generate fault report
    std::string GenerateFaultReport() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// ============================================================================
// Resilience Validator
// ============================================================================

struct ResilienceTestResult {
    FaultType fault_type;
    bool detected;
    bool controlled_failure;
    bool evidence_generated;
    uint64_t recovery_time_ms;
    std::string error_message;
    
    bool Passed() const {
        return detected && controlled_failure && evidence_generated;
    }
};

class ResilienceValidator {
public:
    ResilienceValidator();
    ~ResilienceValidator();
    
    // Run resilience test suite
    std::vector<ResilienceTestResult> RunResilienceTests();
    
    // Individual fault tests
    ResilienceTestResult TestCorruptedTensorHandling();
    ResilienceTestResult TestTruncatedGGUFHandling();
    ResilienceTestResult TestInvalidTokenizerEntryHandling();
    ResilienceTestResult TestKVCacheExhaustionHandling();
    ResilienceTestResult TestKernelDispatchFailureHandling();
    ResilienceTestResult TestBackendCrashHandling();
    ResilienceTestResult TestMalformedTelemetryHandling();
    
    // Validate no silent corruption
    bool ValidateNoSilentCorruption();
    
    // Get summary
    struct Summary {
        int total_tests;
        int passed;
        int failed;
        int undetected_faults;
        bool all_faults_controlled;
    };
    Summary GetSummary() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// ============================================================================
// Controlled Failure Handler
// ============================================================================

class ControlledFailureHandler {
public:
    using FailureCallback = std::function<void(const FaultEvent&)>;
    
    static ControlledFailureHandler& Instance();
    
    // Register failure handler
    void RegisterHandler(FaultSeverity severity, FailureCallback handler);
    
    // Handle fault
    void HandleFault(const FaultEvent& event);
    
    // Generate evidence artifact
    std::string GenerateFailureEvidence(const FaultEvent& event);
    
    // Get failure statistics
    struct Statistics {
        uint64_t total_faults;
        uint64_t controlled_failures;
        uint64_t uncontrolled_failures;
        uint64_t silent_corruptions;
    };
    Statistics GetStatistics() const;

private:
    ControlledFailureHandler() = default;
};

// ============================================================================
// C API
// ============================================================================

extern "C" {

// Fault injection
typedef struct Val076FaultInjector* Val076InjectorHandle;

Val076InjectorHandle val076_injector_create();
void val076_enable_injection(Val076InjectorHandle handle, int enable);
void val076_add_fault_spec(Val076InjectorHandle handle, int fault_type, int severity);
int val076_maybe_inject(Val076InjectorHandle handle, const char* component, const char* operation);
void val076_injector_destroy(Val076InjectorHandle handle);

// Resilience validation
typedef struct Val076ResilienceValidator* Val076ValidatorHandle;

Val076ValidatorHandle val076_validator_create();
int val076_run_resilience_tests(Val076ValidatorHandle handle);
const char* val076_get_fault_report(Val076ValidatorHandle handle);
void val076_validator_destroy(Val076ValidatorHandle handle);

} // extern "C"

} // namespace Certification
} // namespace RawrXD
