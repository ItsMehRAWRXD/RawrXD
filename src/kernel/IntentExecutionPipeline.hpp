// Intent Execution Pipeline - End-to-End Integration
// Wires Intent ABI → PatchFirewall → PatchTransaction → Execution
//
// This is the critical path that makes the architecture real:
//   ModelResponse -> IntentRequest -> PatchFirewall -> ExecutionABI -> NativeBackend

#pragma once

#include "AgentKernel.hpp"
#include "../intent/intent_abi.hpp"
#include "../intent/model_adapter.hpp"
#include "../guardrails/patch_firewall.hpp"
#include "../guardrails/capability_policy.hpp"
#include "../hotpatch/patch_transaction.hpp"
#include "../security/SecurityHardening.hpp"
#include "TelemetryInjector.hpp"

#include <functional>
#include <future>

namespace RawrXD {
namespace Kernel {

// ============================================================================
// Execution Result - What happens after intent execution
// ============================================================================

struct ExecutionResult {
    bool success;
    std::string intentType;
    uint64_t intentId;
    
    // Timing
    double validationTimeMs;
    double executionTimeMs;
    double totalTimeMs;
    
    // Outcomes
    enum class Outcome {
        SUCCESS,           // Intent executed successfully
        VALIDATION_FAILED, // PatchFirewall rejected
        CAPABILITY_DENIED, // Missing capability token
        TRANSACTION_FAILED,// PatchTransaction rollback
        EXECUTION_ERROR,   // Runtime error
        TIMEOUT,           // Exceeded time limit
        EMERGENCY_STOP     // Kernel emergency stop
    } outcome;
    
    std::string errorMessage;
    std::string errorDetails;
    
    // Rollback info
    bool wasRolledBack;
    uint64_t rollbackEpoch;
    
    // Telemetry
    std::unordered_map<std::string, std::string> telemetry;
    
    std::string ToJson() const;
    bool IsSuccess() const { return success && outcome == Outcome::SUCCESS; }
};

// ============================================================================
// Intent Handler - Pluggable execution backends
// ============================================================================

using IntentHandler = std::function<ExecutionResult(const IntentRequest&, 
                                                       const Intent::IntentRequest&)>;

class IntentHandlerRegistry {
public:
    static IntentHandlerRegistry& Instance();
    
    void Register(const std::string& intentType, IntentHandler handler);
    void Unregister(const std::string& intentType);
    
    bool HasHandler(const std::string& intentType) const;
    IntentHandler GetHandler(const std::string& intentType) const;
    
    std::vector<std::string> GetRegisteredTypes() const;
    
private:
    IntentHandlerRegistry() = default;
    
    mutable std::mutex handlersMutex_;
    std::unordered_map<std::string, IntentHandler> handlers_;
};

// ============================================================================
// Execution Pipeline - The main integration point
// ============================================================================

class IntentExecutionPipeline {
public:
    static IntentExecutionPipeline& Instance();
    
    // Lifecycle
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const { return initialized_.load(); }
    
    // Main entry point - Execute an intent end-to-end
    ExecutionResult Execute(const IntentRequest& kernelIntent);
    
    // Async execution
    std::future<ExecutionResult> ExecuteAsync(const IntentRequest& kernelIntent);
    
    // Validation only (dry run)
    ExecutionResult ValidateOnly(const IntentRequest& kernelIntent);
    
    // Configuration
    void SetValidationTimeout(std::chrono::milliseconds timeout);
    void SetExecutionTimeout(std::chrono::milliseconds timeout);
    void EnableDryRunMode(bool enable) { dryRunMode_.store(enable); }
    bool IsDryRunMode() const { return dryRunMode_.load(); }
    
    // Statistics
    struct PipelineStats {
        uint64_t totalIntents;
        uint64_t successfulIntents;
        uint64_t failedIntents;
        uint64_t rolledBackIntents;
        double averageValidationTimeMs;
        double averageExecutionTimeMs;
        std::unordered_map<std::string, uint64_t> intentsByType;
    };
    PipelineStats GetStats() const;
    void ResetStats();
    
    // Integration helpers
    void ConnectToModelAdapter();
    void ConnectToTelemetryInjector();
    
private:
    IntentExecutionPipeline() = default;
    
    // Pipeline stages
    bool Stage1_ValidateIntent(const IntentRequest& kernelIntent,
                                Intent::IntentRequest& abiIntent);
    bool Stage2_AcquireCapabilities(const IntentRequest& kernelIntent,
                                     Guardrails::CapabilityToken& token);
    bool Stage3_FirewallCheck(const Intent::IntentRequest& abiIntent,
                               Guardrails::PatchFirewall::ValidationResult& result);
    bool Stage4_CreateTransaction(const IntentRequest& kernelIntent,
                                   Hotpatch::PatchTransaction& tx);
    bool Stage5_ExecuteHandler(const IntentRequest& kernelIntent,
                                const Intent::IntentRequest& abiIntent,
                                ExecutionResult& result);
    bool Stage6_CommitOrRollback(Hotpatch::PatchTransaction& tx,
                                  bool success,
                                  ExecutionResult& result);
    
    std::atomic<bool> initialized_{false};
    std::atomic<bool> dryRunMode_{false};
    
    std::chrono::milliseconds validationTimeout_{5000};  // 5 seconds
    std::chrono::milliseconds executionTimeout_{30000}; // 30 seconds
    
    // Statistics
    mutable std::mutex statsMutex_;
    PipelineStats stats_{};
    
    // Security
    bool securityPreCheck(const IntentRequest& kernelIntent, ExecutionResult& result);
    void securityPostLog(const IntentRequest& kernelIntent, const ExecutionResult& result);
    
    // Integration
    uint64_t telemetrySubscriptionId_{0};
};

// ============================================================================
// Built-in Intent Handlers
// ============================================================================

// MODIFY_FUNCTION - Hotpatch a function
ExecutionResult HandleModifyFunction(const IntentRequest& kernelIntent,
                                      const Intent::IntentRequest& abiIntent);

// BUILD_PROJECT - Trigger build
ExecutionResult HandleBuildProject(const IntentRequest& kernelIntent,
                                    const Intent::IntentRequest& abiIntent);

// RUN_TESTS - Execute test suite
ExecutionResult HandleRunTests(const IntentRequest& kernelIntent,
                                const Intent::IntentRequest& abiIntent);

// DEBUG_SESSION - Start debugging
ExecutionResult HandleDebugSession(const IntentRequest& kernelIntent,
                                      const Intent::IntentRequest& abiIntent);

// OPTIMIZE_CODE - Self-optimization
ExecutionResult HandleOptimizeCode(const IntentRequest& kernelIntent,
                                      const Intent::IntentRequest& abiIntent);

// ============================================================================
// Convenience API
// ============================================================================

#define EXECUTION_PIPELINE RawrXD::Kernel::IntentExecutionPipeline::Instance()

// Quick execute helper
inline ExecutionResult QuickExecute(const std::string& intentType,
                                     const std::string& target,
                                     const std::string& description) {
    IntentRequest kernelIntent;
    kernelIntent.intentType = intentType;
    kernelIntent.targetFiles = {target};
    kernelIntent.priority = IntentPriority::NORMAL;
    kernelIntent.maxRetries = 3;
    kernelIntent.requiresHumanApproval = false;
    kernelIntent.timeout = std::chrono::seconds(30);
    
    return EXECUTION_PIPELINE.Execute(kernelIntent);
}

} // namespace Kernel
} // namespace RawrXD
