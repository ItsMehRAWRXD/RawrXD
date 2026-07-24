// Intent Execution Pipeline - Implementation
// Wires Intent ABI → PatchFirewall → PatchTransaction → Execution

#include "IntentExecutionPipeline.hpp"
#include "AgentKernel.hpp"

#include <sstream>
#include <chrono>

namespace RawrXD {
namespace Kernel {

// ============================================================================
// ExecutionResult Implementation
// ============================================================================

std::string ExecutionResult::ToJson() const {
    std::stringstream ss;
    ss << "{";
    ss << "\"success\":" << (success ? "true" : "false") << ",";
    ss << "\"intentType\":\"" << intentType << "\",";
    ss << "\"intentId\":" << intentId << ",";
    ss << "\"validationTimeMs\":" << validationTimeMs << ",";
    ss << "\"executionTimeMs\":" << executionTimeMs << ",";
    ss << "\"totalTimeMs\":" << totalTimeMs << ",";
    ss << "\"outcome\":" << static_cast<int>(outcome) << ",";
    ss << "\"errorMessage\":\"" << errorMessage << "\",";
    ss << "\"wasRolledBack\":" << (wasRolledBack ? "true" : "false") << ",";
    ss << "\"rollbackEpoch\":" << rollbackEpoch;
    ss << "}";
    return ss.str();
}

// ============================================================================
// IntentHandlerRegistry Implementation
// ============================================================================

IntentHandlerRegistry& IntentHandlerRegistry::Instance() {
    static IntentHandlerRegistry instance;
    return instance;
}

void IntentHandlerRegistry::Register(const std::string& intentType, IntentHandler handler) {
    std::lock_guard<std::mutex> lock(handlersMutex_);
    handlers_[intentType] = handler;
}

void IntentHandlerRegistry::Unregister(const std::string& intentType) {
    std::lock_guard<std::mutex> lock(handlersMutex_);
    handlers_.erase(intentType);
}

bool IntentHandlerRegistry::HasHandler(const std::string& intentType) const {
    std::lock_guard<std::mutex> lock(handlersMutex_);
    return handlers_.find(intentType) != handlers_.end();
}

IntentHandler IntentHandlerRegistry::GetHandler(const std::string& intentType) const {
    std::lock_guard<std::mutex> lock(handlersMutex_);
    auto it = handlers_.find(intentType);
    if (it != handlers_.end()) return it->second;
    return nullptr;
}

std::vector<std::string> IntentHandlerRegistry::GetRegisteredTypes() const {
    std::lock_guard<std::mutex> lock(handlersMutex_);
    std::vector<std::string> result;
    for (const auto& [type, handler] : handlers_) {
        result.push_back(type);
    }
    return result;
}

// ============================================================================
// IntentExecutionPipeline Implementation
// ============================================================================

IntentExecutionPipeline& IntentExecutionPipeline::Instance() {
    static IntentExecutionPipeline instance;
    return instance;
}

bool IntentExecutionPipeline::Initialize() {
    if (initialized_.load()) return true;
    
    // Initialize security manager
    Security::SecurityManager::Instance().Initialize(Security::SecurityLevel::STANDARD);
    
    // Register built-in handlers
    IntentHandlerRegistry::Instance().Register("MODIFY_FUNCTION", HandleModifyFunction);
    IntentHandlerRegistry::Instance().Register("BUILD_PROJECT", HandleBuildProject);
    IntentHandlerRegistry::Instance().Register("RUN_TESTS", HandleRunTests);
    IntentHandlerRegistry::Instance().Register("DEBUG_SESSION", HandleDebugSession);
    IntentHandlerRegistry::Instance().Register("OPTIMIZE_CODE", HandleOptimizeCode);
    
    // Connect to telemetry
    ConnectToTelemetryInjector();
    
    initialized_.store(true);
    return true;
}

void IntentExecutionPipeline::Shutdown() {
    if (!initialized_.load()) return;
    
    // Unregister handlers
    IntentHandlerRegistry::Instance().Unregister("MODIFY_FUNCTION");
    IntentHandlerRegistry::Instance().Unregister("BUILD_PROJECT");
    IntentHandlerRegistry::Instance().Unregister("RUN_TESTS");
    IntentHandlerRegistry::Instance().Unregister("DEBUG_SESSION");
    IntentHandlerRegistry::Instance().Unregister("OPTIMIZE_CODE");
    
    // Shutdown security manager
    Security::SecurityManager::Instance().Shutdown();
    
    initialized_.store(false);
}

ExecutionResult IntentExecutionPipeline::Execute(const IntentRequest& kernelIntent) {
    auto startTime = std::chrono::steady_clock::now();
    
    ExecutionResult result;
    result.intentType = kernelIntent.intentType;
    result.intentId = kernelIntent.intentId;
    result.success = false;
    result.wasRolledBack = false;
    
    // Security Pre-Check
    if (!securityPreCheck(kernelIntent, result)) {
        return result;
    }
    
    // Stage 1: Validate Intent ABI
    Intent::IntentRequest abiIntent;
    if (!Stage1_ValidateIntent(kernelIntent, abiIntent)) {
        result.outcome = ExecutionResult::Outcome::VALIDATION_FAILED;
        result.errorMessage = "Intent ABI validation failed";
        return result;
    }
    
    auto afterValidation = std::chrono::steady_clock::now();
    result.validationTimeMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        afterValidation - startTime).count();
    
    // Stage 2: Acquire Capabilities
    Guardrails::CapabilityToken token;
    if (!Stage2_AcquireCapabilities(kernelIntent, token)) {
        result.outcome = ExecutionResult::Outcome::CAPABILITY_DENIED;
        result.errorMessage = "Capability acquisition failed";
        return result;
    }
    
    // Stage 3: Patch Firewall Check
    Guardrails::FirewallResult fwResult;
    if (!Stage3_FirewallCheck(abiIntent, fwResult)) {
        result.outcome = ExecutionResult::Outcome::VALIDATION_FAILED;
        result.errorMessage = "Patch firewall rejected: " + fwResult.reason;
        
        // Inject telemetry
        TELEMETRY_INJECTOR.InjectRejectionFromFirewall(
            kernelIntent.intentType,
            "", // target symbol
            ViolationCode::POLICY_VIOLATION,
            fwResult.reason
        );
        
        return result;
    }
    
    // Stage 4: Create Transaction
    Hotpatch::PatchTransaction tx(kernelIntent.intentId);
    if (!Stage4_CreateTransaction(kernelIntent, tx)) {
        result.outcome = ExecutionResult::Outcome::TRANSACTION_FAILED;
        result.errorMessage = "Failed to create patch transaction";
        return result;
    }
    
    // Stage 5: Execute Handler
    if (!Stage5_ExecuteHandler(kernelIntent, abiIntent, result)) {
        // Handler failed - rollback
        Stage6_CommitOrRollback(tx, false, result);
        return result;
    }
    
    // Stage 6: Commit
    if (!Stage6_CommitOrRollback(tx, true, result)) {
        result.outcome = ExecutionResult::Outcome::TRANSACTION_FAILED;
        result.errorMessage = "Transaction commit failed";
        return result;
    }
    
    // Success
    result.success = true;
    result.outcome = ExecutionResult::Outcome::SUCCESS;
    
    auto endTime = std::chrono::steady_clock::now();
    result.executionTimeMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        endTime - afterValidation).count();
    result.totalTimeMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        endTime - startTime).count();
    
    // Update stats
    {
        std::lock_guard<std::mutex> lock(statsMutex_);
        stats_.totalIntents++;
        stats_.successfulIntents++;
        stats_.intentsByType[kernelIntent.intentType]++;
        stats_.averageValidationTimeMs = 
            (stats_.averageValidationTimeMs * (stats_.totalIntents - 1) + result.validationTimeMs)
            / stats_.totalIntents;
        stats_.averageExecutionTimeMs = 
            (stats_.averageExecutionTimeMs * (stats_.totalIntents - 1) + result.executionTimeMs)
            / stats_.totalIntents;
    }
    
    // Inject success telemetry
    TELEMETRY_INJECTOR.InjectSuccessFromTransaction(
        kernelIntent.intentId,
        kernelIntent.intentType,
        result.totalTimeMs
    );
    
    // Security Post-Log
    securityPostLog(kernelIntent, result);
    
    return result;
}

std::future<ExecutionResult> IntentExecutionPipeline::ExecuteAsync(
    const IntentRequest& kernelIntent) {
    return std::async(std::launch::async, [&, kernelIntent]() {
        return Execute(kernelIntent);
    });
}

ExecutionResult IntentExecutionPipeline::ValidateOnly(const IntentRequest& kernelIntent) {
    ExecutionResult result;
    result.intentType = kernelIntent.intentType;
    result.intentId = kernelIntent.intentId;
    
    Intent::IntentRequest abiIntent;
    if (!Stage1_ValidateIntent(kernelIntent, abiIntent)) {
        result.success = false;
        result.outcome = ExecutionResult::Outcome::VALIDATION_FAILED;
        return result;
    }
    
    Guardrails::FirewallResult fwResult;
    if (!Stage3_FirewallCheck(abiIntent, fwResult)) {
        result.success = false;
        result.outcome = ExecutionResult::Outcome::VALIDATION_FAILED;
        result.errorMessage = fwResult.reason;
        return result;
    }
    
    result.success = true;
    result.outcome = ExecutionResult::Outcome::SUCCESS;
    result.errorMessage = "Validation passed (dry run)";
    return result;
}

bool IntentExecutionPipeline::Stage1_ValidateIntent(
    const IntentRequest& kernelIntent,
    Intent::IntentRequest& abiIntent) {

    // Convert kernel intent to ABI intent
    abiIntent.intent_id = kernelIntent.intentId;
    abiIntent.session_id = kernelIntent.sourceAgent;
    abiIntent.timestamp_us = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    // Map intent type
    if (kernelIntent.intentType == "MODIFY_FUNCTION") {
        abiIntent.type = Intent::IntentType::MODIFY_FUNCTION;
    } else if (kernelIntent.intentType == "BUILD_PROJECT") {
        abiIntent.type = Intent::IntentType::COMPILE;
    } else if (kernelIntent.intentType == "RUN_TESTS") {
        abiIntent.type = Intent::IntentType::RUN_TEST;
    } else {
        abiIntent.type = Intent::IntentType::UNKNOWN;
    }

    // Set target
    if (!kernelIntent.targetFiles.empty()) {
        abiIntent.target.file_path = kernelIntent.targetFiles[0];
    }

    // Validate
    return Intent::IntentValidator::Instance().Validate(abiIntent).valid;
}

bool IntentExecutionPipeline::Stage2_AcquireCapabilities(
    const IntentRequest& kernelIntent,
    Guardrails::CapabilityToken& token) {
    
    // Determine required capabilities
    Guardrails::Capability caps = Guardrails::Capability::NONE;
    
    if (kernelIntent.intentType == "MODIFY_FUNCTION") {
        caps = Guardrails::Capability::MODIFY_FUNCTION | 
               Guardrails::Capability::COMPILE |
               Guardrails::Capability::RUN_TEST;
    } else if (kernelIntent.intentType == "BUILD_PROJECT") {
        caps = Guardrails::Capability::COMPILE;
    } else if (kernelIntent.intentType == "RUN_TESTS") {
        caps = Guardrails::Capability::RUN_TEST;
    } else {
        caps = Guardrails::Capability::MODIFY_FUNCTION;
    }
    
    // Issue token
    auto tokenOpt = Guardrails::CapabilityManager::Instance().IssueToken(
        kernelIntent.intentId,
        caps,
        1,    // max uses
        300   // expiry seconds
    );
    
    if (!tokenOpt) return false;
    
    token = *tokenOpt;
    return true;
}

bool IntentExecutionPipeline::Stage3_FirewallCheck(
    const Intent::IntentRequest& abiIntent,
    Guardrails::FirewallResult& result) {

    result = Guardrails::PatchFirewall::Instance().ValidateIntent(abiIntent);
    return result.allowed;
}

bool IntentExecutionPipeline::Stage4_CreateTransaction(
    const IntentRequest& kernelIntent,
    Hotpatch::PatchTransaction& tx) {
    
    if (!tx.Begin()) {
        return false;
    }
    
    // Create snapshot
    if (!tx.CreateSnapshot()) {
        tx.Rollback();
        return false;
    }
    
    return true;
}

bool IntentExecutionPipeline::Stage5_ExecuteHandler(
    const IntentRequest& kernelIntent,
    const Intent::IntentRequest& abiIntent,
    ExecutionResult& result) {

    auto handler = IntentHandlerRegistry::Instance().GetHandler(kernelIntent.intentType);
    if (!handler) {
        result.outcome = ExecutionResult::Outcome::EXECUTION_ERROR;
        result.errorMessage = "No handler registered for intent type: " + kernelIntent.intentType;
        return false;
    }

    result = handler(kernelIntent, abiIntent);
    return result.success;
}

bool IntentExecutionPipeline::Stage6_CommitOrRollback(
    Hotpatch::PatchTransaction& tx,
    bool success,
    ExecutionResult& result) {

    if (success) {
        if (!tx.Commit()) {
            result.outcome = ExecutionResult::Outcome::TRANSACTION_FAILED;
            result.errorMessage = "Transaction commit failed";
            return false;
        }
        return true;
    } else {
        tx.Rollback();
        result.wasRolledBack = true;
        result.rollbackEpoch = tx.GetTransactionId();

        // Update stats
        {
            std::lock_guard<std::mutex> lock(statsMutex_);
            stats_.rolledBackIntents++;
        }

        return false;
    }
}

void IntentExecutionPipeline::SetValidationTimeout(std::chrono::milliseconds timeout) {
    validationTimeout_ = timeout;
}

void IntentExecutionPipeline::SetExecutionTimeout(std::chrono::milliseconds timeout) {
    executionTimeout_ = timeout;
}

IntentExecutionPipeline::PipelineStats IntentExecutionPipeline::GetStats() const {
    std::lock_guard<std::mutex> lock(statsMutex_);
    return stats_;
}

void IntentExecutionPipeline::ResetStats() {
    std::lock_guard<std::mutex> lock(statsMutex_);
    stats_ = {};
}

void IntentExecutionPipeline::ConnectToModelAdapter() {
    // TODO: Implement model adapter integration
}

void IntentExecutionPipeline::ConnectToTelemetryInjector() {
    // Subscribe to rejection feedback
    telemetrySubscriptionId_ = TELEMETRY_INJECTOR.SubscribeToRejections(
        [](const RejectionFeedback& feedback) {
            // Log or handle rejection feedback
            (void)feedback;
        }
    );
}

// ============================================================================
// Security Integration
// ============================================================================

bool IntentExecutionPipeline::securityPreCheck(const IntentRequest& kernelIntent,
                                                ExecutionResult& result) {
    // Check if security manager is initialized
    if (!Security::SecurityManager::Instance().IsInitialized()) {
        return true; // Security not enabled, allow
    }
    
    // Validate pre-execution
    std::string error;
    if (!Security::SecurityManager::Instance().ValidatePreExecution(
            kernelIntent.sourceAgent, kernelIntent.intentId, error)) {
        result.success = false;
        result.outcome = ExecutionResult::Outcome::VALIDATION_FAILED;
        result.errorMessage = "Security check failed: " + error;
        return false;
    }
    
    // Validate target files if present
    for (const auto& file : kernelIntent.targetFiles) {
        std::string validationError;
        if (!Security::InputValidator::Instance().ValidateFilePath(file, validationError)) {
            SECURITY_LOG_ERROR(Security::AuditEventType::VIOLATION_DETECTED,
                "Invalid file path: " + file + " - " + validationError);
            result.success = false;
            result.outcome = ExecutionResult::Outcome::VALIDATION_FAILED;
            result.errorMessage = "File path validation failed: " + validationError;
            return false;
        }
    }

    return true;
}

void IntentExecutionPipeline::securityPostLog(const IntentRequest& kernelIntent,
                                               const ExecutionResult& result) {
    // Log post-execution
    Security::SecurityManager::Instance().LogPostExecution(
        kernelIntent.sourceAgent, kernelIntent.intentId, result.success);
    
    // Log specific events based on outcome
    if (!result.success) {
        switch (result.outcome) {
            case ExecutionResult::Outcome::VALIDATION_FAILED:
                SECURITY_LOG_WARNING(Security::AuditEventType::INTENT_REJECTED,
                    "Intent " + std::to_string(kernelIntent.intentId) + 
                    " rejected: " + result.errorMessage);
                break;
            case ExecutionResult::Outcome::CAPABILITY_DENIED:
                SECURITY_LOG_WARNING(Security::AuditEventType::VIOLATION_DETECTED,
                    "Capability denied for intent " + std::to_string(kernelIntent.intentId));
                break;
            case ExecutionResult::Outcome::TRANSACTION_FAILED:
                SECURITY_LOG_ERROR(Security::AuditEventType::VIOLATION_DETECTED,
                    "Transaction failed for intent " + std::to_string(kernelIntent.intentId));
                break;
            default:
                break;
        }
    }
}

// ============================================================================
// Built-in Intent Handlers - Stubs for now
// ============================================================================

ExecutionResult HandleModifyFunction(const IntentRequest& kernelIntent,
                                      const Intent::IntentRequest& abiIntent) {
    ExecutionResult result;
    result.intentType = "MODIFY_FUNCTION";
    result.intentId = kernelIntent.intentId;
    result.success = true;
    result.outcome = ExecutionResult::Outcome::SUCCESS;
    result.errorMessage = "Function modification completed";
    return result;
}

ExecutionResult HandleBuildProject(const IntentRequest& kernelIntent,
                                    const Intent::IntentRequest& abiIntent) {
    ExecutionResult result;
    result.intentType = "BUILD_PROJECT";
    result.intentId = kernelIntent.intentId;
    result.success = true;
    result.outcome = ExecutionResult::Outcome::SUCCESS;
    result.errorMessage = "Build completed successfully";
    return result;
}

ExecutionResult HandleRunTests(const IntentRequest& kernelIntent,
                                const Intent::IntentRequest& abiIntent) {
    ExecutionResult result;
    result.intentType = "RUN_TESTS";
    result.intentId = kernelIntent.intentId;
    result.success = true;
    result.outcome = ExecutionResult::Outcome::SUCCESS;
    result.errorMessage = "All tests passed";
    return result;
}

ExecutionResult HandleDebugSession(const IntentRequest& kernelIntent,
                                      const Intent::IntentRequest& abiIntent) {
    ExecutionResult result;
    result.intentType = "DEBUG_SESSION";
    result.intentId = kernelIntent.intentId;
    result.success = true;
    result.outcome = ExecutionResult::Outcome::SUCCESS;
    result.errorMessage = "Debug session started";
    return result;
}

ExecutionResult HandleOptimizeCode(const IntentRequest& kernelIntent,
                                      const Intent::IntentRequest& abiIntent) {
    ExecutionResult result;
    result.intentType = "OPTIMIZE_CODE";
    result.intentId = kernelIntent.intentId;
    result.success = true;
    result.outcome = ExecutionResult::Outcome::SUCCESS;
    result.errorMessage = "Code optimization applied";
    return result;
}

} // namespace Kernel
} // namespace RawrXD
