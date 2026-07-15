#pragma once
#ifndef RAWRXD_EXECUTION_PLAN_H
#define RAWRXD_EXECUTION_PLAN_H

#include "execution_capability.h"
#include "execution_policy.h"
#include <string>
#include <vector>
#include <memory>
#include <optional>

namespace RawrXD {

// Forward declarations
struct InferenceRequest;

// ============================================================================
// EXECUTION PLAN - Separated from Capability
// 
// Capability = WHO can execute (authorization)
// ExecutionPlan = WHAT will be executed (intent)
// 
// These are orthogonal and must remain separate
// ============================================================================

enum class ExecutionStage {
    LOCAL_GGUF_LOAD,
    LOCAL_GGUF_INFERENCE,
    LOCAL_OLLAMA_CALL,
    REMOTE_CLOUD_CALL,
    FALLBACK_RETRY,
    RESULT_AGGREGATION
};

enum class FallbackPolicy {
    NEVER_FALLBACK,      // Strict local - fail if unavailable
    LOCAL_FIRST,         // Try local, fail if no local available
    ALLOW_CLOUD,         // Local first, cloud if explicitly permitted
    FULLY_DISTRIBUTED    // Automatic routing based on conditions
};

struct StageConfig {
    ExecutionStage stage;
    std::string targetBackend;  // "gguf", "ollama", "openai", "anthropic"
    int timeoutMs = 30000;
    int retryCount = 0;
    std::optional<std::string> fallbackStage;
};

// ============================================================================
// Execution Plan - Immutable description of execution intent
// ============================================================================
class ExecutionPlan {
public:
    class Builder;
    
    // Immutable once built
    const std::vector<StageConfig>& stages() const { return m_stages; }
    FallbackPolicy fallbackPolicy() const { return m_fallbackPolicy; }
    
    // Plan validation
    bool isValid() const;
    std::string validationError() const { return m_validationError; }
    
    // Plan inspection
    bool requiresCloud() const;
    bool requiresLocal() const;
    std::string toString() const;

private:
    ExecutionPlan() = default;
    std::vector<StageConfig> m_stages;
    FallbackPolicy m_fallbackPolicy = FallbackPolicy::LOCAL_FIRST;
    std::string m_validationError;
    
    friend class Builder;
};

// ============================================================================
// Execution Plan Builder
// ============================================================================
class ExecutionPlan::Builder {
public:
    Builder& addStage(const StageConfig& stage);
    Builder& setFallbackPolicy(FallbackPolicy policy);
    Builder& fromModelType(const std::string& modelName);  // Auto-generate plan
    
    std::optional<ExecutionPlan> build();
    
private:
    ExecutionPlan m_plan;
};

// ============================================================================
// Plan Executor - Uses capability to execute plan
// ============================================================================
class PlanExecutor {
public:
    // Execute plan with valid capability
    struct ExecutionResult {
        bool success = false;
        std::string output;
        std::string error;
        std::vector<std::string> executionTrace;
        int64_t totalLatencyMs = 0;
    };
    
    // Constructor requires capability
    explicit PlanExecutor(ExecutionCapability&& cap);
    
    // Can only execute with valid capability
    ExecutionResult execute(const ExecutionPlan& plan);
    
private:
    ExecutionCapability m_capability;
    
    bool executeStage(const StageConfig& stage);
    std::string stageToString(ExecutionStage stage);
};

// ============================================================================
// Plan Compiler - Converts high-level request to execution plan
// ============================================================================
class PlanCompiler {
public:
    static ExecutionPlan compile(const InferenceRequest& request,
                                 RuntimeMode mode);
    
    static ExecutionPlan compileLocalOnly(const std::string& model,
                                           const std::string& prompt);
    
    static ExecutionPlan compileWithCloudFallback(const std::string& model,
                                                 const std::string& prompt);
};

} // namespace RawrXD

#endif // RAWRXD_EXECUTION_PLAN_H
