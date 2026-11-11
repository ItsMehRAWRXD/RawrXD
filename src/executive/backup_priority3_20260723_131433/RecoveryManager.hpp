// ============================================================================
// RecoveryManager.hpp - Failure Recovery and Retry Logic
// Handles failures gracefully and attempts recovery
// ============================================================================

#pragma once

#include <memory>
#include <vector>
#include <string>
#include <functional>
#include <optional>
#include <chrono>

namespace RawrXD {
namespace Executive {

// Forward declarations
class ExecutiveDirector;

// ============================================================================
// Failure Types
// ============================================================================
enum class FailureType {
    AGENT_ERROR,      // Agent crashed or returned error
    TIMEOUT,          // Operation exceeded time limit
    RESOURCE_EXHAUSTED,  // Out of memory, CPU, etc.
    DEPENDENCY_FAILED,   // Required service/agent unavailable
    PLAN_INVALID,     // Plan cannot be executed
    UNEXPECTED_RESULT,  // Output didn't match expectations
    SYSTEM_ERROR      // Internal system failure
};

// ============================================================================
// Failure Record
// ============================================================================
struct FailureRecord {
    std::string failureId;
    FailureType type;
    std::string description;
    std::string missionId;
    std::string agentId;
    std::string planId;
    std::string stepId;
    
    // Context
    std::chrono::steady_clock::time_point timestamp;
    std::vector<std::string> context;
    std::string stackTrace;
    
    // Recovery
    int retryCount = 0;
    std::vector<std::string> recoveryAttempts;
    bool isRecovered = false;
    std::string recoveryMethod;
};

// ============================================================================
// Recovery Strategy
// ============================================================================
enum class RecoveryStrategy {
    RETRY_IMMEDIATE,      // Try again right away
    RETRY_WITH_BACKOFF,   // Exponential backoff
    RETRY_ALTERNATIVE,    // Try different agent/tool
    REPLAN,               // Create new plan
    DEGRADE,              // Reduce scope/quality
    ESCALATE,             // Hand to human/higher system
    ABANDON,              // Give up on this mission
    COMPENSATE            // Do something else to mitigate
};

// ============================================================================
// Recovery Action
// ============================================================================
struct RecoveryAction {
    RecoveryStrategy strategy;
    std::string description;
    std::function<bool()> execute;
    float successProbability = 0.5f;
    double estimatedTimeMs = 0.0;
};

// ============================================================================
// Recovery Manager - Failure Handling System
// ============================================================================
class RecoveryManager {
public:
    RecoveryManager();
    ~RecoveryManager();

    bool Initialize(ExecutiveDirector* director);
    void Shutdown();
    
    // Failure handling
    std::string RecordFailure(const FailureRecord& failure);
    FailureRecord GetFailure(const std::string& failureId);
    std::vector<FailureRecord> GetRecentFailures(size_t count = 10);
    std::vector<FailureRecord> GetFailuresForMission(const std::string& missionId);
    
    // Recovery strategies
    std::vector<RecoveryAction> GenerateRecoveryOptions(const std::string& failureId);
    RecoveryAction SelectBestRecovery(const std::vector<RecoveryAction>& options);
    bool AttemptRecovery(const std::string& failureId, const RecoveryAction& action);
    
    // Automatic recovery
    void EnableAutomaticRecovery(bool enable);
    bool IsAutomaticRecoveryEnabled() const;
    void SetMaxRetries(int maxRetries);
    void SetRetryBackoffMs(int initialBackoffMs);
    
    // Failure analysis
    std::vector<std::string> IdentifyRecurringFailures();
    std::vector<std::string> IdentifySystemicIssues();
    std::string RootCauseAnalysis(const std::string& failureId);
    
    // Prevention
    std::vector<std::string> PredictPotentialFailures();
    void RegisterPreventionMeasure(const std::string& failurePattern, const std::string& preventionAction);
    
    // Statistics
    struct Stats {
        size_t totalFailures = 0;
        size_t recoveredFailures = 0;
        size_t unrecoveredFailures = 0;
        size_t automaticRecoveries = 0;
        float recoverySuccessRate = 0.0f;
        double averageRecoveryTimeMs = 0.0;
    };
    Stats GetStats() const;

private:
    struct Impl;
    std::unique_ptr<Impl> pImpl_;
};

} // namespace Executive
} // namespace RawrXD
