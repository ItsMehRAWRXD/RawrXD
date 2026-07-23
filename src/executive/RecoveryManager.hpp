// ============================================================
// RecoveryManager.hpp - Failure Recovery and Retry Logic
// Handles failures gracefully and attempts recovery
// ============================================================

#pragma once
#include <string>
#include <vector>
#include <functional>
#include <optional>
#include <unordered_map>
#include <mutex>
#include <atomic>

namespace RawrXD::Executive {

class ExecutiveDirector;

// ============================================================
// Failure Types
// ============================================================
enum class FailureType {
    AGENT_ERROR,
    TIMEOUT,
    RESOURCE_EXHAUSTED,
    DEPENDENCY_FAILED,
    PLAN_INVALID,
    UNEXPECTED_RESULT,
    SYSTEM_ERROR
};

// ============================================================
// Failure Record
// ============================================================
struct FailureRecord {
    uint64_t failureId;
    FailureType type;
    std::string description;
    uint64_t missionId = 0;
    uint64_t agentId = 0;
    uint64_t planId = 0;
    uint64_t stepId = 0;
    
    uint64_t timestampMs = 0;
    std::vector<std::string> context;
    std::string stackTrace;
    
    int retryCount = 0;
    std::vector<std::string> recoveryAttempts;
    bool isRecovered = false;
    std::string recoveryMethod;
};

// ============================================================
// Recovery Strategy
// ============================================================
enum class RecoveryStrategy {
    RETRY_IMMEDIATE,
    RETRY_WITH_BACKOFF,
    RETRY_ALTERNATIVE,
    REPLAN,
    DEGRADE,
    ESCALATE,
    ABANDON,
    COMPENSATE
};

// ============================================================
// Recovery Action
// ============================================================
struct RecoveryAction {
    RecoveryStrategy strategy;
    std::string description;
    std::function<bool()> execute;
    float successProbability = 0.5f;
    double estimatedTimeMs = 0.0;
};

// ============================================================
// Recovery Manager
// ============================================================
class RecoveryManager {
public:
    RecoveryManager() = default;
    ~RecoveryManager() = default;

    bool initialize(ExecutiveDirector* director);
    void shutdown();
    
    uint64_t recordFailure(const FailureRecord& failure);
    FailureRecord getFailure(uint64_t failureId);
    std::vector<FailureRecord> getRecentFailures(size_t count = 10);
    std::vector<FailureRecord> getFailuresForMission(uint64_t missionId);
    
    std::vector<RecoveryAction> generateRecoveryOptions(uint64_t failureId);
    RecoveryAction selectBestRecovery(const std::vector<RecoveryAction>& options);
    bool attemptRecovery(uint64_t failureId, const RecoveryAction& action);
    
    void enableAutomaticRecovery(bool enable);
    bool isAutomaticRecoveryEnabled() const;
    void setMaxRetries(int maxRetries);
    void setRetryBackoffMs(int initialBackoffMs);
    
    std::vector<uint64_t> identifyRecurringFailures();
    std::vector<uint64_t> identifySystemicIssues();
    std::string rootCauseAnalysis(uint64_t failureId);
    std::vector<uint64_t> predictPotentialFailures();
    void registerPreventionMeasure(const std::string& failurePattern, const std::string& preventionAction);
    
    struct Stats {
        size_t totalFailures = 0;
        size_t recoveredFailures = 0;
        size_t unrecoveredFailures = 0;
        size_t automaticRecoveries = 0;
        float recoverySuccessRate = 0.0f;
        double averageRecoveryTimeMs = 0.0;
    };
    Stats getStats() const;

private:
    ExecutiveDirector* director_ = nullptr;
    std::unordered_map<uint64_t, FailureRecord> failures_;
    std::atomic<uint64_t> nextFailureId_{1};
    
    bool automaticRecovery_ = true;
    int maxRetries_ = 3;
    int retryBackoffMs_ = 1000;
    
    std::atomic<size_t> totalFailures_{0};
    std::atomic<size_t> recoveredFailures_{0};
    std::atomic<size_t> automaticRecoveries_{0};
    double totalRecoveryTimeMs_ = 0.0;
    
    mutable std::mutex mutex_;
    
    uint64_t currentTimeMs();
};

} // namespace RawrXD::Executive
