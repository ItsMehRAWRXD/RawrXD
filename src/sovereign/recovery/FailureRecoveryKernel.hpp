// ============================================================================
// FailureRecoveryKernel.hpp - Autonomous Failure Detection & Recovery
// Detects loops, kill/replan automatically, explains why
// ============================================================================

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <unordered_map>
#include <atomic>

namespace Sovereign {

// Failure types
enum class FailureType {
    BUILD_FAILURE,
    TEST_FAILURE,
    TIMEOUT,
    DEADLOCK,
    INFINITE_LOOP,
    RESOURCE_EXHAUSTION,
    TOOL_ERROR,
    MODEL_ERROR,
    NETWORK_ERROR,
    PERMISSION_DENIED,
    UNKNOWN
};

// Failure record
struct FailureRecord {
    uint64_t id;
    FailureType type;
    std::string source;
    std::string message;
    std::string context;
    uint64_t timestamp;
    uint64_t duration;
    int retryCount;
    bool recovered;
    std::string recoveryAction;
    std::string rootCause;
};

// Recovery plan
struct RecoveryPlan {
    std::string action;
    std::vector<std::string> steps;
    int estimatedDuration;
    bool requiresApproval;
    std::string rollbackStrategy;
};

// Failure recovery kernel
class FailureRecoveryKernel {
public:
    FailureRecoveryKernel();
    ~FailureRecoveryKernel();

    bool Initialize();
    void Shutdown();

    // Failure detection
    FailureType ClassifyFailure(const std::string& error, const std::string& context);
    bool DetectInfiniteLoop(const std::vector<std::string>& recentActions);
    bool DetectDeadlock(const std::vector<std::string>& waitChain);
    bool DetectResourceExhaustion(uint64_t memoryUsage, uint64_t cpuUsage);

    // Recovery
    RecoveryPlan GenerateRecoveryPlan(const FailureRecord& failure);
    bool ExecuteRecovery(const RecoveryPlan& plan);
    bool RollbackRecovery(const RecoveryPlan& plan);

    // Loop detection
    void RecordAction(const std::string& action);
    std::vector<std::string> GetRecentActions(size_t count = 10) const;
    bool IsInLoop() const;
    std::string ExplainLoop() const;

    // Kill and replan
    bool KillTask(uint64_t taskId);
    bool Replan(uint64_t taskId, const std::string& newStrategy);
    bool IsTaskAlive(uint64_t taskId) const;

    // Root cause analysis
    std::string AnalyzeRootCause(const FailureRecord& failure);
    std::vector<std::string> SuggestPreventions(const FailureRecord& failure);

    // Statistics
    struct RecoveryStats {
        uint64_t totalFailures;
        uint64_t recoveredFailures;
        uint64_t unrecoveredFailures;
        uint64_t loopsDetected;
        uint64_t deadlocksDetected;
        double recoveryRate;
    };
    RecoveryStats GetStats() const;
    void ResetStats();

private:
    std::vector<FailureRecord> failures_;
    std::vector<std::string> actionHistory_;
    RecoveryStats stats_;
    mutable std::mutex mutex_;
    std::atomic<uint64_t> nextFailureId_{1};
    
    bool IsRepeating(const std::vector<std::string>& actions, size_t patternLength) const;
    std::string FindPattern(const std::vector<std::string>& actions) const;
};

} // namespace Sovereign
