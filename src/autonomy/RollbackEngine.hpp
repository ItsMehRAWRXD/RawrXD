/**
 * RollbackEngine.hpp
 *
 * Phase C.4 Batch 3/5: Autonomous Rollback Engine
 *
 * Executes rollback plans to restore system stability.
 * Integrates with MutationJournal, CheckpointManager, and StabilityEnvelope.
 */

#pragma once

#include "MutationJournal.hpp"
#include "StabilityEnvelope.hpp"
#include "OscillationDampener.hpp"
#include "../core/SovereignState.hpp"

#include <cstring>
#include <vector>
#include <map>
#include <memory>
#include <functional>

namespace Autonomy {

/**
 * Rollback step types
 */
enum class RollbackStepType {
    REVERT_MUTATION,
    RESTORE_GRAPH_NODE,
    RESET_SCHEDULER_WEIGHTS,
    RESTORE_ROLE_ASSIGNMENTS,
    RESTORE_INTENT_STRENGTHS,
    RESTORE_CHECKPOINT,
    REINITIALIZE_SUBSYSTEM,
    CLEAR_MUTATION_HISTORY,
    NOTIFY_OBSERVERS
};

std::string RollbackStepTypeToString(RollbackStepType type);

/**
 * Rollback step
 */
struct RollbackStep {
    int stepNumber{0};
    RollbackStepType type{RollbackStepType::REVERT_MUTATION};
    std::string description;
    std::map<std::string, std::string> parameters;
    bool critical{false};  // Step failure aborts rollback
    int timeoutMs{5000};
    
    std::string ToJson() const;
};

/**
 * Rollback plan
 */
struct RollbackPlan {
    std::string planId;
    std::string rollbackReason;
    RollbackSeverity severity{RollbackSeverity::INFO};
    std::vector<RollbackStep> steps;
    uint64_t targetSnapshotId{0};
    std::vector<uint64_t> mutationsToRevert;
    int estimatedDurationMs{0};
    int64_t createdAtMs{0};
    
    std::string ToJson() const;
    void Print() const;
};

/**
 * Rollback result
 */
struct RollbackResult {
    std::string planId;
    bool success{false};
    int stepsCompleted{0};
    int stepsFailed{0};
    int64_t startedAtMs{0};
    int64_t completedAtMs{0};
    int durationMs{0};
    std::string errorMessage;
    double postRollbackStability{0.0};
    double postRollbackConvergence{0.0};
    std::vector<std::string> completedSteps;
    std::vector<std::string> failedSteps;
    
    std::string ToJson() const;
    void Print() const;
};

/**
 * Rollback trigger
 */
enum class RollbackTrigger {
    MANUAL,
    OSCILLATION_SEVERE,
    OSCILLATION_CRITICAL,
    CONVERGENCE_DROP,
    MEMORY_PRESSURE,
    TIMEOUT,
    SAFETY_VIOLATION,
    AUTONOMOUS_DECISION
};

std::string RollbackTriggerToString(RollbackTrigger trigger);

/**
 * Rollback configuration
 */
struct RollbackConfig {
    bool enableAutoRollback{true};
    bool enablePartialRollback{true};
    bool enableFullRollback{true};
    int maxRollbackSteps{100};
    int rollbackTimeoutMs{30000};
    int stabilityCheckDelayMs{1000};
    double minStabilityThreshold{0.5};
    double minConvergenceThreshold{0.6};
    bool requireCheckpointValidation{true};
    bool notifyOnRollback{true};
    int maxRetries{3};
    
    std::string ToJson() const;
};

/**
 * Rollback observer interface
 */
class IRollbackObserver {
public:
    virtual ~IRollbackObserver() = default;
    virtual void OnRollbackStarted(const RollbackPlan& plan) = 0;
    virtual void OnRollbackStepCompleted(const RollbackStep& step, int stepNumber) = 0;
    virtual void OnRollbackStepFailed(const RollbackStep& step, int stepNumber, const std::string& error) = 0;
    virtual void OnRollbackCompleted(const RollbackResult& result) = 0;
};

/**
 * Rollback Engine
 *
 * Executes rollback plans to restore system stability.
 */
class RollbackEngine {
public:
    RollbackEngine();
    ~RollbackEngine();

    // Disable copy
    RollbackEngine(const RollbackEngine&) = delete;
    RollbackEngine& operator=(const RollbackEngine&) = delete;

    /**
     * Initialize rollback engine
     */
    bool Initialize(const RollbackConfig& config,
                   MutationJournal* journal,
                   StabilityEnvelope* envelope);

    /**
     * Register observer
     */
    void RegisterObserver(std::shared_ptr<IRollbackObserver> observer);

    /**
     * Unregister observer
     */
    void UnregisterObserver(std::shared_ptr<IRollbackObserver> observer);

    /**
     * Generate rollback plan
     */
    RollbackPlan GeneratePlan(RollbackTrigger trigger,
                             const std::string& reason,
                             RollbackSeverity severity);

    /**
     * Generate plan for specific mutations
     */
    RollbackPlan GeneratePlanForMutations(const std::vector<uint64_t>& mutationIds,
                                         const std::string& reason);

    /**
     * Execute rollback plan
     */
    RollbackResult Execute(const RollbackPlan& plan);

    /**
     * Execute rollback by trigger
     */
    RollbackResult Execute(RollbackTrigger trigger, const std::string& reason);

    /**
     * Quick rollback to last stable state
     */
    RollbackResult QuickRollback();

    /**
     * Validate post-rollback stability
     */
    bool ValidateStability(int timeoutMs = 5000);

    /**
     * Get rollback history
     */
    std::vector<RollbackResult> GetRollbackHistory() const;

    /**
     * Get last rollback result
     */
    std::optional<RollbackResult> GetLastRollback() const;

    /**
     * Check if rollback is in progress
     */
    bool IsRollbackInProgress() const;

    /**
     * Cancel current rollback
     */
    bool CancelRollback();

    /**
     * Get rollback statistics
     */
    struct RollbackStats {
        int totalRollbacks{0};
        int successfulRollbacks{0};
        int failedRollbacks{0};
        int partialRollbacks{0};
        double successRate{0.0};
        int64_t totalRollbackTimeMs{0};
        double avgRollbackTimeMs{0.0};
    };
    RollbackStats GetStats() const;

    /**
     * Print status
     */
    void PrintStatus() const;

private:
    RollbackConfig config_;
    MutationJournal* journal_{nullptr};
    StabilityEnvelope* envelope_{nullptr};
    bool initialized_{false};
    
    // Observers
    std::vector<std::weak_ptr<IRollbackObserver>> observers_;
    mutable std::mutex observersMutex_;
    
    // Rollback state
    std::atomic<bool> rollbackInProgress_{false};
    std::atomic<bool> cancelRequested_{false};
    
    // History
    std::vector<RollbackResult> rollbackHistory_;
    mutable std::mutex historyMutex_;
    
    // Plan counter
    std::atomic<int> planCounter_{0};
    
    // Step executors
    bool ExecuteStep(const RollbackStep& step, RollbackResult& result);
    bool RevertMutation(const RollbackStep& step);
    bool RestoreGraphNode(const RollbackStep& step);
    bool ResetSchedulerWeights(const RollbackStep& step);
    bool RestoreRoleAssignments(const RollbackStep& step);
    bool RestoreIntentStrengths(const RollbackStep& step);
    bool RestoreCheckpoint(const RollbackStep& step);
    bool ReinitializeSubsystem(const RollbackStep& step);
    bool ClearMutationHistory(const RollbackStep& step);
    bool NotifyObservers(const RollbackStep& step);
    
    // Plan generators
    RollbackPlan GeneratePartialPlan(const std::vector<uint64_t>& mutations);
    RollbackPlan GenerateFullPlan(uint64_t snapshotId);
    
    // Helpers
    void NotifyRollbackStarted(const RollbackPlan& plan);
    void NotifyStepCompleted(const RollbackStep& step, int stepNumber);
    void NotifyStepFailed(const RollbackStep& step, int stepNumber, const std::string& error);
    void NotifyRollbackCompleted(const RollbackResult& result);
    
    std::string GeneratePlanId();
    int64_t GetCurrentTimeMs() const;
};

/**
 * Integrated Rollback Manager
 *
 * Combines rollback engine with autonomous triggers.
 */
class RollbackManager {
public:
    RollbackManager();
    ~RollbackManager();

    // Disable copy
    RollbackManager(const RollbackManager&) = delete;
    RollbackManager& operator=(const RollbackManager&) = delete;

    /**
     * Initialize manager
     */
    bool Initialize(const RollbackConfig& config,
                   MutationJournal* journal,
                   StabilityEnvelope* envelope,
                   OscillationManager* oscillationManager);

    /**
     * Update - check triggers and execute rollbacks if needed
     */
    void Update();

    /**
     * Manual rollback
     */
    RollbackResult ManualRollback(const std::string& reason);

    /**
     * Triggered rollback
     */
    RollbackResult TriggeredRollback(RollbackTrigger trigger, const std::string& reason);

    /**
     * Get rollback engine
     */
    RollbackEngine& GetEngine() { return engine_; }

    /**
     * Check if autonomous rollback is enabled
     */
    bool IsAutoRollbackEnabled() const { return config_.enableAutoRollback; }

    /**
     * Enable/disable auto rollback
     */
    void SetAutoRollback(bool enabled) { config_.enableAutoRollback = enabled; }

    /**
     * Print status
     */
    void PrintStatus() const;

private:
    RollbackConfig config_;
    RollbackEngine engine_;
    MutationJournal* journal_{nullptr};
    StabilityEnvelope* envelope_{nullptr};
    OscillationManager* oscillationManager_{nullptr};
    bool initialized_{false};
    
    int64_t lastCheckMs_{0};
    int checkIntervalMs_{100};
    
    // Trigger checks
    bool CheckOscillationTrigger();
    bool CheckConvergenceTrigger();
    bool CheckResourceTrigger();
    bool CheckSafetyTrigger();
    
    int64_t GetCurrentTimeMs() const;
};

/**
 * CLI for testing rollback engine
 */
class RollbackEngineCLI {
public:
    static void PrintBanner();
    static void PrintUsage();
    static int Run(int argc, char* argv[]);
    
private:
    static void InteractiveMode(RollbackManager& manager);
    static void SimulateFailure(RollbackManager& manager);
};

} // namespace Autonomy
