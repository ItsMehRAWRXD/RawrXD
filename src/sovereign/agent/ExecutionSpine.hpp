// ============================================================================
// ExecutionSpine.hpp - Agent Runtime Loop
// One event loop: intent → plan → tools → validation → commit → report
// ============================================================================

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <atomic>
#include <queue>
#include <chrono>

namespace Sovereign {

// Spine phase
enum class SpinePhase {
    IDLE,
    INTENT_PARSING,
    PLAN_GENERATION,
    TOOL_EXECUTION,
    VALIDATION,
    COMMIT,
    REPORT,
    ERROR,
    RECOVERY
};

// Spine event
struct SpineEvent {
    uint64_t id;
    SpinePhase phase;
    std::string description;
    uint64_t timestamp;
    uint64_t duration;
    bool success;
    std::string error;
};

// Spine configuration
struct SpineConfig {
    uint32_t maxConcurrentPlans = 4;
    uint32_t maxToolCallsPerPlan = 100;
    uint32_t validationRetries = 3;
    uint32_t commitTimeoutMs = 30000;
    bool autoRecover = true;
    bool emitTelemetry = true;
    std::string workspace;
};

// Execution spine - the main agent runtime loop
class ExecutionSpine {
public:
    ExecutionSpine();
    ~ExecutionSpine();

    bool Initialize(const SpineConfig& config);
    void Shutdown();
    bool IsInitialized() const { return initialized_; }

    // Lifecycle
    void Start();
    void Stop();
    bool IsRunning() const { return running_.load(); }

    // Intent submission
    uint64_t SubmitIntent(const std::string& intent);
    bool CancelIntent(uint64_t intentId);
    bool IsIntentComplete(uint64_t intentId) const;

    // Phase management
    SpinePhase GetCurrentPhase() const { return currentPhase_.load(); }
    void TransitionTo(SpinePhase phase);
    std::vector<SpineEvent> GetEventLog() const;

    // Callbacks
    void SetPhaseCallback(std::function<void(SpinePhase)> callback);
    void SetErrorCallback(std::function<void(const std::string&)> callback);
    void SetCompletionCallback(std::function<void(uint64_t, bool)> callback);

    // Statistics
    struct SpineStats {
        uint64_t totalIntents;
        uint64_t completedIntents;
        uint64_t failedIntents;
        uint64_t totalToolCalls;
        uint64_t totalValidations;
        uint64_t totalCommits;
        double avgIntentTimeMs;
        double avgToolTimeMs;
    };
    SpineStats GetStats() const;
    void ResetStats();

    // Recovery
    bool TriggerRecovery(const std::string& reason);
    bool IsInRecovery() const { return inRecovery_.load(); }

private:
    bool initialized_ = false;
    std::atomic<bool> running_{false};
    std::atomic<SpinePhase> currentPhase_{SpinePhase::IDLE};
    std::atomic<bool> inRecovery_{false};
    SpineConfig config_;
    SpineStats stats_;
    
    struct Intent {
        uint64_t id;
        std::string text;
        SpinePhase phase;
        bool complete;
        bool success;
        uint64_t created;
        uint64_t completed;
        std::vector<SpineEvent> events;
    };
    std::unordered_map<uint64_t, Intent> intents_;
    std::queue<uint64_t> intentQueue_;
    uint64_t nextIntentId_ = 1;
    
    std::function<void(SpinePhase)> phaseCallback_;
    std::function<void(const std::string&)> errorCallback_;
    std::function<void(uint64_t, bool)> completionCallback_;
    
    mutable std::mutex mutex_;
    std::thread spineThread_;
    std::condition_variable cv_;
    
    void SpineLoop();
    void ProcessIntent(uint64_t intentId);
    bool ExecutePlan(uint64_t intentId);
    bool ExecuteTools(uint64_t intentId);
    bool ValidateResults(uint64_t intentId);
    bool CommitResults(uint64_t intentId);
    void GenerateReport(uint64_t intentId);
    void HandleError(uint64_t intentId, const std::string& error);
};

} // namespace Sovereign
