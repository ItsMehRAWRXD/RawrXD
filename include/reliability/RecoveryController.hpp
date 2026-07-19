// ============================================================================
// RecoveryController.hpp — Recovery Orchestration and Execution
// ============================================================================
// Mission 2.4: Reliability Interface Layer
//
// The RecoveryController is the orchestration layer that:
//   - Subscribes to FailureEvents from HealthMonitor
//   - Selects appropriate RecoveryPolicy based on failure type
//   - Executes recovery strategies with retry/backoff
//   - Verifies recovery success
//   - Maintains recovery history and metrics
//
// This is the bridge between failure detection and state restoration.
// ============================================================================

#pragma once

#include "FailureEvent.hpp"
#include "RecoveryPolicy.hpp"
#include "HealthMonitor.hpp"
#include <string>
#include <map>
#include <queue>
#include <chrono>
#include <functional>
#include <memory>
#include <mutex>
#include <atomic>
#include <thread>
#include <condition_variable>

namespace RawrXD {
namespace Reliability {

// ============================================================================
// Recovery Action
// ============================================================================
// Represents a concrete action to execute for recovery
using RecoveryAction = std::function<bool()>;

struct RecoveryActionContext {
    std::string recoveryId;
    std::string eventId;
    RecoveryStrategyType strategy;
    int attemptNumber;
    std::chrono::steady_clock::time_point deadline;
    nlohmann::json stateSnapshot;
};

// ============================================================================
// Recovery Task
// ============================================================================
struct RecoveryTask {
    std::string taskId;
    FailureEvent triggerEvent;
    RecoveryPolicy policy;
    std::chrono::steady_clock::time_point createdAt;
    std::chrono::steady_clock::time_point startedAt;
    std::chrono::steady_clock::time_point completedAt;
    
    RecoveryStatus status = RecoveryStatus::PENDING;
    RecoveryResult result;
    
    std::vector<RecoveryStrategyType> attemptedStrategies;
    std::string currentStrategy;
    int currentAttempt = 0;
    
    bool isExpired() const;
    bool canRetry() const;
    std::chrono::milliseconds timeRemaining() const;
};

// ============================================================================
// Recovery Controller
// ============================================================================
class RecoveryController {
public:
    static RecoveryController& instance();
    
    // Lifecycle
    bool initialize();
    void shutdown();
    bool isRunning() const { return m_running.load(); }
    
    // Policy management
    void registerPolicy(const RecoveryPolicy& policy);
    void registerDefaultPolicy(const RecoveryPolicy& policy);
    void unregisterPolicy(const std::string& name);
    void clearPolicies();
    
    // Action registration
    void registerAction(RecoveryStrategyType type, RecoveryAction action);
    void unregisterAction(RecoveryStrategyType type);
    bool hasAction(RecoveryStrategyType type) const;
    
    // State management
    void registerStateSnapshotter(std::function<nlohmann::json()> snapshotter);
    void registerStateRestorer(std::function<bool(const nlohmann::json&)> restorer);
    nlohmann::json captureStateSnapshot();
    bool restoreState(const nlohmann::json& snapshot);
    
    // Recovery execution
    std::string startRecovery(const FailureEvent& event);
    std::string startRecovery(const FailureEvent& event, 
                               const RecoveryPolicy& overridePolicy);
    bool cancelRecovery(const std::string& recoveryId);
    RecoveryStatus getRecoveryStatus(const std::string& recoveryId) const;
    RecoveryResult getRecoveryResult(const std::string& recoveryId) const;
    
    // Recovery queries
    std::vector<RecoveryTask> getActiveRecoveries() const;
    std::vector<RecoveryTask> getRecoveryHistory(size_t limit = 100) const;
    bool isRecoveryInProgress() const;
    bool isRecoveryInProgressFor(const std::string& component) const;
    
    // Event subscription
    using RecoveryCallback = std::function<void(const RecoveryResult&)>;
    void onRecoveryComplete(RecoveryCallback callback);
    void onRecoveryFailed(RecoveryCallback callback);
    
    // Configuration
    void setMaxConcurrentRecoveries(int max);
    void setGlobalRecoveryTimeout(std::chrono::milliseconds timeout);
    void setAutoRecoveryEnabled(bool enabled);
    
    // Statistics
    struct Statistics {
        uint64_t totalRecoveriesInitiated = 0;
        uint64_t totalRecoveriesSuccessful = 0;
        uint64_t totalRecoveriesFailed = 0;
        uint64_t totalRecoveriesCancelled = 0;
        
        uint64_t totalStrategiesAttempted = 0;
        uint64_t totalStrategiesSuccessful = 0;
        
        double averageRecoveryTimeMs = 0.0;
        uint64_t maxRecoveryTimeMs = 0;
        
        std::map<RecoveryStrategyType, uint64_t> strategySuccessCounts;
        std::map<RecoveryStrategyType, uint64_t> strategyFailureCounts;
    };
    Statistics getStatistics() const;
    void resetStatistics();
    
    // Integration with HealthMonitor
    void connectToHealthMonitor();
    void disconnectFromHealthMonitor();

private:
    RecoveryController() = default;
    ~RecoveryController() { shutdown(); }
    
    RecoveryController(const RecoveryController&) = delete;
    RecoveryController& operator=(const RecoveryController&) = delete;
    
    void recoveryLoop();
    void processRecoveryTask(RecoveryTask& task);
    bool executeStrategy(RecoveryTask& task, const RecoveryStrategy& strategy);
    bool verifyRecovery(const RecoveryTask& task);
    void completeRecovery(RecoveryTask& task, RecoveryStatus status);
    void failRecovery(RecoveryTask& task, const std::string& reason);
    
    RecoveryPolicy selectPolicy(const FailureEvent& event) const;
    RecoveryAction getAction(RecoveryStrategyType type) const;
    
    void notifyComplete(const RecoveryResult& result);
    void notifyFailed(const RecoveryResult& result);
    void updateStatistics(const RecoveryTask& task);
    
    std::atomic<bool> m_running{false};
    std::atomic<bool> m_autoRecoveryEnabled{true};
    std::atomic<int> m_maxConcurrent{3};
    std::chrono::milliseconds m_globalTimeout{60000};
    
    std::thread m_recoveryThread;
    std::condition_variable m_taskCondition;
    mutable std::mutex m_queueMutex;
    std::queue<RecoveryTask> m_pendingTasks;
    std::map<std::string, RecoveryTask> m_activeTasks;
    
    mutable std::mutex m_historyMutex;
    std::vector<RecoveryTask> m_completedTasks;
    static constexpr size_t MAX_HISTORY = 1000;
    
    mutable std::mutex m_policiesMutex;
    std::vector<RecoveryPolicy> m_policies;
    RecoveryPolicy m_defaultPolicy;
    
    mutable std::mutex m_actionsMutex;
    std::map<RecoveryStrategyType, RecoveryAction> m_actions;
    
    mutable std::mutex m_stateMutex;
    std::function<nlohmann::json()> m_snapshotter;
    std::function<bool(const nlohmann::json&)> m_restorer;
    
    mutable std::mutex m_callbacksMutex;
    std::vector<RecoveryCallback> m_completeCallbacks;
    std::vector<RecoveryCallback> m_failedCallbacks;
    
    mutable std::mutex m_statsMutex;
    Statistics m_stats;
    
    std::string m_healthMonitorSubscription;
};

// ============================================================================
// Recovery Guard
// ============================================================================
// RAII helper for automatic recovery on scope exit
class RecoveryGuard {
public:
    RecoveryGuard(const std::string& component, 
                  RecoveryStrategyType fallbackStrategy);
    ~RecoveryGuard();
    
    void disable();  // Call if operation succeeds
    void setFallbackStrategy(RecoveryStrategyType strategy);

private:
    std::string m_component;
    RecoveryStrategyType m_fallbackStrategy;
    bool m_enabled = true;
};

// ============================================================================
// Recovery Macros
// ============================================================================
#define RAWR_RECOVERY_GUARD(component, strategy) \
    RawrXD::Reliability::RecoveryGuard _rawr_recovery_guard(component, strategy)

#define RAWR_RECOVERY_GUARD_DISABLE() \
    _rawr_recovery_guard.disable()

} // namespace Reliability
} // namespace RawrXD