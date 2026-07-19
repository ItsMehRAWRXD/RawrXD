// ============================================================================
// RecoveryController.cpp — Recovery Orchestration Implementation
// ============================================================================

#include "reliability/RecoveryController.hpp"
#include <iostream>
#include <sstream>
#include <random>

namespace RawrXD {
namespace Reliability {

// ============================================================================
// Recovery Task Implementation
// ============================================================================
bool RecoveryTask::isExpired() const {
    auto now = std::chrono::steady_clock::now();
    return now > createdAt + std::chrono::minutes(5);  // 5 min default timeout
}

bool RecoveryTask::canRetry() const {
    return currentAttempt < policy.getStrategies().size() ||
           (currentAttempt < 3 && !isExpired());  // Max 3 attempts
}

std::chrono::milliseconds RecoveryTask::timeRemaining() const {
    auto now = std::chrono::steady_clock::now();
    auto deadline = createdAt + std::chrono::minutes(5);
    if (now >= deadline) return std::chrono::milliseconds(0);
    return std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
}

// ============================================================================
// Recovery Controller Implementation
// ============================================================================
RecoveryController& RecoveryController::instance() {
    static RecoveryController instance;
    return instance;
}

bool RecoveryController::initialize() {
    if (m_running.load()) return true;
    
    // Register default policies
    registerPolicy(Policies::WorkerCrashPolicy());
    registerPolicy(Policies::MemoryPressurePolicy());
    registerPolicy(Policies::StateCorruptionPolicy());
    registerPolicy(Policies::ExceptionStormPolicy());
    registerPolicy(Policies::ServiceUnavailablePolicy());
    
    m_defaultPolicy = Policies::DefaultPolicy();
    
    m_running.store(true);
    m_recoveryThread = std::thread(&RecoveryController::recoveryLoop, this);
    
    return true;
}

void RecoveryController::shutdown() {
    m_running.store(false);
    m_taskCondition.notify_all();
    
    if (m_recoveryThread.joinable()) {
        m_recoveryThread.join();
    }
}

void RecoveryController::recoveryLoop() {
    while (m_running.load()) {
        std::unique_lock<std::mutex> lock(m_queueMutex);
        
        // Wait for tasks or shutdown
        m_taskCondition.wait(lock, [this] {
            return !m_pendingTasks.empty() || !m_running.load();
        });
        
        if (!m_running.load()) break;
        if (m_pendingTasks.empty()) continue;
        
        // Get next task
        RecoveryTask task = m_pendingTasks.front();
        m_pendingTasks.pop();
        
        // Check if we can start this recovery
        if (static_cast<int>(m_activeTasks.size()) >= m_maxConcurrent.load()) {
            // Put it back and wait
            m_pendingTasks.push(task);
            lock.unlock();
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }
        
        // Move to active
        m_activeTasks[task.taskId] = task;
        lock.unlock();
        
        // Process the task
        processRecoveryTask(m_activeTasks[task.taskId]);
    }
}

void RecoveryController::processRecoveryTask(RecoveryTask& task) {
    task.startedAt = std::chrono::steady_clock::now();
    task.status = RecoveryStatus::IN_PROGRESS;
    
    auto strategies = task.policy.getStrategies();
    
    for (size_t i = 0; i < strategies.size(); ++i) {
        if (!m_running.load()) {
            completeRecovery(task, RecoveryStatus::CANCELLED);
            return;
        }
        
        const auto& strategy = strategies[i];
        task.currentStrategy = strategy.name;
        task.currentAttempt = static_cast<int>(i) + 1;
        
        // Execute strategy with retry
        bool success = false;
        for (int attempt = 0; attempt < strategy.maxAttempts; ++attempt) {
            if (executeStrategy(task, strategy)) {
                success = true;
                break;
            }
            
            // Backoff before retry
            auto backoff = strategy.calculateBackoff(attempt + 1);
            std::this_thread::sleep_for(backoff);
        }
        
        if (success) {
            task.result.successfulStrategy = strategy.type;
            task.attemptedStrategies.push_back(strategy.type);
            
            // Verify recovery
            if (verifyRecovery(task)) {
                completeRecovery(task, RecoveryStatus::SUCCESS);
                return;
            }
        }
        
        task.attemptedStrategies.push_back(strategy.type);
    }
    
    // All strategies exhausted
    failRecovery(task, "All recovery strategies exhausted");
}

bool RecoveryController::executeStrategy(RecoveryTask& task, 
                                         const RecoveryStrategy& strategy) {
    auto action = getAction(strategy.type);
    if (!action) {
        // No action registered, simulate success for testing
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        return true;
    }
    
    try {
        return action();
    } catch (...) {
        return false;
    }
}

bool RecoveryController::verifyRecovery(const RecoveryTask& task) {
    // Check if component is healthy again
    auto status = HealthMonitor::instance().getComponentStatus(
        task.triggerEvent.sourceComponent);
    
    return status == HealthStatus::HEALTHY || 
           status == HealthStatus::DEGRADED;
}

void RecoveryController::completeRecovery(RecoveryTask& task, 
                                          RecoveryStatus status) {
    task.status = status;
    task.completedAt = std::chrono::steady_clock::now();
    task.result.status = status;
    task.result.recoveryId = task.taskId;
    task.result.eventId = task.triggerEvent.eventId;
    task.result.attemptsMade = task.currentAttempt;
    task.result.attemptedStrategies = task.attemptedStrategies;
    
    // Move to history
    {
        std::lock_guard<std::mutex> lock(m_historyMutex);
        m_completedTasks.push_back(task);
        if (m_completedTasks.size() > MAX_HISTORY) {
            m_completedTasks.erase(m_completedTasks.begin());
        }
    }
    
    // Remove from active
    {
        std::lock_guard<std::mutex> lock(m_queueMutex);
        m_activeTasks.erase(task.taskId);
    }
    
    // Update stats
    updateStatistics(task);
    
    // Notify
    if (status == RecoveryStatus::SUCCESS || 
        status == RecoveryStatus::PARTIAL_SUCCESS) {
        notifyComplete(task.result);
    } else {
        notifyFailed(task.result);
    }
}

void RecoveryController::failRecovery(RecoveryTask& task, 
                                      const std::string& reason) {
    task.result.failureReason = reason;
    completeRecovery(task, RecoveryStatus::FAILED);
}

RecoveryPolicy RecoveryController::selectPolicy(const FailureEvent& event) const {
    std::lock_guard<std::mutex> lock(m_policiesMutex);
    
    // Find matching policy
    for (const auto& policy : m_policies) {
        if (policy.matches(event)) {
            return policy;
        }
    }
    
    return m_defaultPolicy;
}

RecoveryAction RecoveryController::getAction(RecoveryStrategyType type) const {
    std::lock_guard<std::mutex> lock(m_actionsMutex);
    auto it = m_actions.find(type);
    if (it != m_actions.end()) {
        return it->second;
    }
    return nullptr;
}

void RecoveryController::registerPolicy(const RecoveryPolicy& policy) {
    std::lock_guard<std::mutex> lock(m_policiesMutex);
    m_policies.push_back(policy);
}

void RecoveryController::registerDefaultPolicy(const RecoveryPolicy& policy) {
    std::lock_guard<std::mutex> lock(m_policiesMutex);
    m_defaultPolicy = policy;
}

void RecoveryController::unregisterPolicy(const std::string& name) {
    std::lock_guard<std::mutex> lock(m_policiesMutex);
    m_policies.erase(
        std::remove_if(m_policies.begin(), m_policies.end(),
            [&name](const RecoveryPolicy& p) { return p.getName() == name; }),
        m_policies.end());
}

void RecoveryController::clearPolicies() {
    std::lock_guard<std::mutex> lock(m_policiesMutex);
    m_policies.clear();
}

void RecoveryController::registerAction(RecoveryStrategyType type, 
                                        RecoveryAction action) {
    std::lock_guard<std::mutex> lock(m_actionsMutex);
    m_actions[type] = action;
}

void RecoveryController::unregisterAction(RecoveryStrategyType type) {
    std::lock_guard<std::mutex> lock(m_actionsMutex);
    m_actions.erase(type);
}

bool RecoveryController::hasAction(RecoveryStrategyType type) const {
    std::lock_guard<std::mutex> lock(m_actionsMutex);
    return m_actions.find(type) != m_actions.end();
}

void RecoveryController::registerStateSnapshotter(
    std::function<nlohmann::json()> snapshotter) {
    std::lock_guard<std::mutex> lock(m_stateMutex);
    m_snapshotter = snapshotter;
}

void RecoveryController::registerStateRestorer(
    std::function<bool(const nlohmann::json&)> restorer) {
    std::lock_guard<std::mutex> lock(m_stateMutex);
    m_restorer = restorer;
}

nlohmann::json RecoveryController::captureStateSnapshot() {
    std::lock_guard<std::mutex> lock(m_stateMutex);
    if (m_snapshotter) {
        return m_snapshotter();
    }
    return nlohmann::json::object();
}

bool RecoveryController::restoreState(const nlohmann::json& snapshot) {
    std::lock_guard<std::mutex> lock(m_stateMutex);
    if (m_restorer) {
        return m_restorer(snapshot);
    }
    return false;
}

std::string RecoveryController::startRecovery(const FailureEvent& event) {
    if (!m_autoRecoveryEnabled.load()) {
        return "";
    }
    
    auto policy = selectPolicy(event);
    return startRecovery(event, policy);
}

std::string RecoveryController::startRecovery(const FailureEvent& event,
                                               const RecoveryPolicy& overridePolicy) {
    RecoveryTask task;
    task.taskId = "REC-" + std::to_string(
        std::chrono::steady_clock::now().time_since_epoch().count());
    task.triggerEvent = event;
    task.policy = overridePolicy;
    task.createdAt = std::chrono::steady_clock::now();
    task.status = RecoveryStatus::PENDING;
    
    {
        std::lock_guard<std::mutex> lock(m_queueMutex);
        m_pendingTasks.push(task);
    }
    
    m_taskCondition.notify_one();
    
    {
        std::lock_guard<std::mutex> lock(m_statsMutex);
        m_stats.totalRecoveriesInitiated++;
    }
    
    return task.taskId;
}

bool RecoveryController::cancelRecovery(const std::string& recoveryId) {
    std::lock_guard<std::mutex> lock(m_queueMutex);
    
    auto it = m_activeTasks.find(recoveryId);
    if (it != m_activeTasks.end()) {
        completeRecovery(it->second, RecoveryStatus::CANCELLED);
        return true;
    }
    
    return false;
}

RecoveryStatus RecoveryController::getRecoveryStatus(const std::string& recoveryId) const {
    std::lock_guard<std::mutex> lock(m_queueMutex);
    
    auto it = m_activeTasks.find(recoveryId);
    if (it != m_activeTasks.end()) {
        return it->second.status;
    }
    
    // Check history
    std::lock_guard<std::mutex> hlock(m_historyMutex);
    for (const auto& task : m_completedTasks) {
        if (task.taskId == recoveryId) {
            return task.status;
        }
    }
    
    return RecoveryStatus::PENDING;
}

RecoveryResult RecoveryController::getRecoveryResult(const std::string& recoveryId) const {
    std::lock_guard<std::mutex> lock(m_historyMutex);
    
    for (const auto& task : m_completedTasks) {
        if (task.taskId == recoveryId) {
            return task.result;
        }
    }
    
    return RecoveryResult{};
}

std::vector<RecoveryTask> RecoveryController::getActiveRecoveries() const {
    std::lock_guard<std::mutex> lock(m_queueMutex);
    std::vector<RecoveryTask> result;
    for (const auto& pair : m_activeTasks) {
        result.push_back(pair.second);
    }
    return result;
}

std::vector<RecoveryTask> RecoveryController::getRecoveryHistory(size_t limit) const {
    std::lock_guard<std::mutex> lock(m_historyMutex);
    
    std::vector<RecoveryTask> result;
    size_t start = m_completedTasks.size() > limit ? 
                   m_completedTasks.size() - limit : 0;
    
    for (size_t i = start; i < m_completedTasks.size(); ++i) {
        result.push_back(m_completedTasks[i]);
    }
    
    return result;
}

bool RecoveryController::isRecoveryInProgress() const {
    std::lock_guard<std::mutex> lock(m_queueMutex);
    return !m_activeTasks.empty();
}

bool RecoveryController::isRecoveryInProgressFor(const std::string& component) const {
    std::lock_guard<std::mutex> lock(m_queueMutex);
    for (const auto& pair : m_activeTasks) {
        if (pair.second.triggerEvent.sourceComponent == component) {
            return true;
        }
    }
    return false;
}

void RecoveryController::onRecoveryComplete(RecoveryCallback callback) {
    std::lock_guard<std::mutex> lock(m_callbacksMutex);
    m_completeCallbacks.push_back(callback);
}

void RecoveryController::onRecoveryFailed(RecoveryCallback callback) {
    std::lock_guard<std::mutex> lock(m_callbacksMutex);
    m_failedCallbacks.push_back(callback);
}

void RecoveryController::notifyComplete(const RecoveryResult& result) {
    std::lock_guard<std::mutex> lock(m_callbacksMutex);
    for (const auto& callback : m_completeCallbacks) {
        callback(result);
    }
}

void RecoveryController::notifyFailed(const RecoveryResult& result) {
    std::lock_guard<std::mutex> lock(m_callbacksMutex);
    for (const auto& callback : m_failedCallbacks) {
        callback(result);
    }
}

void RecoveryController::updateStatistics(const RecoveryTask& task) {
    std::lock_guard<std::mutex> lock(m_statsMutex);
    
    switch (task.status) {
        case RecoveryStatus::SUCCESS:
        case RecoveryStatus::PARTIAL_SUCCESS:
            m_stats.totalRecoveriesSuccessful++;
            break;
        case RecoveryStatus::FAILED:
            m_stats.totalRecoveriesFailed++;
            break;
        case RecoveryStatus::CANCELLED:
            m_stats.totalRecoveriesCancelled++;
            break;
        default:
            break;
    }
    
    m_stats.totalStrategiesAttempted += task.attemptedStrategies.size();
    if (task.status == RecoveryStatus::SUCCESS) {
        m_stats.totalStrategiesSuccessful++;
    }
    
    // Update timing stats
    auto duration = task.result.recoveryDurationMs();
    if (duration > m_stats.maxRecoveryTimeMs) {
        m_stats.maxRecoveryTimeMs = duration;
    }
    
    // Update strategy counts
    for (const auto& strat : task.attemptedStrategies) {
        if (task.status == RecoveryStatus::SUCCESS && 
            strat == task.result.successfulStrategy) {
            m_stats.strategySuccessCounts[strat]++;
        } else {
            m_stats.strategyFailureCounts[strat]++;
        }
    }
}

RecoveryController::Statistics RecoveryController::getStatistics() const {
    std::lock_guard<std::mutex> lock(m_statsMutex);
    return m_stats;
}

void RecoveryController::resetStatistics() {
    std::lock_guard<std::mutex> lock(m_statsMutex);
    m_stats = Statistics{};
}

void RecoveryController::setMaxConcurrentRecoveries(int max) {
    m_maxConcurrent.store(max);
}

void RecoveryController::setGlobalRecoveryTimeout(std::chrono::milliseconds timeout) {
    m_globalTimeout = timeout;
}

void RecoveryController::setAutoRecoveryEnabled(bool enabled) {
    m_autoRecoveryEnabled.store(enabled);
}

void RecoveryController::connectToHealthMonitor() {
    // Subscribe to failure events from HealthMonitor
    FailureFilter filter;
    filter.severities = {FailureSeverity::ERROR, 
                         FailureSeverity::CRITICAL, 
                         FailureSeverity::FATAL};
    
    HealthMonitor::instance().subscribeToFailures(filter,
        [this](const FailureEvent& event) {
            if (m_autoRecoveryEnabled.load() && event.isRecoverable()) {
                startRecovery(event);
            }
        });
}

void RecoveryController::disconnectFromHealthMonitor() {
    // Unsubscribe would require storing subscription ID
    // For now, just disable auto-recovery
    m_autoRecoveryEnabled.store(false);
}

// ============================================================================
// Recovery Guard Implementation
// ============================================================================
RecoveryGuard::RecoveryGuard(const std::string& component,
                             RecoveryStrategyType fallbackStrategy)
    : m_component(component)
    , m_fallbackStrategy(fallbackStrategy)
    , m_enabled(true) {
}

RecoveryGuard::~RecoveryGuard() {
    if (m_enabled) {
        // Trigger recovery on scope exit if not disabled
        FailureEvent event(FailureCategory::EXCEPTION_THROWN,
                           FailureSeverity::ERROR,
                           m_component,
                           "Operation failed, triggering recovery");
        RecoveryController::instance().startRecovery(event);
    }
}

void RecoveryGuard::disable() {
    m_enabled = false;
}

void RecoveryGuard::setFallbackStrategy(RecoveryStrategyType strategy) {
    m_fallbackStrategy = strategy;
}

} // namespace Reliability
} // namespace RawrXD