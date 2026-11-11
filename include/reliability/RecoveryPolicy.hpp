// ============================================================================
// RecoveryPolicy.hpp — Recovery Strategy Definitions
// ============================================================================
// Mission 2.4: Reliability Interface Layer
//
// Defines recovery strategies and policies that can be applied to failures.
// Policies are composable and can be chained for multi-stage recovery.
// ============================================================================

#pragma once

#include "FailureEvent.hpp"
#include <string>
#include <vector>
#include <functional>
#include <memory>
#include <future>

namespace RawrXD {
namespace Reliability {

// ============================================================================
// Recovery Strategy Types
// ============================================================================
enum class RecoveryStrategyType {
    UNKNOWN = 0,
    
    // Process-level strategies
    RESTART_SERVICE,        // Full service restart
    RESTART_COMPONENT,      // Restart specific component
    RESTART_THREAD,         // Restart worker thread
    
    // State-level strategies
    ROLLBACK_STATE,         // Restore from checkpoint
    RESET_STATE,            // Clear and reinitialize
    RELOAD_CONFIG,          // Reload configuration
    
    // Resource-level strategies
    RELEASE_MEMORY,         // Force garbage collection/free
    CLEAR_CACHE,            // Clear caches
    RECONNECT_RESOURCE,     // Re-establish connections
    
    // Execution-level strategies
    RETRY_OPERATION,        // Simple retry with backoff
    CIRCUIT_BREAK,          // Stop sending requests temporarily
    DEGRADE_GRACEFULLY,     // Reduce functionality
    
    // Escalation strategies
    ESCALATE_TO_HUMAN,      // Alert operator
    FAILOVER_TO_REPLICA,    // Switch to backup
    SHUTDOWN_GRACEFULLY     // Controlled shutdown
};

const char* RecoveryStrategyTypeToString(RecoveryStrategyType type);
RecoveryStrategyType RecoveryStrategyTypeFromString(const std::string& str);

// ============================================================================
// Recovery Strategy
// ============================================================================
struct RecoveryStrategy {
    RecoveryStrategyType type;
    std::string name;
    std::string description;
    
    // Execution parameters
    int maxAttempts = 3;
    std::chrono::milliseconds initialBackoff{100};
    std::chrono::milliseconds maxBackoff{30000};
    double backoffMultiplier = 2.0;
    
    // Preconditions
    std::vector<FailureCategory> applicableCategories;
    std::vector<FailureSeverity> applicableSeverities;
    
    // Success criteria
    std::chrono::milliseconds verificationTimeout{5000};
    std::function<bool()> healthCheck;
    
    // Metadata
    bool requiresStateSnapshot = false;
    bool canBeInterrupted = true;
    int priority = 0;  // Higher = tried first
    
    RecoveryStrategy();
    RecoveryStrategy(RecoveryStrategyType t, const std::string& n);
    
    bool isApplicableTo(const FailureEvent& event) const;
    std::chrono::milliseconds calculateBackoff(int attempt) const;
    nlohmann::json toJson() const;
};

// ============================================================================
// Recovery Policy
// ============================================================================
// A policy defines a sequence of strategies to attempt for a failure
class RecoveryPolicy {
public:
    RecoveryPolicy(const std::string& name);
    
    // Strategy chain
    RecoveryPolicy& addStrategy(const RecoveryStrategy& strategy);
    RecoveryPolicy& addStrategy(RecoveryStrategyType type);
    RecoveryPolicy& then(RecoveryStrategyType type);  // Fluent alias
    
    // Filter when this policy applies
    RecoveryPolicy& forCategories(const std::vector<FailureCategory>& cats);
    RecoveryPolicy& forSeverities(const std::vector<FailureSeverity>& sevs);
    RecoveryPolicy& forComponents(const std::vector<std::string>& comps);
    
    // Policy matching
    bool matches(const FailureEvent& event) const;
    std::vector<RecoveryStrategy> getStrategies() const;
    
    // Metadata
    std::string getName() const { return m_name; }
    void setDescription(const std::string& desc) { m_description = desc; }
    std::string getDescription() const { return m_description; }
    
    nlohmann::json toJson() const;

private:
    std::string m_name;
    std::string m_description;
    std::vector<RecoveryStrategy> m_strategies;
    
    std::vector<FailureCategory> m_categories;
    std::vector<FailureSeverity> m_severities;
    std::vector<std::string> m_components;
};

// ============================================================================
// Built-in Policies
// ============================================================================
namespace Policies {

// Worker thread crash: restart thread, then escalate
RecoveryPolicy WorkerCrashPolicy();

// Memory pressure: clear cache, release memory, then restart
RecoveryPolicy MemoryPressurePolicy();

// State corruption: rollback, then reset if rollback fails
RecoveryPolicy StateCorruptionPolicy();

// Exception storm: circuit break, then degrade
RecoveryPolicy ExceptionStormPolicy();

// Service unavailable: reconnect, then failover
RecoveryPolicy ServiceUnavailablePolicy();

// Default catch-all policy
RecoveryPolicy DefaultPolicy();

} // namespace Policies

// ============================================================================
// Recovery Result
// ============================================================================
enum class RecoveryStatus {
    PENDING = 0,
    IN_PROGRESS,
    SUCCESS,
    PARTIAL_SUCCESS,
    FAILED,
    CANCELLED,
    TIMED_OUT
};

struct RecoveryResult {
    std::string recoveryId;
    std::string eventId;
    RecoveryStatus status;
    
    std::chrono::steady_clock::time_point startTime;
    std::chrono::steady_clock::time_point endTime;
    
    std::vector<RecoveryStrategyType> attemptedStrategies;
    RecoveryStrategyType successfulStrategy;
    std::string failureReason;
    
    int attemptsMade = 0;
    bool stateRestored = false;
    std::string finalStateHash;
    
    uint64_t recoveryDurationMs() const;
    bool wasSuccessful() const;
    nlohmann::json toJson() const;
};

} // namespace Reliability
} // namespace RawrXD