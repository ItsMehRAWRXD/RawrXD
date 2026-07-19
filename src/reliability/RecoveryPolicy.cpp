// ============================================================================
// RecoveryPolicy.cpp — Recovery Policy Implementation
// ============================================================================

#include "reliability/RecoveryPolicy.hpp"
#include <sstream>

namespace RawrXD {
namespace Reliability {

// ============================================================================
// Recovery Strategy Type Conversions
// ============================================================================
const char* RecoveryStrategyTypeToString(RecoveryStrategyType type) {
    switch (type) {
        case RecoveryStrategyType::RESTART_SERVICE: return "RESTART_SERVICE";
        case RecoveryStrategyType::RESTART_COMPONENT: return "RESTART_COMPONENT";
        case RecoveryStrategyType::RESTART_THREAD: return "RESTART_THREAD";
        case RecoveryStrategyType::ROLLBACK_STATE: return "ROLLBACK_STATE";
        case RecoveryStrategyType::RESET_STATE: return "RESET_STATE";
        case RecoveryStrategyType::RELOAD_CONFIG: return "RELOAD_CONFIG";
        case RecoveryStrategyType::RELEASE_MEMORY: return "RELEASE_MEMORY";
        case RecoveryStrategyType::CLEAR_CACHE: return "CLEAR_CACHE";
        case RecoveryStrategyType::RECONNECT_RESOURCE: return "RECONNECT_RESOURCE";
        case RecoveryStrategyType::RETRY_OPERATION: return "RETRY_OPERATION";
        case RecoveryStrategyType::CIRCUIT_BREAK: return "CIRCUIT_BREAK";
        case RecoveryStrategyType::DEGRADE_GRACEFULLY: return "DEGRADE_GRACEFULLY";
        case RecoveryStrategyType::ESCALATE_TO_HUMAN: return "ESCALATE_TO_HUMAN";
        case RecoveryStrategyType::FAILOVER_TO_REPLICA: return "FAILOVER_TO_REPLICA";
        case RecoveryStrategyType::SHUTDOWN_GRACEFULLY: return "SHUTDOWN_GRACEFULLY";
        default: return "UNKNOWN";
    }
}

RecoveryStrategyType RecoveryStrategyTypeFromString(const std::string& str) {
    if (str == "RESTART_SERVICE") return RecoveryStrategyType::RESTART_SERVICE;
    if (str == "RESTART_COMPONENT") return RecoveryStrategyType::RESTART_COMPONENT;
    if (str == "RESTART_THREAD") return RecoveryStrategyType::RESTART_THREAD;
    if (str == "ROLLBACK_STATE") return RecoveryStrategyType::ROLLBACK_STATE;
    if (str == "RESET_STATE") return RecoveryStrategyType::RESET_STATE;
    if (str == "RELOAD_CONFIG") return RecoveryStrategyType::RELOAD_CONFIG;
    if (str == "RELEASE_MEMORY") return RecoveryStrategyType::RELEASE_MEMORY;
    if (str == "CLEAR_CACHE") return RecoveryStrategyType::CLEAR_CACHE;
    if (str == "RECONNECT_RESOURCE") return RecoveryStrategyType::RECONNECT_RESOURCE;
    if (str == "RETRY_OPERATION") return RecoveryStrategyType::RETRY_OPERATION;
    if (str == "CIRCUIT_BREAK") return RecoveryStrategyType::CIRCUIT_BREAK;
    if (str == "DEGRADE_GRACEFULLY") return RecoveryStrategyType::DEGRADE_GRACEFULLY;
    if (str == "ESCALATE_TO_HUMAN") return RecoveryStrategyType::ESCALATE_TO_HUMAN;
    if (str == "FAILOVER_TO_REPLICA") return RecoveryStrategyType::FAILOVER_TO_REPLICA;
    if (str == "SHUTDOWN_GRACEFULLY") return RecoveryStrategyType::SHUTDOWN_GRACEFULLY;
    return RecoveryStrategyType::UNKNOWN;
}

// ============================================================================
// Recovery Strategy Implementation
// ============================================================================
RecoveryStrategy::RecoveryStrategy() 
    : type(RecoveryStrategyType::UNKNOWN) {
}

RecoveryStrategy::RecoveryStrategy(RecoveryStrategyType t, const std::string& n)
    : type(t)
    , name(n) {
    if (name.empty()) {
        name = RecoveryStrategyTypeToString(t);
    }
}

bool RecoveryStrategy::isApplicableTo(const FailureEvent& event) const {
    // Check category
    if (!applicableCategories.empty()) {
        bool catMatch = false;
        for (const auto& cat : applicableCategories) {
            if (cat == event.category) {
                catMatch = true;
                break;
            }
        }
        if (!catMatch) return false;
    }
    
    // Check severity
    if (!applicableSeverities.empty()) {
        bool sevMatch = false;
        for (const auto& sev : applicableSeverities) {
            if (sev == event.severity) {
                sevMatch = true;
                break;
            }
        }
        if (!sevMatch) return false;
    }
    
    return true;
}

std::chrono::milliseconds RecoveryStrategy::calculateBackoff(int attempt) const {
    if (attempt <= 0) return std::chrono::milliseconds(0);
    
    auto backoff = initialBackoff;
    for (int i = 1; i < attempt; ++i) {
        backoff = std::chrono::milliseconds(
            static_cast<long long>(backoff.count() * backoffMultiplier));
        if (backoff > maxBackoff) {
            backoff = maxBackoff;
            break;
        }
    }
    return backoff;
}

nlohmann::json RecoveryStrategy::toJson() const {
    nlohmann::json j;
    j["type"] = RecoveryStrategyTypeToString(type);
    j["name"] = name;
    j["description"] = description;
    j["max_attempts"] = maxAttempts;
    j["initial_backoff_ms"] = initialBackoff.count();
    j["max_backoff_ms"] = maxBackoff.count();
    j["backoff_multiplier"] = backoffMultiplier;
    j["verification_timeout_ms"] = verificationTimeout.count();
    j["requires_state_snapshot"] = requiresStateSnapshot;
    j["can_be_interrupted"] = canBeInterrupted;
    j["priority"] = priority;
    return j;
}

// ============================================================================
// Recovery Policy Implementation
// ============================================================================
RecoveryPolicy::RecoveryPolicy(const std::string& name)
    : m_name(name) {
}

RecoveryPolicy& RecoveryPolicy::addStrategy(const RecoveryStrategy& strategy) {
    m_strategies.push_back(strategy);
    return *this;
}

RecoveryPolicy& RecoveryPolicy::addStrategy(RecoveryStrategyType type) {
    m_strategies.emplace_back(type, "");
    return *this;
}

RecoveryPolicy& RecoveryPolicy::then(RecoveryStrategyType type) {
    return addStrategy(type);
}

RecoveryPolicy& RecoveryPolicy::forCategories(const std::vector<FailureCategory>& cats) {
    m_categories = cats;
    return *this;
}

RecoveryPolicy& RecoveryPolicy::forSeverities(const std::vector<FailureSeverity>& sevs) {
    m_severities = sevs;
    return *this;
}

RecoveryPolicy& RecoveryPolicy::forComponents(const std::vector<std::string>& comps) {
    m_components = comps;
    return *this;
}

bool RecoveryPolicy::matches(const FailureEvent& event) const {
    // Check categories
    if (!m_categories.empty()) {
        bool catMatch = false;
        for (const auto& cat : m_categories) {
            if (cat == event.category) {
                catMatch = true;
                break;
            }
        }
        if (!catMatch) return false;
    }
    
    // Check severities
    if (!m_severities.empty()) {
        bool sevMatch = false;
        for (const auto& sev : m_severities) {
            if (sev == event.severity) {
                sevMatch = true;
                break;
            }
        }
        if (!sevMatch) return false;
    }
    
    // Check components
    if (!m_components.empty()) {
        bool compMatch = false;
        for (const auto& comp : m_components) {
            if (event.sourceComponent.find(comp) != std::string::npos) {
                compMatch = true;
                break;
            }
        }
        if (!compMatch) return false;
    }
    
    return true;
}

std::vector<RecoveryStrategy> RecoveryPolicy::getStrategies() const {
    return m_strategies;
}

nlohmann::json RecoveryPolicy::toJson() const {
    nlohmann::json j;
    j["name"] = m_name;
    j["description"] = m_description;
    j["strategies"] = nlohmann::json::array();
    for (const auto& strat : m_strategies) {
        j["strategies"].push_back(strat.toJson());
    }
    return j;
}

// ============================================================================
// Built-in Policies
// ============================================================================
namespace Policies {

RecoveryPolicy WorkerCrashPolicy() {
    return RecoveryPolicy("WorkerCrashPolicy")
        .forCategories({FailureCategory::THREAD_TERMINATION, 
                       FailureCategory::PROCESS_CRASH})
        .addStrategy(RecoveryStrategyType::RESTART_THREAD)
        .then(RecoveryStrategyType::RESTART_COMPONENT)
        .then(RecoveryStrategyType::ESCALATE_TO_HUMAN);
}

RecoveryPolicy MemoryPressurePolicy() {
    return RecoveryPolicy("MemoryPressurePolicy")
        .forCategories({FailureCategory::MEMORY_EXHAUSTION,
                       FailureCategory::HANDLE_LEAK})
        .addStrategy(RecoveryStrategyType::CLEAR_CACHE)
        .then(RecoveryStrategyType::RELEASE_MEMORY)
        .then(RecoveryStrategyType::RESTART_COMPONENT);
}

RecoveryPolicy StateCorruptionPolicy() {
    return RecoveryPolicy("StateCorruptionPolicy")
        .forCategories({FailureCategory::STATE_CORRUPTION,
                       FailureCategory::INVALID_CHECKSUM})
        .addStrategy(RecoveryStrategyType::ROLLBACK_STATE)
        .then(RecoveryStrategyType::RESET_STATE)
        .then(RecoveryStrategyType::RESTART_COMPONENT);
}

RecoveryPolicy ExceptionStormPolicy() {
    return RecoveryPolicy("ExceptionStormPolicy")
        .forCategories({FailureCategory::EXCEPTION_THROWN,
                       FailureCategory::ASSERTION_FAILURE})
        .addStrategy(RecoveryStrategyType::CIRCUIT_BREAK)
        .then(RecoveryStrategyType::DEGRADE_GRACEFULLY)
        .then(RecoveryStrategyType::RESTART_SERVICE);
}

RecoveryPolicy ServiceUnavailablePolicy() {
    return RecoveryPolicy("ServiceUnavailablePolicy")
        .forCategories({FailureCategory::SERVICE_UNAVAILABLE,
                       FailureCategory::DEPENDENCY_FAILURE,
                       FailureCategory::TIMEOUT})
        .addStrategy(RecoveryStrategyType::RECONNECT_RESOURCE)
        .then(RecoveryStrategyType::RETRY_OPERATION)
        .then(RecoveryStrategyType::FAILOVER_TO_REPLICA);
}

RecoveryPolicy DefaultPolicy() {
    return RecoveryPolicy("DefaultPolicy")
        .addStrategy(RecoveryStrategyType::RETRY_OPERATION)
        .then(RecoveryStrategyType::RESTART_COMPONENT)
        .then(RecoveryStrategyType::ESCALATE_TO_HUMAN);
}

} // namespace Policies

// ============================================================================
// Recovery Result Implementation
// ============================================================================
uint64_t RecoveryResult::recoveryDurationMs() const {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        endTime - startTime).count();
}

bool RecoveryResult::wasSuccessful() const {
    return status == RecoveryStatus::SUCCESS || 
           status == RecoveryStatus::PARTIAL_SUCCESS;
}

nlohmann::json RecoveryResult::toJson() const {
    nlohmann::json j;
    j["recovery_id"] = recoveryId;
    j["event_id"] = eventId;
    j["status"] = static_cast<int>(status);
    j["attempted_strategies"] = nlohmann::json::array();
    for (const auto& strat : attemptedStrategies) {
        j["attempted_strategies"].push_back(RecoveryStrategyTypeToString(strat));
    }
    j["successful_strategy"] = RecoveryStrategyTypeToString(successfulStrategy);
    j["failure_reason"] = failureReason;
    j["attempts_made"] = attemptsMade;
    j["state_restored"] = stateRestored;
    j["final_state_hash"] = finalStateHash;
    j["duration_ms"] = recoveryDurationMs();
    return j;
}

} // namespace Reliability
} // namespace RawrXD