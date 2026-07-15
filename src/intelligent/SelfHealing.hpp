// Phase Q.2/5: Self-Healing System
// RawrXD Self-Healing - Automated remediation and recovery

#pragma once

#include <cstring>
#include <vector>
#include <memory>
#include <functional>
#include <chrono>
#include <optional>

namespace RawrXD {
namespace Intelligent {

// Forward declaration
struct AnomalyResult;

// Remediation action types
enum class RemediationAction {
    RESTART_SERVICE,        // Restart a service
    SCALE_UP,             // Add capacity
    SCALE_DOWN,           // Remove capacity
    CLEAR_CACHE,          // Clear caches
    REBALANCE_LOAD,       // Redistribute load
    FAILOVER,             // Switch to backup
    ROLLBACK_CONFIG,      // Revert configuration
    RESTART_INSTANCE,     // Restart VM/container
    RECONNECT_RESOURCE,   // Reconnect to resource
    RUN_DIAGNOSTIC,       // Execute diagnostic
    NOTIFY_OPERATOR,      // Escalate to human
    CUSTOM                // Custom action
};

// Remediation result
struct RemediationResult {
    std::string id;
    std::string anomaly_id;
    RemediationAction action;
    
    bool success;
    std::string error_message;
    std::chrono::milliseconds execution_time;
    
    std::chrono::system_clock::time_point started_at;
    std::chrono::system_clock::time_point completed_at;
    
    // Impact assessment
    bool resolved_anomaly;
    double confidence_improvement;
    std::vector<std::string> side_effects;
    
    // Rollback info
    bool can_rollback;
    std::string rollback_command;
    bool rollback_executed;
};

// Remediation policy
struct RemediationPolicy {
    std::string id;
    std::string name;
    
    // Trigger conditions
    std::vector<std::string> anomaly_types;  // Which anomalies trigger this
    std::vector<std::string> affected_resources;
    double min_confidence;      // Minimum anomaly confidence
    uint32_t min_occurrences;   // Times seen before acting
    
    // Action
    RemediationAction action;
    std::string action_script;
    std::unordered_map<std::string, std::string> action_params;
    
    // Safety
    bool requires_approval;     // Human approval required
    std::chrono::seconds approval_timeout;
    bool dry_run_first;         // Test before executing
    uint32_t max_attempts;      // Max remediation attempts
    std::chrono::seconds cooldown_between_attempts;
    
    // Escalation
    std::string escalation_policy_id;  // If remediation fails
    uint32_t escalation_after_attempts;
    
    // Monitoring
    bool enabled;
    std::chrono::system_clock::time_point last_executed;
    uint32_t execution_count;
    uint32_t success_count;
};

// Health check definition
struct HealthCheck {
    std::string id;
    std::string name;
    std::string resource_id;
    
    enum class CheckType {
        HTTP_ENDPOINT,
        TCP_PORT,
        COMMAND_EXEC,
        METRIC_THRESHOLD,
        CUSTOM
    } type;
    
    // Check configuration
    std::string target;         // URL, host:port, or command
    std::unordered_map<std::string, std::string> parameters;
    
    // Timing
    std::chrono::seconds interval;
    std::chrono::seconds timeout;
    uint32_t retries;
    
    // Thresholds
    uint32_t consecutive_failures_before_unhealthy;
    uint32_t consecutive_successes_before_healthy;
    
    // Current state
    enum class HealthState {
        HEALTHY,
        DEGRADED,
        UNHEALTHY,
        UNKNOWN
    } state;
    
    uint32_t consecutive_failures;
    uint32_t consecutive_successes;
    std::chrono::system_clock::time_point last_check;
    std::chrono::system_clock::time_point last_state_change;
    std::string last_error;
};

// Circuit breaker state
enum class CircuitState {
    CLOSED,     // Normal operation
    OPEN,       // Failing, rejecting requests
    HALF_OPEN   // Testing if recovered
};

struct CircuitBreaker {
    std::string id;
    std::string resource_id;
    
    CircuitState state;
    uint32_t failure_threshold;
    uint32_t success_threshold;
    std::chrono::seconds timeout;
    
    uint32_t current_failures;
    uint32_t current_successes;
    std::chrono::system_clock::time_point last_failure;
    std::chrono::system_clock::time_point opened_at;
    
    // Statistics
    uint64_t total_requests;
    uint64_t failed_requests;
    uint64_t rejected_requests;
};

// Self-healing manager interface
class ISelfHealingManager {
public:
    virtual ~ISelfHealingManager() = default;
    
    // Initialization
    virtual bool Initialize(const std::string& config_path) = 0;
    virtual void Shutdown() = 0;
    
    // Policy management
    virtual std::string CreatePolicy(const RemediationPolicy& policy) = 0;
    virtual bool UpdatePolicy(const RemediationPolicy& policy) = 0;
    virtual bool DeletePolicy(const std::string& policy_id) = 0;
    virtual std::optional<RemediationPolicy> GetPolicy(const std::string& policy_id) = 0;
    virtual std::vector<RemediationPolicy> ListPolicies() = 0;
    virtual bool EnablePolicy(const std::string& policy_id) = 0;
    virtual bool DisablePolicy(const std::string& policy_id) = 0;
    
    // Remediation execution
    virtual std::string ExecuteRemediation(const std::string& anomaly_id,
                                            const RemediationPolicy& policy) = 0;
    virtual bool CancelRemediation(const std::string& remediation_id) = 0;
    virtual std::optional<RemediationResult> GetRemediationResult(
        const std::string& remediation_id) = 0;
    virtual std::vector<RemediationResult> GetRemediationHistory(
        const std::string& anomaly_id = "") = 0;
    
    // Automated remediation
    virtual bool EnableAutoRemediation(const std::string& policy_id) = 0;
    virtual bool DisableAutoRemediation(const std::string& policy_id) = 0;
    virtual std::vector<RemediationResult> ProcessAnomaly(
        const AnomalyResult& anomaly) = 0;
    
    // Health checks
    virtual std::string RegisterHealthCheck(const HealthCheck& check) = 0;
    virtual bool UnregisterHealthCheck(const std::string& check_id) = 0;
    virtual bool UpdateHealthCheck(const HealthCheck& check) = 0;
    virtual std::optional<HealthCheck> GetHealthCheck(const std::string& check_id) = 0;
    virtual std::vector<HealthCheck> GetHealthChecks(const std::string& resource_id = "") = 0;
    virtual HealthCheck::HealthState GetResourceHealth(const std::string& resource_id) = 0;
    
    // Circuit breakers
    virtual std::string CreateCircuitBreaker(const CircuitBreaker& breaker) = 0;
    virtual bool UpdateCircuitBreaker(const CircuitBreaker& breaker) = 0;
    virtual std::optional<CircuitBreaker> GetCircuitBreaker(const std::string& breaker_id) = 0;
    virtual CircuitState CheckCircuitState(const std::string& resource_id) = 0;
    virtual bool RecordSuccess(const std::string& breaker_id) = 0;
    virtual bool RecordFailure(const std::string& breaker_id) = 0;
    
    // Rollback
    virtual bool CanRollback(const std::string& remediation_id) = 0;
    virtual bool RollbackRemediation(const std::string& remediation_id) = 0;
    
    // Statistics
    virtual struct HealingStatistics {
        uint32_t total_remediations;
        uint32_t successful_remediations;
        uint32_t failed_remediations;
        uint32_t auto_remediations;
        uint32_t manual_remediations;
        double success_rate;
        double avg_resolution_time_ms;
        uint32_t prevented_outages;
    } GetStatistics(std::chrono::hours lookback = std::chrono::hours(168)) = 0;
};

// Local self-healing manager
class LocalSelfHealingManager : public ISelfHealingManager {
public:
    LocalSelfHealingManager();
    ~LocalSelfHealingManager() override;
    
    bool Initialize(const std::string& config_path) override;
    void Shutdown() override;
    
    std::string CreatePolicy(const RemediationPolicy& policy) override;
    bool UpdatePolicy(const RemediationPolicy& policy) override;
    bool DeletePolicy(const std::string& policy_id) override;
    std::optional<RemediationPolicy> GetPolicy(const std::string& policy_id) override;
    std::vector<RemediationPolicy> ListPolicies() override;
    bool EnablePolicy(const std::string& policy_id) override;
    bool DisablePolicy(const std::string& policy_id) override;
    
    std::string ExecuteRemediation(const std::string& anomaly_id,
                                    const RemediationPolicy& policy) override;
    bool CancelRemediation(const std::string& remediation_id) override;
    std::optional<RemediationResult> GetRemediationResult(
        const std::string& remediation_id) override;
    std::vector<RemediationResult> GetRemediationHistory(
        const std::string& anomaly_id = "") override;
    
    bool EnableAutoRemediation(const std::string& policy_id) override;
    bool DisableAutoRemediation(const std::string& policy_id) override;
    std::vector<RemediationResult> ProcessAnomaly(const AnomalyResult& anomaly) override;
    
    std::string RegisterHealthCheck(const HealthCheck& check) override;
    bool UnregisterHealthCheck(const std::string& check_id) override;
    bool UpdateHealthCheck(const HealthCheck& check) override;
    std::optional<HealthCheck> GetHealthCheck(const std::string& check_id) override;
    std::vector<HealthCheck> GetHealthChecks(const std::string& resource_id = "") override;
    HealthCheck::HealthState GetResourceHealth(const std::string& resource_id) override;
    
    std::string CreateCircuitBreaker(const CircuitBreaker& breaker) override;
    bool UpdateCircuitBreaker(const CircuitBreaker& breaker) override;
    std::optional<CircuitBreaker> GetCircuitBreaker(const std::string& breaker_id) override;
    CircuitState CheckCircuitState(const std::string& resource_id) override;
    bool RecordSuccess(const std::string& breaker_id) override;
    bool RecordFailure(const std::string& breaker_id) override;
    
    bool CanRollback(const std::string& remediation_id) override;
    bool RollbackRemediation(const std::string& remediation_id) override;
    
    HealingStatistics GetStatistics(std::chrono::hours lookback = std::chrono::hours(168)) override;
    
private:
    std::unordered_map<std::string, RemediationPolicy> policies_;
    std::unordered_map<std::string, RemediationResult> remediations_;
    std::unordered_map<std::string, HealthCheck> health_checks_;
    std::unordered_map<std::string, CircuitBreaker> circuit_breakers_;
    bool initialized_ = false;
    
    bool ExecuteAction(const RemediationAction& action,
                       const std::unordered_map<std::string, std::string>& params,
                       RemediationResult& result);
    bool RunHealthCheck(HealthCheck& check);
    void UpdateCircuitState(CircuitBreaker& breaker);
};

// Remediation action library
class RemediationActions {
public:
    // Pre-built remediation actions
    static bool RestartService(const std::string& service_name, std::string& output);
    static bool ScaleResource(const std::string& resource_id, int delta, std::string& output);
    static bool ClearCache(const std::string& cache_name, std::string& output);
    static bool FailoverToBackup(const std::string& resource_id, std::string& output);
    static bool RollbackConfiguration(const std::string& resource_id, 
                                       const std::string& version,
                                       std::string& output);
    static bool RestartInstance(const std::string& instance_id, std::string& output);
    static bool ReconnectResource(const std::string& resource_id, std::string& output);
    static bool RunDiagnostic(const std::string& diagnostic_name,
                               const std::string& resource_id,
                               std::string& output);
};

// Predictive healing
class PredictiveHealing {
public:
    // Predict failures before they happen
    struct FailurePrediction {
        std::string resource_id;
        std::string predicted_failure_type;
        double probability;
        std::chrono::system_clock::time_point predicted_time;
        std::chrono::seconds confidence_interval;
        std::vector<std::string> contributing_factors;
    };
    
    std::vector<FailurePrediction> PredictFailures(
        std::chrono::hours horizon = std::chrono::hours(24));
    
    // Proactive remediation
    bool ExecuteProactiveRemediation(const FailurePrediction& prediction);
    
    // Model management
    bool TrainPredictionModel(const std::vector<RemediationResult>& historical_data);
    double EvaluatePredictionAccuracy();
};

// Global self-healing manager
extern std::unique_ptr<ISelfHealingManager> g_self_healing_manager;

// Initialize self-healing
bool InitializeSelfHealing(const std::string& config_path);
void ShutdownSelfHealing();
bool IsSelfHealingEnabled();

} // namespace Intelligent
} // namespace RawrXD
