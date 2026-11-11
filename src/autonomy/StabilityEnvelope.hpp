// StabilityEnvelope.hpp
// Phase C.4 Batch 1/5 — Autonomous Stability Envelope
// Safety governance layer for sovereign autonomous runtime

#ifndef STABILITY_ENVELOPE_HPP
#define STABILITY_ENVELOPE_HPP

#include <vector>
#include <map>
#include <memory>
#include <string>
#include <chrono>
#include <atomic>
#include <mutex>
#include <functional>
#include <limits>

namespace Autonomy {

// Forward declarations
class OscillationDetector;
class RollbackEngine;
class SafetyGate;

// ============================================================================
// Stability Threshold Types
// ============================================================================

enum class StabilityDimension {
    HARMONIC,           // Frequency/oscillation stability
    RESOURCE,           // CPU, memory, GPU stability
    PERFORMANCE,        // TPS, latency stability
    GRAPH_STRUCTURE,    // Mutation safety
    DECISION_QUALITY,   // Decision confidence bounds
    ROLE_BEHAVIOR      // Role execution stability
};

enum class ThresholdSeverity {
    INFO,       // Within normal bounds
    WARNING,    // Approaching limit
    CRITICAL,   // At boundary
    VIOLATION   // Outside envelope
};

// ============================================================================
// Stability Threshold Configuration
// ============================================================================

struct StabilityThreshold {
    StabilityDimension dimension;
    
    // Threshold values
    double nominal_min;
    double nominal_max;
    double warning_min;
    double warning_max;
    double critical_min;
    double critical_max;
    
    // Hysteresis to prevent oscillation
    double hysteresis;
    
    // Time-based constraints
    std::chrono::milliseconds min_violation_duration;
    std::chrono::milliseconds max_warning_duration;
    
    // Auto-recovery
    bool auto_recovery_enabled;
    std::chrono::milliseconds recovery_cooldown;
    
    StabilityThreshold()
        : nominal_min(0.0), nominal_max(1.0)
        , warning_min(0.0), warning_max(1.0)
        , critical_min(0.0), critical_max(1.0)
        , hysteresis(0.05)
        , min_violation_duration(std::chrono::milliseconds(1000))
        , max_warning_duration(std::chrono::milliseconds(5000))
        , auto_recovery_enabled(true)
        , recovery_cooldown(std::chrono::milliseconds(30000))
    {}
};

// ============================================================================
// Resource Safety Limits
// ============================================================================

struct ResourceSafetyLimits {
    // CPU limits
    double cpu_utilization_max;
    double cpu_utilization_critical;
    uint32_t max_thread_count;
    
    // Memory limits
    size_t memory_usage_max_bytes;
    size_t memory_usage_critical_bytes;
    double memory_growth_rate_max; // bytes/sec
    
    // GPU limits
    double gpu_utilization_max;
    double gpu_memory_max;
    double gpu_temperature_max;
    
    // KV Cache limits
    size_t kv_cache_size_max;
    double kv_cache_pressure_max;
    
    // Network limits
    double network_bandwidth_max_mbps;
    uint32_t max_concurrent_connections;
    
    ResourceSafetyLimits()
        : cpu_utilization_max(0.85), cpu_utilization_critical(0.95)
        , max_thread_count(64)
        , memory_usage_max_bytes(16ULL * 1024 * 1024 * 1024) // 16GB
        , memory_usage_critical_bytes(28ULL * 1024 * 1024 * 1024) // 28GB
        , memory_growth_rate_max(100 * 1024 * 1024) // 100MB/sec
        , gpu_utilization_max(0.90), gpu_memory_max(0.90)
        , gpu_temperature_max(85.0)
        , kv_cache_size_max(8ULL * 1024 * 1024 * 1024) // 8GB
        , kv_cache_pressure_max(0.85)
        , network_bandwidth_max_mbps(10000.0)
        , max_concurrent_connections(1000)
    {}
};

// ============================================================================
// Graph Mutation Safety Constraints
// ============================================================================

struct GraphMutationConstraints {
    // Structural limits
    uint32_t max_graph_nodes;
    uint32_t max_graph_edges;
    uint32_t max_mutation_depth;
    
    // Mutation rate limits
    double max_mutations_per_second;
    double max_mutation_chain_length;
    std::chrono::milliseconds min_mutation_interval;
    
    // Safety checks
    bool require_rollback_capability;
    bool require_state_backup;
    bool require_validation_before_apply;
    
    // Mutation type restrictions
    std::vector<std::string> forbidden_mutation_types;
    std::vector<std::string> restricted_mutation_types;
    
    GraphMutationConstraints()
        : max_graph_nodes(10000)
        , max_graph_edges(50000)
        , max_mutation_depth(10)
        , max_mutations_per_second(5.0)
        , max_mutation_chain_length(3.0)
        , min_mutation_interval(std::chrono::milliseconds(200))
        , require_rollback_capability(true)
        , require_state_backup(true)
        , require_validation_before_apply(true)
    {}
};

// ============================================================================
// Decision Risk Scoring
// ============================================================================

struct DecisionRiskProfile {
    // Risk weights (must sum to 1.0)
    double performance_impact_weight;
    double stability_impact_weight;
    double resource_impact_weight;
    double safety_impact_weight;
    double reversibility_weight;
    
    // Risk thresholds
    double max_acceptable_risk;
    double max_warning_risk;
    double min_confidence_for_autonomous;
    
    DecisionRiskProfile()
        : performance_impact_weight(0.25)
        , stability_impact_weight(0.25)
        , resource_impact_weight(0.20)
        , safety_impact_weight(0.20)
        , reversibility_weight(0.10)
        , max_acceptable_risk(0.30)
        , max_warning_risk(0.60)
        , min_confidence_for_autonomous(0.75)
    {}
    
    double CalculateCompositeRisk(double performance_risk,
                                   double stability_risk,
                                   double resource_risk,
                                   double safety_risk,
                                   double reversibility_score) const;
};

// ============================================================================
// Intent Safety Gating
// ============================================================================

struct IntentSafetyGate {
    // Intent classification
    std::string intent_type;
    ThresholdSeverity required_clearance;
    
    // Preconditions
    std::vector<std::string> required_preconditions;
    std::vector<std::string> forbidden_preconditions;
    
    // Postconditions
    std::vector<std::string> required_postconditions;
    
    // Resource requirements
    double min_available_resources;
    double max_resource_consumption;
    
    // Time constraints
    std::chrono::milliseconds max_execution_time;
    std::chrono::milliseconds timeout_action_delay;
    
    IntentSafetyGate()
        : required_clearance(ThresholdSeverity::WARNING)
        , min_available_resources(0.20)
        , max_resource_consumption(0.50)
        , max_execution_time(std::chrono::milliseconds(30000))
        , timeout_action_delay(std::chrono::milliseconds(5000))
    {}
};

// ============================================================================
// Role Safety Profile
// ============================================================================

struct RoleSafetyProfile {
    std::string role_name;
    
    // Capability restrictions
    std::vector<std::string> allowed_mutations;
    std::vector<std::string> forbidden_mutations;
    std::vector<std::string> allowed_decisions;
    
    // Resource budget
    double max_resource_allocation;
    double max_concurrent_tasks;
    
    // Safety level
    ThresholdSeverity min_safety_clearance;
    bool requires_human_approval;
    
    // Timeout and recovery
    std::chrono::milliseconds role_timeout;
    std::string fallback_role;
    
    RoleSafetyProfile()
        : max_resource_allocation(0.30)
        , max_concurrent_tasks(10)
        , min_safety_clearance(ThresholdSeverity::WARNING)
        , requires_human_approval(false)
        , role_timeout(std::chrono::milliseconds(300000)) // 5 minutes
    {}
};

// ============================================================================
// Stability State
// ============================================================================

struct StabilityState {
    std::chrono::steady_clock::time_point timestamp;
    
    // Current values per dimension
    std::map<StabilityDimension, double> current_values;
    std::map<StabilityDimension, ThresholdSeverity> current_severity;
    
    // Historical tracking
    std::map<StabilityDimension, std::vector<std::pair<std::chrono::steady_clock::time_point, double>>> history;
    
    // Violation tracking
    std::map<StabilityDimension, std::chrono::steady_clock::time_point> violation_start_time;
    std::map<StabilityDimension, uint32_t> violation_count;
    
    // Overall stability
    double overall_stability_score;
    ThresholdSeverity overall_severity;
    bool envelope_violated;
    
    StabilityState()
        : overall_stability_score(1.0)
        , overall_severity(ThresholdSeverity::INFO)
        , envelope_violated(false)
    {}
};

// ============================================================================
// Stability Alert
// ============================================================================

struct StabilityAlert {
    std::string alert_id;
    StabilityDimension dimension;
    ThresholdSeverity severity;
    std::string message;
    double current_value;
    double threshold_value;
    std::chrono::steady_clock::time_point timestamp;
    std::map<std::string, std::string> context;
    
    // Recommended actions
    std::vector<std::string> recommended_actions;
    bool auto_action_triggered;
};

// ============================================================================
// Stability Envelope Configuration
// ============================================================================

struct StabilityEnvelopeConfig {
    // Thresholds per dimension
    std::map<StabilityDimension, StabilityThreshold> thresholds;
    
    // Resource limits
    ResourceSafetyLimits resource_limits;
    
    // Mutation constraints
    GraphMutationConstraints mutation_constraints;
    
    // Risk profile
    DecisionRiskProfile risk_profile;
    
    // Intent gates
    std::map<std::string, IntentSafetyGate> intent_gates;
    
    // Role profiles
    std::map<std::string, RoleSafetyProfile> role_profiles;
    
    // Global settings
    bool auto_recovery_enabled;
    bool alert_on_warning;
    bool enforce_safety_gates;
    uint32_t max_alerts_per_minute;
    std::chrono::milliseconds state_history_window;
    
    StabilityEnvelopeConfig()
        : auto_recovery_enabled(true)
        , alert_on_warning(true)
        , enforce_safety_gates(true)
        , max_alerts_per_minute(60)
        , state_history_window(std::chrono::minutes(5))
    {
        // Initialize default thresholds for all dimensions
        thresholds[StabilityDimension::HARMONIC] = StabilityThreshold();
        thresholds[StabilityDimension::RESOURCE] = StabilityThreshold();
        thresholds[StabilityDimension::PERFORMANCE] = StabilityThreshold();
        thresholds[StabilityDimension::GRAPH_STRUCTURE] = StabilityThreshold();
        thresholds[StabilityDimension::DECISION_QUALITY] = StabilityThreshold();
        thresholds[StabilityDimension::ROLE_BEHAVIOR] = StabilityThreshold();
    }
};

// ============================================================================
// Stability Envelope — Main Controller
// ============================================================================

class StabilityEnvelope {
public:
    explicit StabilityEnvelope(const StabilityEnvelopeConfig& config = StabilityEnvelopeConfig{});
    ~StabilityEnvelope();
    
    // Lifecycle
    void Initialize();
    void Start();
    void Stop();
    void Shutdown();
    
    // State monitoring
    void UpdateDimension(StabilityDimension dimension, double value);
    void UpdateResourceState(const ResourceSafetyLimits& current_usage);
    void UpdatePerformanceMetrics(double tps, double latency_ms, double throughput);
    
    // Query current state
    StabilityState GetCurrentState() const;
    ThresholdSeverity GetDimensionSeverity(StabilityDimension dimension) const;
    double GetStabilityScore() const;
    bool IsEnvelopeViolated() const;
    
    // Safety checks
    bool CheckIntentSafety(const std::string& intent_type, 
                          const std::map<std::string, double>& context) const;
    bool CheckMutationSafety(const std::string& mutation_type,
                            const std::map<std::string, double>& impact_estimate) const;
    bool CheckRoleSafety(const std::string& role_name,
                        const std::map<std::string, double>& role_context) const;
    
    // Risk assessment
    double AssessDecisionRisk(const std::string& decision_type,
                              const std::map<std::string, double>& impact_factors) const;
    ThresholdSeverity GetDecisionClearance(double risk_score) const;
    
    // Alert handling
    using AlertCallback = std::function<void(const StabilityAlert& alert)>;
    void SetAlertCallback(AlertCallback callback);
    std::vector<StabilityAlert> GetActiveAlerts() const;
    void AcknowledgeAlert(const std::string& alert_id);
    void ClearAlert(const std::string& alert_id);
    
    // Recovery
    bool TriggerAutoRecovery(StabilityDimension dimension);
    bool IsRecoveryInProgress() const;
    std::vector<std::string> GetRecoveryActions() const;
    
    // Configuration
    void UpdateThreshold(StabilityDimension dimension, const StabilityThreshold& threshold);
    void UpdateResourceLimits(const ResourceSafetyLimits& limits);
    void UpdateMutationConstraints(const GraphMutationConstraints& constraints);
    void UpdateRiskProfile(const DecisionRiskProfile& profile);
    
    // Statistics
    struct StabilityStatistics {
        uint64_t total_updates;
        uint64_t warning_count;
        uint64_t critical_count;
        uint64_t violation_count;
        uint64_t auto_recovery_count;
        double average_stability_score;
        std::chrono::steady_clock::time_point last_violation;
        std::chrono::steady_clock::time_point last_recovery;
    };
    
    StabilityStatistics GetStatistics() const;
    
    // Export/Import
    void ExportConfiguration(const std::string& path) const;
    void ImportConfiguration(const std::string& path);
    void ExportStateHistory(const std::string& path) const;
    
private:
    StabilityEnvelopeConfig config_;
    
    // Current state
    StabilityState current_state_;
    mutable std::mutex state_mutex_;
    
    // Alert management
    std::vector<StabilityAlert> active_alerts_;
    mutable std::mutex alerts_mutex_;
    AlertCallback alert_callback_;
    
    // Recovery state
    std::atomic<bool> recovery_in_progress_{false};
    std::map<StabilityDimension, std::chrono::steady_clock::time_point> last_recovery_;
    
    // Statistics
    StabilityStatistics stats_;
    mutable std::mutex stats_mutex_;
    
    // Background monitoring
    std::atomic<bool> running_{false};
    std::thread monitor_thread_;
    
    // Internal methods
    void MonitorLoop();
    ThresholdSeverity EvaluateThreshold(StabilityDimension dimension, double value) const;
    void CheckForViolations();
    void GenerateAlert(StabilityDimension dimension, ThresholdSeverity severity,
                      double current_value, double threshold_value);
    void ExecuteAutoRecovery(StabilityDimension dimension);
    double CalculateOverallStability() const;
    bool ShouldTriggerRecovery(StabilityDimension dimension) const;
    bool IsWithinCooldown(StabilityDimension dimension) const;
};

// ============================================================================
// Utility Functions
// ============================================================================

namespace StabilityUtils {
    // Threshold helpers
    bool IsWithinEnvelope(double value, const StabilityThreshold& threshold);
    bool IsWithinWarning(double value, const StabilityThreshold& threshold);
    bool IsWithinCritical(double value, const StabilityThreshold& threshold);
    
    // Severity comparison
    bool IsMoreSevere(ThresholdSeverity a, ThresholdSeverity b);
    ThresholdSeverity MaxSeverity(ThresholdSeverity a, ThresholdSeverity b);
    
    // String conversions
    std::string DimensionToString(StabilityDimension dim);
    std::string SeverityToString(ThresholdSeverity sev);
    StabilityDimension StringToDimension(const std::string& str);
    ThresholdSeverity StringToSeverity(const std::string& str);
    
    // Statistical analysis
    double CalculateVariance(const std::vector<double>& values);
    double CalculateTrend(const std::vector<std::pair<std::chrono::steady_clock::time_point, double>>& history);
    bool DetectOscillation(const std::vector<double>& values, double threshold);
    
    // Safety scoring
    double NormalizeRiskScore(double raw_score, double min_expected, double max_expected);
    double CombineRiskScores(const std::vector<double>& scores, const std::vector<double>& weights);
} // namespace StabilityUtils

} // namespace Autonomy

#endif // STABILITY_ENVELOPE_HPP
