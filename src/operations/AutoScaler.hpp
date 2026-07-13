// Phase P.2/5: Auto-Scaling System
// RawrXD AutoScaler - Dynamic resource scaling

#pragma once

#include <cstring>
#include <vector>
#include <memory>
#include <functional>
#include <chrono>
#include <optional>

namespace RawrXD {
namespace Operations {

// Scaling policy types
enum class ScalingPolicyType {
    TARGET_TRACKING,    // Maintain target metric value
    STEP_SCALING,       // Scale by steps based on thresholds
    SCHEDULED,          // Scale based on schedule
    PREDICTIVE,         // ML-based predictive scaling
    CUSTOM              // Custom policy
};

// Metric types for scaling
enum class ScalingMetric {
    GPU_UTILIZATION,
    GPU_MEMORY_UTILIZATION,
    CPU_UTILIZATION,
    MEMORY_UTILIZATION,
    REQUEST_COUNT,
    REQUEST_LATENCY_P99,
    REQUEST_LATENCY_P95,
    QUEUE_DEPTH,
    TOKEN_THROUGHPUT,
    ERROR_RATE
};

// Scaling action
enum class ScalingAction {
    SCALE_OUT,      // Add capacity
    SCALE_IN,       // Remove capacity
    NO_ACTION       // No change needed
};

// Scaling policy configuration
struct ScalingPolicy {
    std::string id;
    std::string name;
    ScalingPolicyType type;
    std::string target_resource;    // e.g., "inference-pool", "gpu-workers"
    
    // Target tracking configuration
    struct TargetTracking {
        ScalingMetric metric;
        double target_value;
        double scale_out_cooldown_seconds;
        double scale_in_cooldown_seconds;
    } target_tracking;
    
    // Step scaling configuration
    struct StepScaling {
        struct StepAdjustment {
            double metric_lower_bound;
            double metric_upper_bound;
            int scaling_adjustment;     // Positive = scale out, negative = scale in
        };
        std::vector<StepAdjustment> steps;
        double aggregation_period_seconds;
    } step_scaling;
    
    // Scheduled scaling configuration
    struct ScheduledScaling {
        std::string schedule_expression;  // Cron expression
        int min_capacity;
        int max_capacity;
        int desired_capacity;
    } scheduled_scaling;
    
    // Predictive scaling configuration
    struct PredictiveScaling {
        ScalingMetric metric;
        double target_value;
        uint32_t forecast_horizon_minutes;
        double metric_history_hours;
    } predictive_scaling;
    
    // Capacity limits
    int min_capacity;
    int max_capacity;
    int desired_capacity;
    
    // Cooldowns
    std::chrono::seconds scale_out_cooldown;
    std::chrono::seconds scale_in_cooldown;
    
    // State
    bool enabled;
    std::chrono::system_clock::time_point last_scale_time;
    int last_scale_amount;
    ScalingAction last_action;
};

// Scaling event
struct ScalingEvent {
    std::string id;
    std::string policy_id;
    std::string target_resource;
    ScalingAction action;
    int previous_capacity;
    int new_capacity;
    ScalingMetric trigger_metric;
    double metric_value;
    std::string reason;
    std::chrono::system_clock::time_point timestamp;
    bool successful;
    std::string error_message;
};

// Resource metrics
struct ResourceMetrics {
    std::string resource_id;
    std::chrono::system_clock::time_point timestamp;
    
    double gpu_utilization_percent;
    double gpu_memory_utilization_percent;
    double cpu_utilization_percent;
    double memory_utilization_percent;
    
    uint32_t active_requests;
    uint32_t queued_requests;
    double request_latency_ms_p99;
    double request_latency_ms_p95;
    double request_latency_ms_p50;
    
    double tokens_per_second;
    uint32_t error_count;
    uint32_t request_count;
};

// Capacity state
struct CapacityState {
    std::string resource_id;
    int current_capacity;
    int pending_capacity;       // Instances being added
    int terminating_capacity;   // Instances being removed
    std::chrono::system_clock::time_point last_updated;
    std::vector<std::string> instance_ids;
};

// Auto-scaler interface
class IAutoScaler {
public:
    virtual ~IAutoScaler() = default;
    
    // Initialization
    virtual bool Initialize(const std::string& config_path) = 0;
    virtual void Shutdown() = 0;
    
    // Policy management
    virtual std::string CreatePolicy(const ScalingPolicy& policy) = 0;
    virtual bool UpdatePolicy(const ScalingPolicy& policy) = 0;
    virtual bool DeletePolicy(const std::string& policy_id) = 0;
    virtual std::optional<ScalingPolicy> GetPolicy(const std::string& policy_id) = 0;
    virtual std::vector<ScalingPolicy> ListPolicies(const std::string& target_resource = "") = 0;
    virtual bool EnablePolicy(const std::string& policy_id) = 0;
    virtual bool DisablePolicy(const std::string& policy_id) = 0;
    
    // Metric submission
    virtual bool SubmitMetrics(const ResourceMetrics& metrics) = 0;
    virtual bool SubmitMetricsBatch(const std::vector<ResourceMetrics>& metrics) = 0;
    
    // Capacity management
    virtual bool RegisterResource(const std::string& resource_id, 
                                     int min_capacity,
                                     int max_capacity) = 0;
    virtual bool UpdateCapacity(const std::string& resource_id, int capacity) = 0;
    virtual CapacityState GetCapacityState(const std::string& resource_id) = 0;
    
    // Scaling operations
    virtual bool EvaluatePolicies() = 0;
    virtual std::optional<ScalingEvent> EvaluatePolicy(const std::string& policy_id) = 0;
    virtual bool ExecuteScaling(const ScalingEvent& event) = 0;
    
    // Manual scaling
    virtual bool ScaleTo(const std::string& resource_id, int capacity, const std::string& reason) = 0;
    virtual bool ScaleBy(const std::string& resource_id, int delta, const std::string& reason) = 0;
    
    // History
    virtual std::vector<ScalingEvent> GetScalingHistory(
        const std::string& resource_id = "",
        std::chrono::system_clock::time_point start = {},
        std::chrono::system_clock::time_point end = {}) = 0;
    
    // Statistics
    virtual struct ScalingStatistics {
        uint32_t total_scale_out_events;
        uint32_t total_scale_in_events;
        uint32_t failed_scaling_events;
        double average_scale_out_time_seconds;
        double average_scale_in_time_seconds;
        int current_capacity;
        int target_capacity;
    } GetStatistics(const std::string& resource_id) = 0;
    
    // Health
    virtual bool IsHealthy() const = 0;
};

// Kubernetes HPA-style auto-scaler
class KubernetesAutoScaler : public IAutoScaler {
public:
    KubernetesAutoScaler();
    ~KubernetesAutoScaler() override;
    
    bool Initialize(const std::string& config_path) override;
    void Shutdown() override;
    
    std::string CreatePolicy(const ScalingPolicy& policy) override;
    bool UpdatePolicy(const ScalingPolicy& policy) override;
    bool DeletePolicy(const std::string& policy_id) override;
    std::optional<ScalingPolicy> GetPolicy(const std::string& policy_id) override;
    std::vector<ScalingPolicy> ListPolicies(const std::string& target_resource = "") override;
    bool EnablePolicy(const std::string& policy_id) override;
    bool DisablePolicy(const std::string& policy_id) override;
    
    bool SubmitMetrics(const ResourceMetrics& metrics) override;
    bool SubmitMetricsBatch(const std::vector<ResourceMetrics>& metrics) override;
    
    bool RegisterResource(const std::string& resource_id, 
                          int min_capacity,
                          int max_capacity) override;
    bool UpdateCapacity(const std::string& resource_id, int capacity) override;
    CapacityState GetCapacityState(const std::string& resource_id) override;
    
    bool EvaluatePolicies() override;
    std::optional<ScalingEvent> EvaluatePolicy(const std::string& policy_id) override;
    bool ExecuteScaling(const ScalingEvent& event) override;
    
    bool ScaleTo(const std::string& resource_id, int capacity, const std::string& reason) override;
    bool ScaleBy(const std::string& resource_id, int delta, const std::string& reason) override;
    
    std::vector<ScalingEvent> GetScalingHistory(
        const std::string& resource_id = "",
        std::chrono::system_clock::time_point start = {},
        std::chrono::system_clock::time_point end = {}) override;
    
    ScalingStatistics GetStatistics(const std::string& resource_id) override;
    
    bool IsHealthy() const override;
    
private:
    std::unordered_map<std::string, ScalingPolicy> policies_;
    std::unordered_map<std::string, CapacityState> capacity_states_;
    std::vector<ScalingEvent> scaling_history_;
    std::vector<ResourceMetrics> metrics_buffer_;
    bool initialized_ = false;
    
    bool CheckCooldown(const ScalingPolicy& policy, ScalingAction action);
    double GetMetricValue(const std::string& resource_id, ScalingMetric metric);
    bool ScaleDeployment(const std::string& resource_id, int new_capacity);
};

// Predictive scaling using ML
class PredictiveAutoScaler {
public:
    struct PredictionConfig {
        uint32_t forecast_horizon_minutes = 30;
        uint32_t training_data_hours = 168;  // 1 week
        double confidence_threshold = 0.8;
    };
    
    explicit PredictiveAutoScaler(const PredictionConfig& config);
    
    // Train model on historical data
    bool Train(const std::vector<ResourceMetrics>& historical_data);
    
    // Predict future load
    std::vector<double> PredictLoad(
        const std::vector<ResourceMetrics>& recent_data,
        uint32_t horizon_minutes);
    
    // Recommend capacity
    int RecommendCapacity(
        const std::vector<double>& predicted_load,
        double target_utilization);
    
private:
    PredictionConfig config_;
    // ML model would be here
};

// Cost-aware scaling
class CostAwareScaler {
public:
    struct CostScalingConfig {
        double max_cost_per_hour;
        double target_cost_efficiency;  // tokens per dollar
        bool prefer_spot_instances;
        double spot_discount_threshold;  // Accept spot if discount > threshold
    };
    
    explicit CostAwareScaler(const CostScalingConfig& config);
    
    // Evaluate scaling decision with cost consideration
    struct ScalingDecision {
        bool should_scale;
        int recommended_capacity;
        double estimated_cost_per_hour;
        double estimated_efficiency;
        std::string reason;
    };
    
    ScalingDecision EvaluateScaling(
        const ResourceMetrics& current_metrics,
        const ScalingPolicy& policy,
        double current_cost_per_hour);
    
    // Optimize instance mix
    struct InstanceMix {
        int on_demand_count;
        int spot_count;
        double blended_cost_per_hour;
    };
    
    InstanceMix OptimizeInstanceMix(
        int total_capacity_needed,
        double spot_reliability);
    
private:
    CostScalingConfig config_;
};

// Scaling strategies
namespace ScalingStrategies {
    // Conservative: Scale out early, scale in late
    ScalingPolicy ConservativePolicy(const std::string& resource_id);
    
    // Aggressive: Scale out late, scale in early
    ScalingPolicy AggressivePolicy(const std::string& resource_id);
    
    // Cost-optimized: Minimize over-provisioning
    ScalingPolicy CostOptimizedPolicy(const std::string& resource_id);
    
    // Latency-sensitive: Maintain low latency at all costs
    ScalingPolicy LatencySensitivePolicy(const std::string& resource_id);
}

// Global auto-scaler
extern std::unique_ptr<IAutoScaler> g_auto_scaler;

// Initialize auto-scaling
bool InitializeAutoScaling(const std::string& config_path);
void ShutdownAutoScaling();
bool IsAutoScalingEnabled();

} // namespace Operations
} // namespace RawrXD
