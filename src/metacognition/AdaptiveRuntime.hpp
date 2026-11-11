// Phase V.5/5: Adaptive Runtime
// RawrXD Adaptive Runtime - Self-optimizing execution environment

#pragma once

#include <cstring>
#include <vector>
#include <memory>
#include <functional>
#include <chrono>
#include <optional>
#include <unordered_map>

namespace RawrXD {
namespace MetaCognition {

// Adaptation trigger types
enum class AdaptationTrigger {
    PERFORMANCE_REGRESSION,
    RESOURCE_CONSTRAINT,
    WORKLOAD_CHANGE,
    ERROR_RATE_INCREASE,
    USER_PREFERENCE,
    PREDICTED_ISSUE,
    EXTERNAL_SIGNAL
};

// Runtime configuration
struct RuntimeConfiguration {
    std::string config_id;
    std::string name;
    std::chrono::system_clock::time_point created_at;
    
    // Compute settings
    std::string preferred_backend;
    uint32_t thread_count;
    uint32_t batch_size;
    bool enable_gpu;
    bool enable_quantum;
    
    // Inference settings
    uint32_t max_tokens;
    float temperature;
    float top_p;
    uint32_t top_k;
    float repetition_penalty;
    
    // Resource limits
    uint64_t max_memory_mb;
    uint32_t max_concurrent_requests;
    std::chrono::seconds timeout;
    
    // Optimization
    bool enable_caching;
    bool enable_batching;
    bool enable_compression;
    std::string optimization_level;
    
    // Validation
    bool is_validated;
    double performance_score;
    double reliability_score;
};

// Adaptation action
struct AdaptationAction {
    std::string action_id;
    AdaptationTrigger trigger;
    std::chrono::system_clock::time_point triggered_at;
    
    // Action details
    std::string target_component;
    std::string action_type;
    std::string description;
    std::unordered_map<std::string, std::string> parameters;
    
    // Expected impact
    double expected_improvement;
    std::vector<std::string> affected_metrics;
    std::vector<std::string> risks;
    
    // Execution
    bool is_executed;
    std::chrono::system_clock::time_point executed_at;
    bool was_successful;
    double actual_improvement;
};

// Workload characteristics
struct WorkloadCharacteristics {
    std::string workload_type;
    
    // Compute profile
    double compute_intensity;
    double memory_intensity;
    double io_intensity;
    double network_intensity;
    
    // Temporal patterns
    double arrival_rate;
    double burstiness;
    std::chrono::seconds average_duration;
    
    // Requirements
    double latency_requirement_ms;
    double throughput_requirement;
    double accuracy_requirement;
    
    // Patterns
    bool is_predictable;
    bool is_batchable;
    bool is_cacheable;
};

// Backend selection policy
struct BackendSelectionPolicy {
    std::string policy_id;
    std::string name;
    
    // Selection criteria
    std::unordered_map<std::string, double> weights;
    double latency_weight;
    double throughput_weight;
    double cost_weight;
    double accuracy_weight;
    
    // Thresholds
    double max_acceptable_latency_ms;
    double min_required_throughput;
    double max_cost_per_request;
    
    // Fallback
    std::vector<std::string> fallback_order;
    bool allow_fallback;
};

// Adaptive runtime interface
class IAdaptiveRuntime {
public:
    virtual ~IAdaptiveRuntime() = default;
    
    // Initialization
    virtual bool Initialize(const std::string& config_path) = 0;
    virtual void Shutdown() = 0;
    
    // Configuration management
    virtual std::string CreateConfiguration(const RuntimeConfiguration& config) = 0;
    virtual bool UpdateConfiguration(const RuntimeConfiguration& config) = 0;
    virtual bool DeleteConfiguration(const std::string& config_id) = 0;
    virtual std::optional<RuntimeConfiguration> GetConfiguration(const std::string& config_id) = 0;
    virtual std::vector<RuntimeConfiguration> ListConfigurations() = 0;
    virtual bool ActivateConfiguration(const std::string& config_id) = 0;
    virtual std::optional<RuntimeConfiguration> GetActiveConfiguration() = 0;
    
    // Workload analysis
    virtual WorkloadCharacteristics AnalyzeWorkload(const std::string& workload_id) = 0;
    virtual std::string ClassifyWorkload(const WorkloadCharacteristics& characteristics) = 0;
    virtual std::vector<std::string> GetSimilarWorkloads(const std::string& workload_type) = 0;
    
    // Backend selection
    virtual std::string SelectBackend(const WorkloadCharacteristics& workload,
                                       const BackendSelectionPolicy& policy) = 0;
    virtual std::string CreateBackendPolicy(const BackendSelectionPolicy& policy) = 0;
    virtual bool UpdateBackendPolicy(const BackendSelectionPolicy& policy) = 0;
    virtual std::optional<BackendSelectionPolicy> GetBackendPolicy(const std::string& policy_id) = 0;
    
    // Adaptation
    virtual bool TriggerAdaptation(AdaptationTrigger trigger) = 0;
    virtual std::string RecordAdaptation(const AdaptationAction& action) = 0;
    virtual bool ExecuteAdaptation(const std::string& action_id) = 0;
    virtual std::vector<AdaptationAction> GetAdaptationHistory() = 0;
    virtual std::vector<AdaptationAction> GetPendingAdaptations() = 0;
    
    // Optimization
    virtual std::vector<std::string> SuggestOptimizations() = 0;
    virtual bool ApplyOptimization(const std::string& optimization_id) = 0;
    virtual bool ValidateOptimization(const std::string& optimization_id) = 0;
    virtual bool RollbackOptimization(const std::string& optimization_id) = 0;
    
    // Prediction
    virtual std::vector<std::string> PredictIssues(std::chrono::hours horizon = std::chrono::hours(1)) = 0;
    virtual WorkloadCharacteristics PredictWorkload(std::chrono::hours horizon = std::chrono::hours(1)) = 0;
    virtual std::optional<RuntimeConfiguration> RecommendConfiguration(const std::string& workload_type) = 0;
    
    // Monitoring
    virtual bool EnableAutoAdaptation() = 0;
    virtual bool DisableAutoAdaptation() = 0;
    virtual bool IsAutoAdaptationEnabled() = 0;
    virtual void SetAdaptationInterval(std::chrono::seconds interval) = 0;
    
    // Statistics
    virtual struct AdaptiveRuntimeStatistics {
        uint64_t configurations_created;
        uint32_t configurations_active;
        uint64_t adaptations_triggered;
        uint64_t adaptations_executed;
        uint64_t adaptations_rolled_back;
        double average_adaptation_time_ms;
        double optimization_success_rate;
        double prediction_accuracy;
        std::chrono::seconds current_uptime;
    } GetStatistics() = 0;
};

// Local adaptive runtime
class LocalAdaptiveRuntime : public IAdaptiveRuntime {
public:
    LocalAdaptiveRuntime();
    ~LocalAdaptiveRuntime() override;
    
    bool Initialize(const std::string& config_path) override;
    void Shutdown() override;
    
    std::string CreateConfiguration(const RuntimeConfiguration& config) override;
    bool UpdateConfiguration(const RuntimeConfiguration& config) override;
    bool DeleteConfiguration(const std::string& config_id) override;
    std::optional<RuntimeConfiguration> GetConfiguration(const std::string& config_id) override;
    std::vector<RuntimeConfiguration> ListConfigurations() override;
    bool ActivateConfiguration(const std::string& config_id) override;
    std::optional<RuntimeConfiguration> GetActiveConfiguration() override;
    
    WorkloadCharacteristics AnalyzeWorkload(const std::string& workload_id) override;
    std::string ClassifyWorkload(const WorkloadCharacteristics& characteristics) override;
    std::vector<std::string> GetSimilarWorkloads(const std::string& workload_type) override;
    
    std::string SelectBackend(const WorkloadCharacteristics& workload,
                               const BackendSelectionPolicy& policy) override;
    std::string CreateBackendPolicy(const BackendSelectionPolicy& policy) override;
    bool UpdateBackendPolicy(const BackendSelectionPolicy& policy) override;
    std::optional<BackendSelectionPolicy> GetBackendPolicy(const std::string& policy_id) override;
    
    bool TriggerAdaptation(AdaptationTrigger trigger) override;
    std::string RecordAdaptation(const AdaptationAction& action) override;
    bool ExecuteAdaptation(const std::string& action_id) override;
    std::vector<AdaptationAction> GetAdaptationHistory() override;
    std::vector<AdaptationAction> GetPendingAdaptations() override;
    
    std::vector<std::string> SuggestOptimizations() override;
    bool ApplyOptimization(const std::string& optimization_id) override;
    bool ValidateOptimization(const std::string& optimization_id) override;
    bool RollbackOptimization(const std::string& optimization_id) override;
    
    std::vector<std::string> PredictIssues(std::chrono::hours horizon = std::chrono::hours(1)) override;
    WorkloadCharacteristics PredictWorkload(std::chrono::hours horizon = std::chrono::hours(1)) override;
    std::optional<RuntimeConfiguration> RecommendConfiguration(const std::string& workload_type) override;
    
    bool EnableAutoAdaptation() override;
    bool DisableAutoAdaptation() override;
    bool IsAutoAdaptationEnabled() override;
    void SetAdaptationInterval(std::chrono::seconds interval) override;
    
    AdaptiveRuntimeStatistics GetStatistics() override;
    
private:
    std::unordered_map<std::string, RuntimeConfiguration> configurations_;
    std::unordered_map<std::string, BackendSelectionPolicy> policies_;
    std::unordered_map<std::string, AdaptationAction> adaptations_;
    std::unordered_map<std::string, WorkloadCharacteristics> workload_history_;
    std::string active_config_id_;
    bool auto_adaptation_enabled_ = false;
    std::chrono::seconds adaptation_interval_ = std::chrono::seconds(300);
    bool initialized_ = false;
    std::chrono::system_clock::time_point start_time_;
    
    double ScoreBackend(const std::string& backend, const WorkloadCharacteristics& workload);
    bool ValidateConfiguration(const RuntimeConfiguration& config);
    std::vector<std::string> GenerateOptimizationSuggestions();
    bool ApplyConfiguration(const RuntimeConfiguration& config);
    void MonitorAndAdapt();
};

// Global adaptive runtime
extern std::unique_ptr<IAdaptiveRuntime> g_adaptive_runtime;

// Initialize adaptive runtime
bool InitializeAdaptiveRuntime(const std::string& config_path);
void ShutdownAdaptiveRuntime();
bool IsAdaptiveRuntimeEnabled();

// Trigger helpers
std::string AdaptationTriggerToString(AdaptationTrigger trigger);
AdaptationTrigger AdaptationTriggerFromString(const std::string& str);

} // namespace MetaCognition
} // namespace RawrXD
