// Phase V.1/5: Self-Model Engine
// RawrXD Self-Model - Runtime representation of system capabilities and state

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

// Capability types
enum class CapabilityType {
    COMPUTE_CPU,
    COMPUTE_GPU,
    COMPUTE_QUANTUM,
    MEMORY_RAM,
    MEMORY_GPU,
    STORAGE_LOCAL,
    STORAGE_NETWORK,
    NETWORK_BANDWIDTH,
    INFERENCE_MODEL,
    TOOL_EXECUTION,
    AGENT_ORCHESTRATION,
    SECURITY_ENCRYPTION,
    SECURITY_AUTHENTICATION,
    DEBUGGING,
    PROFILING,
    MONITORING
};

// Capability descriptor
struct Capability {
    CapabilityType type;
    std::string name;
    std::string description;
    std::string version;
    
    // Availability
    bool is_available;
    bool is_enabled;
    std::chrono::system_clock::time_point last_checked;
    
    // Capacity
    double capacity_total;
    double capacity_used;
    double capacity_available;
    
    // Performance
    double performance_score;
    double latency_ms;
    double throughput_ops_per_sec;
    
    // Dependencies
    std::vector<CapabilityType> dependencies;
    std::vector<std::string> required_resources;
    
    // Metadata
    std::unordered_map<std::string, std::string> metadata;
};

// Limitation descriptor
struct Limitation {
    std::string id;
    std::string description;
    std::string category;  // "resource", "capability", "policy", "external"
    
    // Impact
    double severity;  // 0.0 to 1.0
    bool is_blocking;
    std::vector<std::string> affected_capabilities;
    
    // Temporal
    bool is_temporary;
    std::optional<std::chrono::system_clock::time_point> expires_at;
    
    // Mitigation
    std::vector<std::string> mitigation_strategies;
    std::optional<std::string> workaround;
};

// Performance profile
struct PerformanceProfile {
    std::string profile_id;
    std::chrono::system_clock::time_point measured_at;
    
    // Compute metrics
    double cpu_utilization;
    double gpu_utilization;
    double memory_utilization;
    double inference_latency_ms;
    double throughput_tokens_per_sec;
    
    // Reliability metrics
    double uptime_percentage;
    double error_rate;
    double recovery_time_ms;
    
    // Efficiency metrics
    double tokens_per_watt;
    double throughput_per_core;
    double cache_hit_rate;
    
    // Historical
    std::vector<double> latency_history;
    std::vector<double> throughput_history;
    double latency_p50;
    double latency_p99;
};

// Self-model representation
struct SelfModel {
    std::string model_id;
    std::string runtime_version;
    std::chrono::system_clock::time_point generated_at;
    
    // Capabilities
    std::unordered_map<CapabilityType, Capability> capabilities;
    std::vector<CapabilityType> available_capabilities;
    std::vector<CapabilityType> enabled_capabilities;
    
    // Limitations
    std::vector<Limitation> active_limitations;
    std::vector<Limitation> blocking_limitations;
    
    // Performance
    PerformanceProfile current_performance;
    std::vector<PerformanceProfile> performance_history;
    
    // Configuration
    std::unordered_map<std::string, std::string> configuration;
    std::vector<std::string> active_modules;
    std::vector<std::string> loaded_models;
    
    // State
    std::string current_status;
    std::vector<std::string> active_tasks;
    uint32_t queue_depth;
    double health_score;
};

// Self-model engine interface
class ISelfModelEngine {
public:
    virtual ~ISelfModelEngine() = default;
    
    // Initialization
    virtual bool Initialize(const std::string& config_path) = 0;
    virtual void Shutdown() = 0;
    
    // Model generation
    virtual SelfModel GenerateSelfModel() = 0;
    virtual std::string SerializeSelfModel(const SelfModel& model) = 0;
    virtual std::optional<SelfModel> DeserializeSelfModel(const std::string& serialized) = 0;
    
    // Capability management
    virtual bool RegisterCapability(const Capability& capability) = 0;
    virtual bool UpdateCapability(CapabilityType type, const Capability& capability) = 0;
    virtual bool EnableCapability(CapabilityType type) = 0;
    virtual bool DisableCapability(CapabilityType type) = 0;
    virtual std::optional<Capability> GetCapability(CapabilityType type) = 0;
    virtual std::vector<Capability> ListCapabilities() = 0;
    virtual std::vector<Capability> ListAvailableCapabilities() = 0;
    virtual bool CheckCapability(CapabilityType type) = 0;
    
    // Limitation management
    virtual std::string AddLimitation(const Limitation& limitation) = 0;
    virtual bool RemoveLimitation(const std::string& limitation_id) = 0;
    virtual bool UpdateLimitation(const Limitation& limitation) = 0;
    virtual std::vector<Limitation> ListLimitations() = 0;
    virtual std::vector<Limitation> ListBlockingLimitations() = 0;
    virtual bool IsCapabilityBlocked(CapabilityType type) = 0;
    
    // Performance tracking
    virtual void RecordPerformance(const PerformanceProfile& profile) = 0;
    virtual PerformanceProfile GetCurrentPerformance() = 0;
    virtual std::vector<PerformanceProfile> GetPerformanceHistory(std::chrono::hours lookback = std::chrono::hours(24)) = 0;
    virtual PerformanceProfile GetPerformanceBaseline() = 0;
    virtual bool DetectPerformanceRegression() = 0;
    
    // Query interface
    virtual bool CanExecute(const std::string& task_type) = 0;
    virtual std::vector<std::string> GetExecutionRequirements(const std::string& task_type) = 0;
    virtual double EstimateExecutionCost(const std::string& task_type) = 0;
    virtual std::vector<std::string> SuggestAlternativeApproaches(const std::string& task_type) = 0;
    
    // Validation
    virtual bool ValidateSelfModel(const SelfModel& model) = 0;
    virtual std::vector<std::string> GetModelDiscrepancies() = 0;
    virtual bool SynchronizeWithTelemetry() = 0;
};

// Local self-model engine
class LocalSelfModelEngine : public ISelfModelEngine {
public:
    LocalSelfModelEngine();
    ~LocalSelfModelEngine() override;
    
    bool Initialize(const std::string& config_path) override;
    void Shutdown() override;
    
    SelfModel GenerateSelfModel() override;
    std::string SerializeSelfModel(const SelfModel& model) override;
    std::optional<SelfModel> DeserializeSelfModel(const std::string& serialized) override;
    
    bool RegisterCapability(const Capability& capability) override;
    bool UpdateCapability(CapabilityType type, const Capability& capability) override;
    bool EnableCapability(CapabilityType type) override;
    bool DisableCapability(CapabilityType type) override;
    std::optional<Capability> GetCapability(CapabilityType type) override;
    std::vector<Capability> ListCapabilities() override;
    std::vector<Capability> ListAvailableCapabilities() override;
    bool CheckCapability(CapabilityType type) override;
    
    std::string AddLimitation(const Limitation& limitation) override;
    bool RemoveLimitation(const std::string& limitation_id) override;
    bool UpdateLimitation(const Limitation& limitation) override;
    std::vector<Limitation> ListLimitations() override;
    std::vector<Limitation> ListBlockingLimitations() override;
    bool IsCapabilityBlocked(CapabilityType type) override;
    
    void RecordPerformance(const PerformanceProfile& profile) override;
    PerformanceProfile GetCurrentPerformance() override;
    std::vector<PerformanceProfile> GetPerformanceHistory(std::chrono::hours lookback = std::chrono::hours(24)) override;
    PerformanceProfile GetPerformanceBaseline() override;
    bool DetectPerformanceRegression() override;
    
    bool CanExecute(const std::string& task_type) override;
    std::vector<std::string> GetExecutionRequirements(const std::string& task_type) override;
    double EstimateExecutionCost(const std::string& task_type) override;
    std::vector<std::string> SuggestAlternativeApproaches(const std::string& task_type) override;
    
    bool ValidateSelfModel(const SelfModel& model) override;
    std::vector<std::string> GetModelDiscrepancies() override;
    bool SynchronizeWithTelemetry() override;
    
private:
    std::unordered_map<CapabilityType, Capability> capabilities_;
    std::unordered_map<std::string, Limitation> limitations_;
    std::vector<PerformanceProfile> performance_history_;
    PerformanceProfile baseline_performance_;
    bool initialized_ = false;
    
    bool ProbeCapability(CapabilityType type);
    double CalculateHealthScore();
    bool CheckDependencies(CapabilityType type);
    void PrunePerformanceHistory();
};

// Global self-model engine
extern std::unique_ptr<ISelfModelEngine> g_self_model_engine;

// Initialize self-model engine
bool InitializeSelfModelEngine(const std::string& config_path);
void ShutdownSelfModelEngine();
bool IsSelfModelEngineEnabled();

// Capability helpers
std::string CapabilityTypeToString(CapabilityType type);
CapabilityType CapabilityTypeFromString(const std::string& str);

} // namespace MetaCognition
} // namespace RawrXD
