// Phase T.4/5: Self-Awareness Monitor
// RawrXD Self-Awareness Monitor - System introspection and self-monitoring

#pragma once

#include <cstring>
#include <vector>
#include <memory>
#include <functional>
#include <chrono>
#include <optional>
#include <unordered_map>

namespace RawrXD {
namespace Meta {

// System state representation
struct SystemState {
    std::string state_id;
    std::chrono::system_clock::time_point timestamp;
    
    // Component states
    std::unordered_map<std::string, std::string> component_states;
    std::unordered_map<std::string, double> component_health;
    
    // Resource state
    double cpu_utilization;
    double memory_utilization;
    double storage_utilization;
    double network_utilization;
    
    // Performance state
    double throughput;
    double latency_p50;
    double latency_p99;
    double error_rate;
    
    // Operational state
    uint32_t active_tasks;
    uint32_t queued_tasks;
    uint32_t failed_tasks_last_minute;
    
    // Overall health
    double overall_health_score;
    std::vector<std::string> active_alerts;
    std::vector<std::string> recent_events;
};

// Self-diagnostic result
struct SelfDiagnosticResult {
    std::string diagnostic_id;
    std::string diagnostic_type;
    std::chrono::system_clock::time_point timestamp;
    
    // Target
    std::string component_id;
    std::string subsystem;
    
    // Results
    bool passed;
    std::vector<std::string> checks_performed;
    std::vector<std::string> failures;
    std::vector<std::string> warnings;
    
    // Findings
    std::unordered_map<std::string, std::string> findings;
    std::vector<std::string> recommendations;
    
    // Severity
    enum class Severity {
        INFO,
        LOW,
        MEDIUM,
        HIGH,
        CRITICAL
    } severity;
    
    // Duration
    std::chrono::milliseconds execution_time;
};

// Introspection query
struct IntrospectionQuery {
    std::string query_id;
    std::string query_type;
    std::string query_text;
    
    // Scope
    std::vector<std::string> target_components;
    std::chrono::seconds lookback_period;
    
    // Results
    std::unordered_map<std::string, std::string> results;
    std::chrono::system_clock::time_point executed_at;
    std::chrono::milliseconds execution_time;
};

// Self-prediction
struct SelfPrediction {
    std::string prediction_id;
    std::string prediction_type;
    std::chrono::system_clock::time_point predicted_at;
    
    // Prediction window
    std::chrono::seconds horizon;
    std::chrono::system_clock::time_point prediction_time;
    
    // Predicted values
    std::unordered_map<std::string, double> predicted_metrics;
    std::vector<std::string> predicted_events;
    
    // Confidence
    double confidence;
    std::vector<std::string> confidence_factors;
    
    // Model used
    std::string model_id;
    std::string model_version;
    
    // Validation
    bool validated;
    std::chrono::system_clock::time_point actual_time;
    double accuracy;
};

// Self-awareness monitor
class ISelfAwarenessMonitor {
public:
    virtual ~ISelfAwarenessMonitor() = default;
    
    // Initialization
    virtual bool Initialize(const std::string& config_path) = 0;
    virtual void Shutdown() = 0;
    
    // State monitoring
    virtual SystemState CaptureCurrentState() = 0;
    virtual std::string RecordState(const SystemState& state) = 0;
    virtual std::vector<SystemState> GetStateHistory(std::chrono::hours lookback = std::chrono::hours(24)) = 0;
    virtual std::optional<SystemState> GetStateAtTime(std::chrono::system_clock::time_point time) = 0;
    
    // Self-diagnostics
    virtual std::string RunDiagnostic(const std::string& diagnostic_type,
                                       const std::string& component_id = "") = 0;
    virtual std::optional<SelfDiagnosticResult> GetDiagnosticResult(const std::string& diagnostic_id) = 0;
    virtual std::vector<SelfDiagnosticResult> GetDiagnosticHistory(const std::string& component_id = "") = 0;
    virtual bool ScheduleDiagnostic(const std::string& diagnostic_type,
                                     std::chrono::seconds interval) = 0;
    
    // Introspection
    virtual std::string QueryIntrospection(const std::string& query_type,
                                              const std::string& query_text) = 0;
    virtual std::optional<IntrospectionQuery> GetIntrospectionResult(const std::string& query_id) = 0;
    virtual std::vector<IntrospectionQuery> GetIntrospectionHistory() = 0;
    
    // Self-prediction
    virtual std::string PredictFuture(const std::string& prediction_type,
                                        std::chrono::seconds horizon) = 0;
    virtual std::optional<SelfPrediction> GetPrediction(const std::string& prediction_id) = 0;
    virtual std::vector<SelfPrediction> GetActivePredictions() = 0;
    virtual bool ValidatePrediction(const std::string& prediction_id,
                                     const SystemState& actual_state) = 0;
    virtual double GetPredictionAccuracy(const std::string& prediction_type) = 0;
    
    // Self-description
    virtual std::string GenerateSelfDescription() = 0;
    virtual std::vector<std::string> ListCapabilities() = 0;
    virtual std::vector<std::string> ListLimitations() = 0;
    virtual std::unordered_map<std::string, std::string> GetConfiguration() = 0;
    
    // Self-assessment
    virtual double AssessOverallHealth() = 0;
    virtual std::vector<std::string> IdentifyBottlenecks() = 0;
    virtual std::vector<std::string> IdentifyRisks() = 0;
    virtual std::vector<std::string> SuggestOptimizations() = 0;
    
    // Statistics
    virtual struct SelfAwarenessStatistics {
        uint64_t states_recorded;
        uint64_t diagnostics_run;
        uint64_t introspection_queries;
        uint64_t predictions_made;
        double prediction_accuracy;
        double average_health_score;
        uint32_t active_bottlenecks;
        uint32_t identified_risks;
    } GetStatistics() = 0;
};

// Local self-awareness monitor
class LocalSelfAwarenessMonitor : public ISelfAwarenessMonitor {
public:
    LocalSelfAwarenessMonitor();
    ~LocalSelfAwarenessMonitor() override;
    
    bool Initialize(const std::string& config_path) override;
    void Shutdown() override;
    
    SystemState CaptureCurrentState() override;
    std::string RecordState(const SystemState& state) override;
    std::vector<SystemState> GetStateHistory(std::chrono::hours lookback = std::chrono::hours(24)) override;
    std::optional<SystemState> GetStateAtTime(std::chrono::system_clock::time_point time) override;
    
    std::string RunDiagnostic(const std::string& diagnostic_type,
                             const std::string& component_id = "") override;
    std::optional<SelfDiagnosticResult> GetDiagnosticResult(const std::string& diagnostic_id) override;
    std::vector<SelfDiagnosticResult> GetDiagnosticHistory(const std::string& component_id = "") override;
    bool ScheduleDiagnostic(const std::string& diagnostic_type,
                             std::chrono::seconds interval) override;
    
    std::string QueryIntrospection(const std::string& query_type,
                                    const std::string& query_text) override;
    std::optional<IntrospectionQuery> GetIntrospectionResult(const std::string& query_id) override;
    std::vector<IntrospectionQuery> GetIntrospectionHistory() override;
    
    std::string PredictFuture(const std::string& prediction_type,
                               std::chrono::seconds horizon) override;
    std::optional<SelfPrediction> GetPrediction(const std::string& prediction_id) override;
    std::vector<SelfPrediction> GetActivePredictions() override;
    bool ValidatePrediction(const std::string& prediction_id,
                             const SystemState& actual_state) override;
    double GetPredictionAccuracy(const std::string& prediction_type) override;
    
    std::string GenerateSelfDescription() override;
    std::vector<std::string> ListCapabilities() override;
    std::vector<std::string> ListLimitations() override;
    std::unordered_map<std::string, std::string> GetConfiguration() override;
    
    double AssessOverallHealth() override;
    std::vector<std::string> IdentifyBottlenecks() override;
    std::vector<std::string> IdentifyRisks() override;
    std::vector<std::string> SuggestOptimizations() override;
    
    SelfAwarenessStatistics GetStatistics() override;
    
private:
    std::vector<SystemState> state_history_;
    std::unordered_map<std::string, SelfDiagnosticResult> diagnostics_;
    std::unordered_map<std::string, IntrospectionQuery> introspections_;
    std::unordered_map<std::string, SelfPrediction> predictions_;
    bool initialized_ = false;
    
    bool RunComponentDiagnostic(const std::string& component_id, SelfDiagnosticResult& result);
    bool QueryComponentState(const std::string& component_id, std::unordered_map<std::string, std::string>& state);
    double PredictMetric(const std::string& metric, std::chrono::seconds horizon);
    double CalculateHealthScore(const SystemState& state);
};

// Global self-awareness monitor
extern std::unique_ptr<ISelfAwarenessMonitor> g_self_awareness_monitor;

// Initialize self-awareness monitor
bool InitializeSelfAwarenessMonitor(const std::string& config_path);
void ShutdownSelfAwarenessMonitor();
bool IsSelfAwarenessMonitorEnabled();

} // namespace Meta
} // namespace RawrXD
