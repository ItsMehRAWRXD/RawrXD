// Phase W.3/5: End-to-End Validation Suite
// RawrXD End-to-End Validation - Integration scenarios across all subsystems

#pragma once

#include <cstring>
#include <vector>
#include <memory>
#include <functional>
#include <chrono>
#include <optional>
#include <unordered_map>

namespace RawrXD {
namespace Convergence {

// Validation scenario types
enum class ValidationScenarioType {
    INFERENCE_PIPELINE,
    AGENT_WORKFLOW,
    METACOGNITIVE_LOOP,
    QUANTUM_CLASSICAL_HYBRID,
    MULTI_AGENT_COORDINATION,
    MEMORY_REFLECTION_CYCLE,
    ADAPTIVE_OPTIMIZATION,
    FULL_SYSTEM
};

// Validation step
struct ValidationStep {
    std::string step_id;
    std::string name;
    std::string description;
    
    // Execution
    std::string subsystem;
    std::string operation;
    std::unordered_map<std::string, std::string> parameters;
    
    // Validation
    std::string expected_result;
    std::string validation_method;  // "exact", "contains", "regex", "custom"
    double tolerance;
    
    // State
    bool is_executed;
    bool is_successful;
    std::string actual_result;
    std::string error_message;
    std::chrono::milliseconds execution_time;
};

// Validation scenario
struct ValidationScenario {
    std::string scenario_id;
    std::string name;
    std::string description;
    ValidationScenarioType type;
    
    // Steps
    std::vector<ValidationStep> steps;
    
    // Requirements
    std::vector<std::string> required_capabilities;
    std::vector<std::string> required_subsystems;
    
    // Configuration
    std::unordered_map<std::string, std::string> configuration;
    
    // State
    bool is_enabled;
    uint32_t execution_count;
    uint32_t success_count;
    double success_rate;
    std::chrono::milliseconds average_execution_time;
    
    // Baseline
    std::chrono::milliseconds baseline_execution_time;
    double baseline_success_rate;
};

// Validation result
struct ValidationResult {
    std::string result_id;
    std::string scenario_id;
    std::chrono::system_clock::time_point executed_at;
    
    // Overall result
    bool is_successful;
    uint32_t steps_passed;
    uint32_t steps_failed;
    uint32_t steps_total;
    
    // Step results
    std::vector<ValidationStep> step_results;
    
    // Performance
    std::chrono::milliseconds total_execution_time;
    std::chrono::milliseconds baseline_comparison;
    double performance_regression;  // Percentage
    
    // Details
    std::string summary;
    std::vector<std::string> errors;
    std::vector<std::string> warnings;
};

// Baseline metrics
struct BaselineMetrics {
    std::string metric_id;
    std::string scenario_id;
    std::chrono::system_clock::time_point established_at;
    
    // Metrics
    std::chrono::milliseconds execution_time;
    double success_rate;
    std::unordered_map<std::string, double> performance_metrics;
    
    // History
    std::vector<ValidationResult> historical_results;
    double variance;
    double standard_deviation;
};

// End-to-end validation interface
class IEndToEndValidation {
public:
    virtual ~IEndToEndValidation() = default;
    
    // Initialization
    virtual bool Initialize(const std::string& config_path) = 0;
    virtual void Shutdown() = 0;
    
    // Scenario management
    virtual std::string CreateScenario(const ValidationScenario& scenario) = 0;
    virtual bool UpdateScenario(const ValidationScenario& scenario) = 0;
    virtual bool DeleteScenario(const std::string& scenario_id) = 0;
    virtual std::optional<ValidationScenario> GetScenario(const std::string& scenario_id) = 0;
    virtual std::vector<ValidationScenario> ListScenarios() = 0;
    virtual std::vector<ValidationScenario> GetScenariosByType(ValidationScenarioType type) = 0;
    virtual bool EnableScenario(const std::string& scenario_id) = 0;
    virtual bool DisableScenario(const std::string& scenario_id) = 0;
    
    // Execution
    virtual std::string ExecuteScenario(const std::string& scenario_id) = 0;
    virtual std::string ExecuteScenarioAsync(const std::string& scenario_id) = 0;
    virtual std::optional<ValidationResult> GetResult(const std::string& result_id) = 0;
    virtual std::vector<ValidationResult> GetResults(const std::string& scenario_id = "") = 0;
    virtual bool CancelExecution(const std::string& execution_id) = 0;
    
    // Batch execution
    virtual std::vector<std::string> ExecuteAllScenarios() = 0;
    virtual std::vector<std::string> ExecuteScenariosByType(ValidationScenarioType type) = 0;
    
    // Baseline management
    virtual bool EstablishBaseline(const std::string& scenario_id) = 0;
    virtual bool UpdateBaseline(const std::string& scenario_id) = 0;
    virtual std::optional<BaselineMetrics> GetBaseline(const std::string& scenario_id) = 0;
    virtual bool CompareToBaseline(const std::string& result_id) = 0;
    
    // Regression detection
    virtual std::vector<std::string> DetectRegressions() = 0;
    virtual bool IsRegression(const std::string& result_id) = 0;
    virtual std::string ExplainRegression(const std::string& result_id) = 0;
    
    // Reporting
    virtual std::string GenerateReport(const std::string& result_id) = 0;
    virtual std::string GenerateSummaryReport() = 0;
    virtual std::string GenerateRegressionReport() = 0;
    
    // Statistics
    virtual struct ValidationStatistics {
        uint32_t total_scenarios;
        uint32_t enabled_scenarios;
        uint64_t total_executions;
        uint64_t successful_executions;
        uint64_t failed_executions;
        double overall_success_rate;
        uint32_t regressions_detected;
        std::unordered_map<ValidationScenarioType, uint32_t> by_type;
    } GetStatistics() = 0;
};

// Local end-to-end validation
class LocalEndToEndValidation : public IEndToEndValidation {
public:
    LocalEndToEndValidation();
    ~LocalEndToEndValidation() override;
    
    bool Initialize(const std::string& config_path) override;
    void Shutdown() override;
    
    std::string CreateScenario(const ValidationScenario& scenario) override;
    bool UpdateScenario(const ValidationScenario& scenario) override;
    bool DeleteScenario(const std::string& scenario_id) override;
    std::optional<ValidationScenario> GetScenario(const std::string& scenario_id) override;
    std::vector<ValidationScenario> ListScenarios() override;
    std::vector<ValidationScenario> GetScenariosByType(ValidationScenarioType type) override;
    bool EnableScenario(const std::string& scenario_id) override;
    bool DisableScenario(const std::string& scenario_id) override;
    
    std::string ExecuteScenario(const std::string& scenario_id) override;
    std::string ExecuteScenarioAsync(const std::string& scenario_id) override;
    std::optional<ValidationResult> GetResult(const std::string& result_id) override;
    std::vector<ValidationResult> GetResults(const std::string& scenario_id = "") override;
    bool CancelExecution(const std::string& execution_id) override;
    
    std::vector<std::string> ExecuteAllScenarios() override;
    std::vector<std::string> ExecuteScenariosByType(ValidationScenarioType type) override;
    
    bool EstablishBaseline(const std::string& scenario_id) override;
    bool UpdateBaseline(const std::string& scenario_id) override;
    std::optional<BaselineMetrics> GetBaseline(const std::string& scenario_id) override;
    bool CompareToBaseline(const std::string& result_id) override;
    
    std::vector<std::string> DetectRegressions() override;
    bool IsRegression(const std::string& result_id) override;
    std::string ExplainRegression(const std::string& result_id) override;
    
    std::string GenerateReport(const std::string& result_id) override;
    std::string GenerateSummaryReport() override;
    std::string GenerateRegressionReport() override;
    
    ValidationStatistics GetStatistics() override;
    
private:
    std::unordered_map<std::string, ValidationScenario> scenarios_;
    std::unordered_map<std::string, ValidationResult> results_;
    std::unordered_map<std::string, BaselineMetrics> baselines_;
    bool initialized_ = false;
    
    bool ExecuteStep(ValidationStep& step);
    bool ValidateStepResult(const ValidationStep& step);
    bool CheckRequirements(const ValidationScenario& scenario);
    double CalculatePerformanceRegression(const ValidationResult& result, 
                                           const BaselineMetrics& baseline);
    std::string GenerateMarkdownReport(const ValidationResult& result);
};

// Global end-to-end validation
extern std::unique_ptr<IEndToEndValidation> g_end_to_end_validation;

// Initialize end-to-end validation
bool InitializeEndToEndValidation(const std::string& config_path);
void ShutdownEndToEndValidation();
bool IsEndToEndValidationEnabled();

// Scenario type helpers
std::string ValidationScenarioTypeToString(ValidationScenarioType type);
ValidationScenarioType ValidationScenarioTypeFromString(const std::string& str);

} // namespace Convergence
} // namespace RawrXD
