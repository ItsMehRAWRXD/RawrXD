// Phase V.2/5: Reflection & Evaluation Engine
// RawrXD Reflection Engine - Continuous evaluation and optimization loop

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

// Reflection event types
enum class ReflectionEventType {
    EXECUTION_COMPLETE,
    BENCHMARK_RESULT,
    ERROR_OCCURRED,
    PERFORMANCE_ANOMALY,
    USER_FEEDBACK,
    SYSTEM_ALERT,
    GOAL_ACHIEVED,
    GOAL_FAILED
};

// Reflection event
struct ReflectionEvent {
    std::string event_id;
    ReflectionEventType type;
    std::chrono::system_clock::time_point timestamp;
    
    // Context
    std::string task_id;
    std::string task_type;
    std::string agent_id;
    std::unordered_map<std::string, std::string> context;
    
    // Outcome
    bool success;
    double performance_score;
    std::chrono::milliseconds duration;
    std::string error_message;
    
    // Metrics
    std::unordered_map<std::string, double> metrics;
    std::vector<std::string> observations;
};

// Analysis result
struct AnalysisResult {
    std::string analysis_id;
    std::string event_id;
    std::chrono::system_clock::time_point analyzed_at;
    
    // Findings
    std::vector<std::string> findings;
    std::vector<std::string> root_causes;
    std::vector<std::string> contributing_factors;
    
    // Classification
    bool is_regression;
    bool is_improvement;
    double severity;  // 0.0 to 1.0
    std::string category;
    
    // Comparison
    double deviation_from_baseline;
    double deviation_from_expected;
    std::vector<std::string> similar_historical_events;
};

// Optimization proposal
struct OptimizationProposal {
    std::string proposal_id;
    std::string analysis_id;
    std::chrono::system_clock::time_point proposed_at;
    
    // Proposal details
    std::string target_component;
    std::string optimization_type;
    std::string description;
    
    // Expected impact
    double expected_improvement;
    std::vector<std::string> affected_metrics;
    std::vector<std::string> risks;
    
    // Implementation
    std::string implementation_plan;
    std::chrono::seconds estimated_duration;
    bool requires_restart;
    bool can_rollback;
    
    // Validation
    std::vector<std::string> validation_criteria;
    std::string rollback_procedure;
    
    // State
    enum class State {
        PROPOSED,
        APPROVED,
        REJECTED,
        IMPLEMENTING,
        VALIDATING,
        COMPLETED,
        ROLLED_BACK
    } state;
};

// Regression detection
struct Regression {
    std::string regression_id;
    std::string metric_name;
    std::chrono::system_clock::time_point detected_at;
    
    // Details
    double baseline_value;
    double current_value;
    double percentage_change;
    
    // Severity
    enum class Severity {
        LOW,
        MEDIUM,
        HIGH,
        CRITICAL
    } severity;
    
    // Attribution
    std::string suspected_commit;
    std::string suspected_component;
    std::vector<std::string> recent_changes;
    
    // Status
    bool is_confirmed;
    bool is_resolved;
    std::string resolution;
};

// Reflection engine interface
class IReflectionEngine {
public:
    virtual ~IReflectionEngine() = default;
    
    // Initialization
    virtual bool Initialize(const std::string& config_path) = 0;
    virtual void Shutdown() = 0;
    
    // Event recording
    virtual std::string RecordEvent(const ReflectionEvent& event) = 0;
    virtual std::vector<ReflectionEvent> GetEvents(
        ReflectionEventType type = ReflectionEventType::EXECUTION_COMPLETE,
        std::chrono::hours lookback = std::chrono::hours(24)) = 0;
    virtual std::vector<ReflectionEvent> GetEventsForTask(const std::string& task_id) = 0;
    
    // Analysis
    virtual std::string AnalyzeEvent(const std::string& event_id) = 0;
    virtual std::optional<AnalysisResult> GetAnalysis(const std::string& analysis_id) = 0;
    virtual std::vector<AnalysisResult> GetAnalysesForEvent(const std::string& event_id) = 0;
    
    // Regression detection
    virtual std::vector<Regression> DetectRegressions() = 0;
    virtual std::string CreateRegression(const Regression& regression) = 0;
    virtual bool ConfirmRegression(const std::string& regression_id) = 0;
    virtual bool ResolveRegression(const std::string& regression_id, const std::string& resolution) = 0;
    virtual std::vector<Regression> GetActiveRegressions() = 0;
    
    // Optimization
    virtual std::vector<OptimizationProposal> GenerateProposals() = 0;
    virtual std::string SubmitProposal(const OptimizationProposal& proposal) = 0;
    virtual bool ApproveProposal(const std::string& proposal_id) = 0;
    virtual bool RejectProposal(const std::string& proposal_id, const std::string& reason) = 0;
    virtual bool ImplementProposal(const std::string& proposal_id) = 0;
    virtual bool ValidateProposal(const std::string& proposal_id) = 0;
    virtual bool RollbackProposal(const std::string& proposal_id) = 0;
    
    // Explanation
    virtual std::string ExplainEvent(const std::string& event_id) = 0;
    virtual std::string ExplainPerformance(const std::string& metric_name) = 0;
    virtual std::vector<std::string> GetRecommendations() = 0;
    
    // Continuous reflection
    virtual bool EnableContinuousReflection() = 0;
    virtual bool DisableContinuousReflection() = 0;
    virtual bool IsContinuousReflectionEnabled() = 0;
    virtual void SetReflectionInterval(std::chrono::seconds interval) = 0;
    
    // Statistics
    virtual struct ReflectionStatistics {
        uint64_t total_events_recorded;
        uint64_t total_analyses_performed;
        uint32_t active_regressions;
        uint32_t optimizations_proposed;
        uint32_t optimizations_implemented;
        uint32_t optimizations_rolled_back;
        double average_analysis_time_ms;
        double regression_detection_rate;
        double optimization_success_rate;
    } GetStatistics() = 0;
};

// Local reflection engine
class LocalReflectionEngine : public IReflectionEngine {
public:
    LocalReflectionEngine();
    ~LocalReflectionEngine() override;
    
    bool Initialize(const std::string& config_path) override;
    void Shutdown() override;
    
    std::string RecordEvent(const ReflectionEvent& event) override;
    std::vector<ReflectionEvent> GetEvents(
        ReflectionEventType type = ReflectionEventType::EXECUTION_COMPLETE,
        std::chrono::hours lookback = std::chrono::hours(24)) override;
    std::vector<ReflectionEvent> GetEventsForTask(const std::string& task_id) override;
    
    std::string AnalyzeEvent(const std::string& event_id) override;
    std::optional<AnalysisResult> GetAnalysis(const std::string& analysis_id) override;
    std::vector<AnalysisResult> GetAnalysesForEvent(const std::string& event_id) override;
    
    std::vector<Regression> DetectRegressions() override;
    std::string CreateRegression(const Regression& regression) override;
    bool ConfirmRegression(const std::string& regression_id) override;
    bool ResolveRegression(const std::string& regression_id, const std::string& resolution) override;
    std::vector<Regression> GetActiveRegressions() override;
    
    std::vector<OptimizationProposal> GenerateProposals() override;
    std::string SubmitProposal(const OptimizationProposal& proposal) override;
    bool ApproveProposal(const std::string& proposal_id) override;
    bool RejectProposal(const std::string& proposal_id, const std::string& reason) override;
    bool ImplementProposal(const std::string& proposal_id) override;
    bool ValidateProposal(const std::string& proposal_id) override;
    bool RollbackProposal(const std::string& proposal_id) override;
    
    std::string ExplainEvent(const std::string& event_id) override;
    std::string ExplainPerformance(const std::string& metric_name) override;
    std::vector<std::string> GetRecommendations() override;
    
    bool EnableContinuousReflection() override;
    bool DisableContinuousReflection() override;
    bool IsContinuousReflectionEnabled() override;
    void SetReflectionInterval(std::chrono::seconds interval) override;
    
    ReflectionStatistics GetStatistics() override;
    
private:
    std::unordered_map<std::string, ReflectionEvent> events_;
    std::unordered_map<std::string, AnalysisResult> analyses_;
    std::unordered_map<std::string, Regression> regressions_;
    std::unordered_map<std::string, OptimizationProposal> proposals_;
    bool continuous_reflection_enabled_ = false;
    std::chrono::seconds reflection_interval_ = std::chrono::seconds(60);
    bool initialized_ = false;
    
    AnalysisResult PerformAnalysis(const ReflectionEvent& event);
    std::vector<std::string> IdentifyRootCauses(const ReflectionEvent& event);
    double CalculateDeviation(const std::string& metric, double current, double baseline);
    bool CheckForRegression(const std::string& metric_name, double current_value);
    std::vector<OptimizationProposal> GenerateOptimizationProposals(const AnalysisResult& analysis);
    bool ValidateImplementation(const OptimizationProposal& proposal);
};

// Global reflection engine
extern std::unique_ptr<IReflectionEngine> g_reflection_engine;

// Initialize reflection engine
bool InitializeReflectionEngine(const std::string& config_path);
void ShutdownReflectionEngine();
bool IsReflectionEngineEnabled();

// Event type helpers
std::string ReflectionEventTypeToString(ReflectionEventType type);
ReflectionEventType ReflectionEventTypeFromString(const std::string& str);

} // namespace MetaCognition
} // namespace RawrXD
