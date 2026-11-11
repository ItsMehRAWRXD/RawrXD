// Phase O.3/5: A/B Testing Framework
// RawrXD A/B Testing - Model comparison and evaluation

#pragma once

#include <cstring>
#include <vector>
#include <memory>
#include <unordered_map>
#include <chrono>
#include <functional>
#include <optional>

namespace RawrXD {
namespace ML {

// Traffic allocation strategy
enum class TrafficStrategy {
    RANDOM,         // Random assignment
    STICKY,         // Same user gets same variant
    WEIGHTED,       // Weighted by performance
    THOMPSON,       // Thompson sampling
    UCB             // Upper Confidence Bound
};

// Experiment status
enum class ABTestStatus {
    DRAFT,          // Configured but not started
    RUNNING,        // Active experiment
    PAUSED,         // Temporarily paused
    COMPLETED,      // Reached end condition
    STOPPED         // Manually stopped
};

// Variant definition
struct Variant {
    std::string id;
    std::string name;
    std::string description;
    std::string model_id;           // Model to use
    float traffic_percentage;       // 0.0 - 100.0
    std::unordered_map<std::string, std::string> config_overrides;
    bool control;                   // Is this the control variant?
    bool active;
    
    // Statistics
    uint64_t impressions;
    uint64_t conversions;
    double conversion_rate;
    double confidence_interval_lower;
    double confidence_interval_upper;
};

// Success metric definition
struct SuccessMetric {
    std::string name;
    std::string description;
    enum class Type {
        CONVERSION,     // Binary success/failure
        CONTINUOUS,     // Numeric value (e.g., latency)
        COUNT           // Count events
    } type;
    
    enum class Direction {
        HIGHER_IS_BETTER,
        LOWER_IS_BETTER
    } direction;
    
    double minimum_detectable_effect;  // Minimum improvement to detect
    double baseline_value;
    
    // For conversion metrics
    std::string conversion_event;
    std::optional<std::string> attribution_window;  // e.g., "24h"
};

// A/B test definition
struct ABTest {
    std::string id;
    std::string name;
    std::string description;
    std::string hypothesis;
    
    // Targeting
    std::vector<std::string> target_models;     // Which models to test
    std::vector<std::string> target_tenants;    // Which tenants (empty = all)
    std::vector<std::string> target_users;      // Specific users
    std::unordered_map<std::string, std::string> filters;  // Custom filters
    
    // Variants
    std::vector<Variant> variants;
    TrafficStrategy traffic_strategy;
    
    // Metrics
    SuccessMetric primary_metric;
    std::vector<SuccessMetric> secondary_metrics;
    
    // Configuration
    uint32_t min_sample_size;           // Minimum samples per variant
    uint32_t max_sample_size;           // Maximum samples (optional)
    double significance_level;          // Alpha (default 0.05)
    double statistical_power;           // 1 - Beta (default 0.80)
    std::chrono::hours min_duration;    // Minimum test duration
    std::chrono::hours max_duration;    // Maximum test duration (optional)
    
    // Status
    ABTestStatus status;
    std::chrono::system_clock::time_point created_at;
    std::chrono::system_clock::time_point started_at;
    std::chrono::system_clock::time_point ended_at;
    std::string created_by;
    std::string ended_by;
    
    // Results
    std::string winning_variant_id;
    bool statistically_significant;
    double p_value;
    double effect_size;
    std::string conclusion;
};

// Assignment result
struct AssignmentResult {
    std::string variant_id;
    std::string test_id;
    bool assigned;
    std::string reason;  // Why this variant was chosen
    std::string assignment_id;  // Unique ID for this assignment
};

// Event for tracking
struct ABTestEvent {
    std::string assignment_id;
    std::string test_id;
    std::string variant_id;
    std::string user_id;
    std::string session_id;
    std::string event_type;  // "impression", "conversion", "custom"
    std::chrono::system_clock::time_point timestamp;
    std::unordered_map<std::string, double> metrics;
    std::unordered_map<std::string, std::string> metadata;
};

// Statistical results
struct StatisticalResults {
    std::string variant_id;
    uint64_t sample_size;
    double mean;
    double std_dev;
    double confidence_interval_lower;
    double confidence_interval_upper;
    
    // Comparison to control
    double relative_lift;       // Percentage improvement
    double absolute_lift;
    double p_value;
    bool statistically_significant;
    
    // Bayesian metrics (if using Bayesian analysis)
    double probability_better;  // Probability this variant is better than control
    double expected_loss;       // Expected loss if this variant is chosen
};

// A/B testing manager
class IABTestingManager {
public:
    virtual ~IABTestingManager() = default;
    
    // Initialization
    virtual bool Initialize(const std::string& config_path) = 0;
    virtual void Shutdown() = 0;
    
    // Test lifecycle
    virtual std::string CreateTest(const ABTest& test) = 0;
    virtual bool StartTest(const std::string& test_id) = 0;
    virtual bool PauseTest(const std::string& test_id) = 0;
    virtual bool ResumeTest(const std::string& test_id) = 0;
    virtual bool StopTest(const std::string& test_id, const std::string& reason) = 0;
    virtual bool DeleteTest(const std::string& test_id) = 0;
    
    // Test queries
    virtual std::optional<ABTest> GetTest(const std::string& test_id) = 0;
    virtual std::vector<ABTest> ListTests(ABTestStatus status = ABTestStatus::RUNNING) = 0;
    virtual std::vector<ABTest> GetTestsForModel(const std::string& model_id) = 0;
    
    // Assignment
    virtual AssignmentResult AssignVariant(const std::string& test_id,
                                              const std::string& user_id,
                                              const std::unordered_map<std::string, std::string>& context = {}) = 0;
    virtual AssignmentResult AssignVariantAuto(const std::string& user_id,
                                                const std::string& model_id,
                                                const std::unordered_map<std::string, std::string>& context = {}) = 0;
    
    // Event tracking
    virtual bool TrackEvent(const ABTestEvent& event) = 0;
    virtual bool TrackImpression(const std::string& assignment_id) = 0;
    virtual bool TrackConversion(const std::string& assignment_id,
                                  const std::unordered_map<std::string, double>& metrics = {}) = 0;
    
    // Analysis
    virtual StatisticalResults AnalyzeVariant(const std::string& test_id,
                                               const std::string& variant_id) = 0;
    virtual std::vector<StatisticalResults> AnalyzeAllVariants(const std::string& test_id) = 0;
    virtual bool IsTestSignificant(const std::string& test_id) = 0;
    virtual std::optional<std::string> GetWinningVariant(const std::string& test_id) = 0;
    
    // Real-time monitoring
    virtual std::unordered_map<std::string, double> GetTestMetrics(const std::string& test_id) = 0;
    virtual bool CheckEarlyStopping(const std::string& test_id) = 0;
    
    // Reporting
    virtual bool GenerateReport(const std::string& test_id,
                                 const std::string& output_path,
                                 const std::string& format = "html") = 0;
};

// Local A/B testing implementation
class LocalABTestingManager : public IABTestingManager {
public:
    LocalABTestingManager();
    ~LocalABTestingManager() override;
    
    bool Initialize(const std::string& config_path) override;
    void Shutdown() override;
    
    std::string CreateTest(const ABTest& test) override;
    bool StartTest(const std::string& test_id) override;
    bool PauseTest(const std::string& test_id) override;
    bool ResumeTest(const std::string& test_id) override;
    bool StopTest(const std::string& test_id, const std::string& reason) override;
    bool DeleteTest(const std::string& test_id) override;
    
    std::optional<ABTest> GetTest(const std::string& test_id) override;
    std::vector<ABTest> ListTests(ABTestStatus status = ABTestStatus::RUNNING) override;
    std::vector<ABTest> GetTestsForModel(const std::string& model_id) override;
    
    AssignmentResult AssignVariant(const std::string& test_id,
                                    const std::string& user_id,
                                    const std::unordered_map<std::string, std::string>& context = {}) override;
    AssignmentResult AssignVariantAuto(const std::string& user_id,
                                        const std::string& model_id,
                                        const std::unordered_map<std::string, std::string>& context = {}) override;
    
    bool TrackEvent(const ABTestEvent& event) override;
    bool TrackImpression(const std::string& assignment_id) override;
    bool TrackConversion(const std::string& assignment_id,
                         const std::unordered_map<std::string, double>& metrics = {}) override;
    
    StatisticalResults AnalyzeVariant(const std::string& test_id,
                                       const std::string& variant_id) override;
    std::vector<StatisticalResults> AnalyzeAllVariants(const std::string& test_id) override;
    bool IsTestSignificant(const std::string& test_id) override;
    std::optional<std::string> GetWinningVariant(const std::string& test_id) override;
    
    std::unordered_map<std::string, double> GetTestMetrics(const std::string& test_id) override;
    bool CheckEarlyStopping(const std::string& test_id) override;
    
    bool GenerateReport(const std::string& test_id,
                         const std::string& output_path,
                         const std::string& format = "html") override;
    
private:
    std::unordered_map<std::string, ABTest> tests_;
    std::unordered_map<std::string, std::vector<ABTestEvent>> events_;
    std::unordered_map<std::string, std::string> user_assignments_;  // user+test -> variant
    bool initialized_ = false;
    
    std::string GenerateAssignmentId();
    Variant* SelectVariant(const std::string& test_id, const std::string& user_id);
    double CalculatePValue(const std::vector<double>& control, const std::vector<double>& treatment);
    double CalculateConfidenceInterval(const std::vector<double>& data, double confidence);
};

// Statistical utilities
namespace ABTestStatistics {
    // Sample size calculation
    uint32_t CalculateRequiredSampleSize(double baseline_rate,
                                          double minimum_detectable_effect,
                                          double significance_level = 0.05,
                                          double power = 0.80);
    
    // Confidence interval
    std::pair<double, double> CalculateConfidenceInterval(const std::vector<double>& data,
                                                           double confidence = 0.95);
    
    // Two-sample t-test
    double TwoSampleTTest(const std::vector<double>& sample1,
                           const std::vector<double>& sample2);
    
    // Chi-square test for proportions
    double ChiSquareTest(uint64_t control_success, uint64_t control_total,
                         uint64_t treatment_success, uint64_t treatment_total);
    
    // Bayesian analysis
    struct BayesianResult {
        double probability_better;
        double expected_lift;
        double credible_interval_lower;
        double credible_interval_upper;
    };
    BayesianResult BayesianAnalysis(const std::vector<double>& control,
                                     const std::vector<double>& treatment);
    
    // Sequential testing (optional stopping)
    bool CheckSequentialBoundaries(const std::vector<double>& control,
                                    const std::vector<double>& treatment,
                                    double significance_level);
    
    // Multiple testing correction
    double BonferroniCorrection(double p_value, uint32_t num_tests);
    double BenjaminiHochbergCorrection(std::vector<double>& p_values);
}

// Guardrails
struct GuardrailConfig {
    bool enabled = true;
    double max_degradation_percent = 5.0;  // Stop if variant is 5% worse
    uint32_t min_samples_before_check = 100;
    std::vector<std::string> critical_metrics;  // Metrics that trigger immediate stop
};

class ABTestGuardrails {
public:
    explicit ABTestGuardrails(const GuardrailConfig& config);
    
    bool CheckGuardrails(const std::string& test_id,
                         const std::vector<ABTestEvent>& events);
    bool ShouldStop(const std::string& test_id,
                    const std::string& reason);
    
private:
    GuardrailConfig config_;
};

// Global A/B testing manager
extern std::unique_ptr<IABTestingManager> g_ab_testing_manager;

// Initialize A/B testing
bool InitializeABTesting(const std::string& config_path);
void ShutdownABTesting();
bool IsABTestingEnabled();

} // namespace ML
} // namespace RawrXD
