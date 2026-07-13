// RawrXD A/B Testing Framework
// Phase V.3: A/B testing and experimentation platform
// Enables data-driven feature rollouts and experimentation

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <chrono>
#include <functional>
#include <random>
#include <optional>

namespace RawrXD {
namespace Monitoring {

// Experiment status
enum class ExperimentStatus {
    DRAFT,          // Being configured
    SCHEDULED,      // Scheduled to start
    RUNNING,        // Active and collecting data
    PAUSED,         // Temporarily paused
    COMPLETED,      // Finished successfully
    CANCELLED       // Cancelled before completion
};

// Experiment type
enum class ExperimentType {
    AB_TEST,        // Classic A/B test (control vs variant)
    MULTIVARIATE,   // Multiple variants
    SPLIT_URL,      // Different URLs
    FEATURE_FLAG,   // Feature toggle with metrics
    CANARY          // Gradual rollout
};

// Traffic allocation
struct TrafficAllocation {
    std::string variantId;
    double percentage;  // 0.0 - 100.0
    uint64_t userCount{0};
};

// Variant definition
struct Variant {
    std::string id;
    std::string name;
    std::string description;
    std::map<std::string, std::string> config;  // Feature configuration
    bool isControl{false};
    TrafficAllocation allocation;
};

// Success metric
struct SuccessMetric {
    std::string name;
    std::string description;
    std::string eventName;  // Event that triggers this metric
    std::string aggregation;  // "count", "sum", "average", "unique"
    double minimumDetectableEffect{0.05};  // Minimum improvement to detect
    bool isPrimary{false};  // Primary metric for determining winner
};

// Guardrail metric
struct GuardrailMetric {
    std::string name;
    std::string description;
    std::string eventName;
    double maxValue;  // Alert if exceeded
    double minValue;  // Alert if below
};

// Targeting rule
struct TargetingRule {
    std::string attribute;  // e.g., "user_type", "region"
    std::string operator_;    // "equals", "contains", "gt", "lt"
    std::string value;
    bool negate{false};     // If true, negate the condition
};

// Experiment audience
struct ExperimentAudience {
    std::vector<TargetingRule> includeRules;
    std::vector<TargetingRule> excludeRules;
    uint32_t trafficPercentage{100};  // Percentage of matching users to include
    std::optional<uint32_t> maxUsers;  // Maximum users to enroll
};

// Experiment schedule
struct ExperimentSchedule {
    std::chrono::system_clock::time_point startTime;
    std::optional<std::chrono::system_clock::time_point> endTime;
    std::optional<std::chrono::hours> minDuration;  // Minimum time before declaring winner
    std::optional<std::chrono::hours> maxDuration;  // Auto-stop after this time
};

// Experiment definition
struct Experiment {
    std::string id;
    std::string name;
    std::string description;
    std::string hypothesis;
    ExperimentType type;
    ExperimentStatus status;
    ExperimentAudience audience;
    ExperimentSchedule schedule;
    std::vector<Variant> variants;
    std::vector<SuccessMetric> successMetrics;
    std::vector<GuardrailMetric> guardrailMetrics;
    double confidenceLevel{0.95};  // Statistical confidence required
    std::map<std::string, std::string> metadata;
    std::chrono::system_clock::time_point createdAt;
    std::chrono::system_clock::time_point updatedAt;
};

// User assignment
struct UserAssignment {
    std::string experimentId;
    std::string variantId;
    std::string userId;
    std::chrono::system_clock::time_point assignedAt;
    bool isEnrolled{true};
};

// Metric result
struct MetricResult {
    std::string metricName;
    std::string variantId;
    double value;
    double confidenceIntervalLower;
    double confidenceIntervalUpper;
    uint64_t sampleSize;
    double pValue;
    bool isSignificant;
};

// Experiment results
struct ExperimentResults {
    std::string experimentId;
    std::chrono::system_clock::time_point generatedAt;
    
    struct VariantResult {
        std::string variantId;
        std::string variantName;
        uint64_t usersEnrolled;
        uint64_t usersConverted;
        double conversionRate;
        std::map<std::string, double> metricValues;
    };
    std::vector<VariantResult> variantResults;
    
    std::vector<MetricResult> metricComparisons;
    
    std::string winningVariantId;
    bool hasWinner{false};
    double winnerConfidence{0.0};
    
    std::string recommendation;  // "rollout", "rollback", "continue", "inconclusive"
    std::chrono::hours duration;
    bool isStatisticallySignificant{false};
};

// Sample size calculation
struct SampleSizeCalculation {
    uint64_t requiredPerVariant;
    uint64_t totalRequired;
    double baselineConversionRate;
    double minimumDetectableEffect;
    double statisticalPower{0.8};
    double significanceLevel{0.05};
    std::chrono::hours estimatedDuration;
};

// A/B testing framework
class ABTestingFramework {
public:
    ABTestingFramework();
    ~ABTestingFramework();
    
    // Initialization
    bool initialize(const std::string& configPath);
    bool shutdown();
    bool isRunning() const { return running_; }
    
    // Experiment management
    std::string createExperiment(const Experiment& experiment);
    bool updateExperiment(const std::string& experimentId, const Experiment& experiment);
    bool deleteExperiment(const std::string& experimentId);
    Experiment getExperiment(const std::string& experimentId) const;
    std::vector<Experiment> listExperiments() const;
    std::vector<Experiment> listExperimentsByStatus(ExperimentStatus status) const;
    
    // Experiment lifecycle
    bool startExperiment(const std::string& experimentId);
    bool pauseExperiment(const std::string& experimentId);
    bool resumeExperiment(const std::string& experimentId);
    bool stopExperiment(const std::string& experimentId);
    bool cancelExperiment(const std::string& experimentId);
    
    // User assignment
    std::optional<UserAssignment> assignUser(const std::string& experimentId, 
                                             const std::string& userId,
                                             const std::map<std::string, std::string>& userAttributes);
    std::optional<std::string> getUserVariant(const std::string& experimentId, 
                                              const std::string& userId) const;
    bool isUserEnrolled(const std::string& experimentId, const std::string& userId) const;
    bool unenrollUser(const std::string& experimentId, const std::string& userId);
    
    // Feature flag evaluation
    bool isFeatureEnabled(const std::string& featureKey, 
                         const std::string& userId,
                         const std::map<std::string, std::string>& userAttributes = {});
    std::map<std::string, std::string> getFeatureConfig(const std::string& featureKey,
                                                       const std::string& userId);
    
    // Event tracking for experiments
    void trackEvent(const std::string& experimentId,
                   const std::string& userId,
                   const std::string& eventName,
                   const std::map<std::string, double>& metrics = {});
    void trackConversion(const std::string& experimentId, const std::string& userId);
    void trackRevenue(const std::string& experimentId, const std::string& userId, double amount);
    
    // Results and analysis
    ExperimentResults getResults(const std::string& experimentId) const;
    ExperimentResults getResultsRealtime(const std::string& experimentId) const;
    bool exportResults(const std::string& experimentId, const std::string& outputPath) const;
    
    // Statistical calculations
    SampleSizeCalculation calculateRequiredSampleSize(
        double baselineRate,
        double minimumDetectableEffect,
        double statisticalPower = 0.8,
        double significanceLevel = 0.05) const;
    
    double calculatePValue(const std::vector<double>& controlValues,
                          const std::vector<double>& treatmentValues) const;
    double calculateConfidenceInterval(const std::vector<double>& values,
                                       double confidenceLevel) const;
    bool isStatisticallySignificant(const MetricResult& result) const;
    
    // Sample size validation
    bool hasEnoughSamples(const std::string& experimentId) const;
    SampleSizeCalculation getSampleSizeStatus(const std::string& experimentId) const;
    
    // Guardrail monitoring
    std::vector<std::string> checkGuardrails(const std::string& experimentId) const;
    bool areGuardrailsViolated(const std::string& experimentId) const;
    
    // Auto-decision
    void enableAutoDecision(const std::string& experimentId,
                           std::chrono::hours minDuration,
                           double confidenceThreshold);
    bool shouldAutoStop(const std::string& experimentId) const;
    
    // Feature flags (simplified experiments)
    std::string createFeatureFlag(const std::string& name,
                                 const std::map<std::string, std::string>& config,
                                 double rolloutPercentage = 0.0);
    bool updateFeatureFlagRollout(const std::string& flagId, double percentage);
    bool deleteFeatureFlag(const std::string& flagId);
    std::vector<Experiment> listFeatureFlags() const;
    
    // Progress tracking
    struct ExperimentProgress {
        std::string experimentId;
        uint64_t usersEnrolled;
        uint64_t usersNeeded;
        double progressPercentage;
        std::chrono::hours elapsed;
        std::chrono::hours estimatedRemaining;
        bool isComplete;
    };
    ExperimentProgress getProgress(const std::string& experimentId) const;
    
    // Statistics
    struct ABTestStats {
        uint32_t totalExperiments;
        uint32_t runningExperiments;
        uint32_t completedExperiments;
        uint32_t totalUsersEnrolled;
        uint32_t totalConversions;
        double averageConversionRate;
    };
    ABTestStats getStats() const;

private:
    std::string generateExperimentId() const;
    std::string hashUserToVariant(const std::string& experimentId, 
                                 const std::string& userId,
                                 const std::vector<Variant>& variants) const;
    bool matchesTargeting(const std::map<std::string, std::string>& userAttributes,
                         const std::vector<TargetingRule>& rules) const;
    bool evaluateRule(const std::map<std::string, std::string>& userAttributes,
                     const TargetingRule& rule) const;
    void checkExperimentSchedule();
    void autoStopExperiments();
    
    mutable std::mutex mutex_;
    std::map<std::string, Experiment> experiments_;
    std::map<std::string, std::map<std::string, UserAssignment>> userAssignments_;  // expId -> userId -> assignment
    std::map<std::string, std::map<std::string, std::vector<double>>> metricData_;  // expId -> metricName -> values
    
    std::atomic<bool> running_{false};
    std::thread schedulerThread_;
    std::mt19937 rng_{std::random_device{}()};
};

// Experiment builder for fluent API
class ExperimentBuilder {
public:
    ExperimentBuilder(ABTestingFramework* framework);
    
    ExperimentBuilder& withName(const std::string& name);
    ExperimentBuilder& withDescription(const std::string& description);
    ExperimentBuilder& withHypothesis(const std::string& hypothesis);
    ExperimentBuilder& ofType(ExperimentType type);
    
    ExperimentBuilder& withVariant(const Variant& variant);
    ExperimentBuilder& withControl(const std::string& name);
    ExperimentBuilder& withTreatment(const std::string& name);
    
    ExperimentBuilder& targeting(const std::vector<TargetingRule>& rules);
    ExperimentBuilder& excluding(const std::vector<TargetingRule>& rules);
    ExperimentBuilder& withTrafficPercentage(uint32_t percentage);
    
    ExperimentBuilder& measuring(const SuccessMetric& metric);
    ExperimentBuilder& withPrimaryMetric(const std::string& eventName);
    ExperimentBuilder& guarding(const GuardrailMetric& metric);
    
    ExperimentBuilder& startingAt(std::chrono::system_clock::time_point time);
    ExperimentBuilder& endingAt(std::chrono::system_clock::time_point time);
    ExperimentBuilder& forDuration(std::chrono::hours duration);
    
    ExperimentBuilder& withConfidence(double level);
    
    std::string create();
    
private:
    ABTestingFramework* framework_;
    Experiment experiment_;
};

// Feature flag builder
class FeatureFlagBuilder {
public:
    FeatureFlagBuilder(ABTestingFramework* framework);
    
    FeatureFlagBuilder& withName(const std::string& name);
    FeatureFlagBuilder& withConfig(const std::map<std::string, std::string>& config);
    FeatureFlagBuilder& rolledOutTo(double percentage);
    FeatureFlagBuilder& targeting(const std::vector<TargetingRule>& rules);
    
    std::string create();
    
private:
    ABTestingFramework* framework_;
    Experiment flag_;
};

} // namespace Monitoring
} // namespace RawrXD
