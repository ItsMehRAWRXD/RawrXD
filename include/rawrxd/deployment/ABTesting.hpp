#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <random>
#include <mutex>
#include <chrono>

namespace rawrxd {
namespace deployment {

// A/B test configuration
struct ABTestConfig {
    std::string testId;
    std::string testName;
    std::string description;
    
    // Traffic split (must sum to 1.0)
    struct Variant {
        std::string variantId;
        std::string name;
        float trafficPercentage = 0.5f;
        std::string modelPath;
        std::map<std::string, std::string> parameters;
    };
    std::vector<Variant> variants;
    
    // Targeting
    std::vector<std::string> targetUsers; // Empty = all users
    std::vector<std::string> targetRegions;
    float trafficAllocation = 1.0f; // % of traffic in test
    
    // Duration
    std::chrono::system_clock::time_point startTime;
    std::chrono::system_clock::time_point endTime;
    int minSampleSize = 1000;
    
    // Success metrics
    std::vector<std::string> primaryMetrics;
    std::vector<std::string> secondaryMetrics;
    float minDetectableEffect = 0.05f; // 5% relative difference
    float statisticalPower = 0.8f;
    float significanceLevel = 0.05f;
};

// Experiment result
struct ExperimentResult {
    std::string testId;
    std::string variantId;
    
    // Sample size
    int numSamples = 0;
    
    // Metrics
    struct MetricStats {
        std::string metricName;
        double mean = 0.0;
        double stdDev = 0.0;
        double min = 0.0;
        double max = 0.0;
        double p50 = 0.0;
        double p95 = 0.0;
        double p99 = 0.0;
    };
    std::map<std::string, MetricStats> metrics;
    
    // Statistical test results
    struct StatisticalTest {
        std::string metricName;
        double controlMean = 0.0;
        double treatmentMean = 0.0;
        double relativeDifference = 0.0;
        double pValue = 1.0;
        bool isSignificant = false;
        double confidenceIntervalLower = 0.0;
        double confidenceIntervalUpper = 0.0;
    };
    std::vector<StatisticalTest> testResults;
    
    // Overall winner
    std::string winningVariant;
    bool testConclusive = false;
};

// User assignment
struct UserAssignment {
    std::string userId;
    std::string testId;
    std::string variantId;
    std::chrono::system_clock::time_point assignmentTime;
    bool sticky = true; // Keep user in same variant
};

// A/B testing manager
class ABTestingManager {
public:
    ABTestingManager();
    ~ABTestingManager();

    // Initialize
    bool Initialize(const std::string& storagePath = "ab_tests");
    
    // Create test
    bool CreateTest(const ABTestConfig& config);
    
    // Start test
    bool StartTest(const std::string& testId);
    
    // Stop test
    bool StopTest(const std::string& testId);
    
    // Get variant for user
    std::string GetVariantForUser(const std::string& testId, const std::string& userId);
    
    // Record event
    void RecordEvent(const std::string& testId, const std::string& variantId,
                     const std::string& userId, const std::string& metricName,
                     double value);
    
    // Get test results
    ExperimentResult GetTestResults(const std::string& testId);
    
    // Get all active tests
    std::vector<ABTestConfig> GetActiveTests();
    
    // Get test status
    enum class TestStatus {
        DRAFT,
        RUNNING,
        PAUSED,
        COMPLETED
    };
    TestStatus GetTestStatus(const std::string& testId);
    
    // Generate report
    std::string GenerateReport(const std::string& testId);
    
    // Auto-stop tests that have reached significance
    void CheckAndAutoStopTests();

private:
    std::map<std::string, ABTestConfig> tests_;
    std::map<std::string, TestStatus> testStatus_;
    std::map<std::string, std::map<std::string, UserAssignment>> userAssignments_;
    std::map<std::string, std::map<std::string, std::vector<double>>> metricData_;
    
    mutable std::mutex mutex_;
    std::string storagePath_;
    std::mt19937 rng_;
    
    void SaveTest(const ABTestConfig& config);
    void LoadTests();
    std::string HashUserToVariant(const std::string& userId, const std::vector<ABTestConfig::Variant>& variants);
    double ComputePValue(const std::vector<double>& control, const std::vector<double>& treatment);
    double ComputeConfidenceInterval(const std::vector<double>& data, double confidenceLevel, bool upper);
};

// Feature flags
class FeatureFlags {
public:
    struct Flag {
        std::string name;
        bool enabled = false;
        std::vector<std::string> enabledForUsers;
        std::vector<std::string> enabledForRegions;
        float rolloutPercentage = 0.0f;
        std::chrono::system_clock::time_point createdAt;
        std::chrono::system_clock::time_point updatedAt;
    };
    
    static FeatureFlags& GetInstance();
    
    // Initialize
    bool Initialize(const std::string& configPath = "feature_flags.json");
    
    // Check if feature is enabled
    bool IsEnabled(const std::string& flagName, const std::string& userId = "",
                   const std::string& region = "");
    
    // Set flag
    void SetFlag(const std::string& flagName, bool enabled);
    void SetFlagRollout(const std::string& flagName, float percentage);
    void EnableForUser(const std::string& flagName, const std::string& userId);
    void EnableForRegion(const std::string& flagName, const std::string& region);
    
    // Get all flags
    std::vector<Flag> GetAllFlags();
    
    // Save/Load
    void SaveToFile();
    void LoadFromFile();

private:
    FeatureFlags() = default;
    ~FeatureFlags() = default;
    FeatureFlags(const FeatureFlags&) = delete;
    FeatureFlags& operator=(const FeatureFlags&) = delete;
    
    std::map<std::string, Flag> flags_;
    std::string configPath_;
    mutable std::mutex mutex_;
    std::mt19937 rng_;
};

// Canary deployment
class CanaryDeployment {
public:
    struct CanaryConfig {
        std::string deploymentId;
        std::string newModelPath;
        std::string baselineModelPath;
        float canaryPercentage = 5.0f; // Start with 5%
        float maxCanaryPercentage = 50.0f;
        float autoPromotionThreshold = 0.99f; // Error rate threshold
        float autoRollbackThreshold = 0.95f;
        int minSamples = 100;
        std::chrono::minutes evaluationInterval{5};
    };
    
    struct CanaryMetrics {
        float errorRate = 0.0f;
        float latencyP95 = 0.0f;
        float latencyP99 = 0.0f;
        int totalRequests = 0;
        int errorCount = 0;
    };
    
    CanaryDeployment();
    ~CanaryDeployment();
    
    // Start canary deployment
    bool Start(const CanaryConfig& config);
    
    // Check if request should use canary
    bool ShouldUseCanary(const std::string& requestId);
    
    // Record canary metrics
    void RecordCanaryMetrics(const std::string& requestId, bool success, float latencyMs);
    void RecordBaselineMetrics(const std::string& requestId, bool success, float latencyMs);
    
    // Evaluate and potentially promote/rollback
    void Evaluate();
    
    // Manual actions
    void Promote();
    void Rollback();
    
    // Get status
    enum class Status {
        NOT_STARTED,
        RUNNING,
        PROMOTED,
        ROLLED_BACK
    };
    Status GetStatus() const;
    
    // Get current metrics
    CanaryMetrics GetCanaryMetrics() const;
    CanaryMetrics GetBaselineMetrics() const;

private:
    CanaryConfig config_;
    Status status_ = Status::NOT_STARTED;
    
    std::map<std::string, bool> canaryAssignments_;
    std::vector<float> canaryLatencies_;
    std::vector<float> baselineLatencies_;
    int canaryErrors_ = 0;
    int canaryTotal_ = 0;
    int baselineErrors_ = 0;
    int baselineTotal_ = 0;
    
    mutable std::mutex mutex_;
    std::thread evaluationThread_;
    std::atomic<bool> running_{false};
    
    void EvaluationLoop();
    bool ShouldPromote();
    bool ShouldRollback();
};

} // namespace deployment
} // namespace rawrxd
