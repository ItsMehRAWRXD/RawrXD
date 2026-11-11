#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <mutex>
#include <chrono>
#include <random>
#include <functional>

namespace rawrxd {
namespace serving {

// A/B test configuration
struct ABTestConfig {
    std::string test_id;
    std::string model_id;
    std::string description;
    
    // Traffic split (must sum to 1.0)
    struct Variant {
        std::string version_id;
        float traffic_percentage;  // 0.0 - 1.0
        std::unordered_map<std::string, std::string> metadata;
    };
    std::vector<Variant> variants;
    
    // Test parameters
    std::chrono::system_clock::time_point start_time;
    std::chrono::system_clock::time_point end_time;
    size_t min_samples = 1000;
    float confidence_level = 0.95f;
    
    // Status
    enum class Status {
        PENDING,
        RUNNING,
        PAUSED,
        COMPLETED,
        CANCELLED
    };
    Status status = Status::PENDING;
};

// A/B test results
struct ABTestResults {
    std::string test_id;
    std::chrono::system_clock::time_point completed_at;
    
    struct VariantResult {
        std::string version_id;
        size_t samples;
        float mean_latency_ms;
        float p95_latency_ms;
        float p99_latency_ms;
        float error_rate;
        float throughput_qps;
        float user_satisfaction_score;
        
        // Statistical significance
        bool is_significant;
        float p_value;
        float confidence_interval_low;
        float confidence_interval_high;
    };
    std::vector<VariantResult> variant_results;
    
    // Winner
    std::string winning_version;
    float improvement_percentage;
    bool is_statistically_significant;
};

// Traffic splitting strategy
enum class TrafficSplitStrategy {
    RANDOM,           // Random assignment
    USER_ID_HASH,     // Consistent hashing by user ID
    SESSION_HASH,     // Consistent hashing by session
    GEOGRAPHIC,       // Geographic-based splitting
    TIME_BASED,       // Time-window based
    CUSTOM            // Custom function
};

// A/B testing framework
class ABTestingFramework {
public:
    ABTestingFramework();
    ~ABTestingFramework();
    
    // Test management
    std::string createTest(const ABTestConfig& config);
    bool startTest(const std::string& test_id);
    bool pauseTest(const std::string& test_id);
    bool resumeTest(const std::string& test_id);
    bool stopTest(const std::string& test_id);
    bool deleteTest(const std::string& test_id);
    
    std::optional<ABTestConfig> getTest(const std::string& test_id) const;
    std::vector<ABTestConfig> listTests(const std::string& model_id = "") const;
    std::vector<ABTestConfig> listActiveTests() const;
    
    // Traffic assignment
    std::string assignVariant(const std::string& test_id, 
                              const std::string& user_id = "",
                              const std::string& session_id = "");
    
    // Record metrics
    void recordLatency(const std::string& test_id, 
                      const std::string& variant_id,
                      float latency_ms);
    void recordSuccess(const std::string& test_id, 
                      const std::string& variant_id);
    void recordError(const std::string& test_id, 
                    const std::string& variant_id);
    void recordUserFeedback(const std::string& test_id,
                           const std::string& variant_id,
                           float satisfaction_score);
    
    // Results and analysis
    ABTestResults getResults(const std::string& test_id);
    bool isTestComplete(const std::string& test_id);
    std::string getRecommendation(const std::string& test_id);
    
    // Traffic splitting configuration
    void setTrafficSplitStrategy(TrafficSplitStrategy strategy);
    void setCustomSplitter(std::function<std::string(const std::string&, 
                                                      const std::vector<ABTestConfig::Variant>&)> splitter);
    
    // Statistics
    struct Stats {
        size_t total_tests;
        size_t active_tests;
        size_t completed_tests;
        size_t total_assignments;
        size_t total_samples;
    };
    Stats getStats() const;
    
    // Export/Import
    bool exportResults(const std::string& test_id, const std::string& path);
    bool exportAllResults(const std::string& path);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// Canary deployment helper
class CanaryDeployment {
public:
    struct Config {
        std::string model_id;
        std::string new_version;
        std::string baseline_version;
        float initial_traffic_percentage = 0.05f;  // Start with 5%
        float max_traffic_percentage = 1.0f;       // Up to 100%
        float traffic_increment = 0.05f;             // 5% increments
        size_t min_samples_per_step = 100;
        float max_error_rate = 0.01f;                // 1% error threshold
        float max_latency_regression = 1.2f;         // 20% regression allowed
        std::chrono::minutes step_duration{30};    // 30 min per step
    };
    
    explicit CanaryDeployment(const Config& config);
    
    // Deployment steps
    bool start();
    bool promote();  // Increase traffic
    bool rollback(); // Revert to baseline
    bool complete(); // Finish canary
    
    // Status
    struct Status {
        float current_traffic_percentage;
        size_t current_step;
        size_t total_steps;
        bool is_healthy;
        std::string health_reason;
        std::chrono::system_clock::time_point step_start_time;
    };
    Status getStatus() const;
    
    // Auto-advance
    void enableAutoAdvance(bool enabled);
    void checkAndAdvance();  // Call periodically

private:
    Config config_;
    float current_traffic_;
    size_t current_step_;
    bool auto_advance_;
};

} // namespace serving
} // namespace rawrxd
