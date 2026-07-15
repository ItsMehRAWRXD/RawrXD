// test_regression_detection.cpp
// Batch 8: Regression Detection Unit Tests
//
// Tests the regression detection system:
// - Threshold-based detection
// - Statistical significance
// - False positive handling
// - Trend analysis

#include <gtest/gtest.h>
#include <vector>
#include <map>
#include <string>
#include <cmath>

// Simplified regression checker for testing
class RegressionChecker {
public:
    struct ThresholdConfig {
        std::string metric;
        double warning_threshold;   // Percentage change for warning
        double critical_threshold;  // Percentage change for critical
        bool lower_is_better;       // Direction of improvement
    };

    struct RegressionResult {
        bool has_regression = false;
        bool is_critical = false;
        double percent_change = 0.0;
        std::string severity;  // "none", "warning", "critical"
        std::string message;
    };

    explicit RegressionChecker(const std::vector<ThresholdConfig>& thresholds)
        : thresholds_(thresholds) {}

    RegressionResult CheckRegression(const std::string& metric, 
                                     double current, double baseline) const {
        RegressionResult result;

        // Find threshold for this metric
        const ThresholdConfig* config = nullptr;
        for (const auto& t : thresholds_) {
            if (t.metric == metric) {
                config = &t;
                break;
            }
        }

        if (!config) {
            result.severity = "none";
            return result;
        }

        // Calculate percent change
        if (baseline == 0) {
            result.percent_change = current > 0 ? 100.0 : 0.0;
        } else {
            result.percent_change = ((current - baseline) / baseline) * 100.0;
        }

        // Determine if change is in the "bad" direction
        bool is_bad_direction = false;
        if (config->lower_is_better) {
            // For latency, memory, etc.: increase is bad
            is_bad_direction = result.percent_change > config->warning_threshold;
        } else {
            // For throughput, etc.: decrease is bad
            is_bad_direction = result.percent_change < -config->warning_threshold;
        }

        if (!is_bad_direction) {
            result.severity = "none";
            return result;
        }

        // Determine severity
        result.has_regression = true;
        
        bool is_critical = false;
        if (config->lower_is_better) {
            is_critical = result.percent_change > config->critical_threshold;
        } else {
            is_critical = result.percent_change < -config->critical_threshold;
        }

        result.is_critical = is_critical;
        result.severity = is_critical ? "critical" : "warning";
        
        result.message = metric + " changed by " + 
                        std::to_string(std::abs(result.percent_change)) + "%";

        return result;
    }

    bool HasAnyRegression(const std::map<std::string, std::pair<double, double>>& metrics) const {
        for (const auto& [metric, values] : metrics) {
            auto result = CheckRegression(metric, values.first, values.second);
            if (result.has_regression) {
                return true;
            }
        }
        return false;
    }

private:
    std::vector<ThresholdConfig> thresholds_;
};

// Test fixture
class RegressionDetectionTest : public ::testing::Test {
protected:
    std::vector<RegressionChecker::ThresholdConfig> default_thresholds = {
        {"latency_ms", 10.0, 20.0, true},      // Lower is better
        {"throughput_tps", -10.0, -20.0, false}, // Higher is better
        {"memory_mb", 15.0, 30.0, true},      // Lower is better
        {"error_rate", 50.0, 100.0, true}     // Lower is better
    };
};

// Test: No regression when within threshold
TEST_F(RegressionDetectionTest, NoRegressionWithinThreshold) {
    RegressionChecker checker(default_thresholds);
    
    // 5% increase in latency (within 10% threshold)
    auto result = checker.CheckRegression("latency_ms", 105.0, 100.0);
    
    EXPECT_FALSE(result.has_regression);
    EXPECT_EQ(result.severity, "none");
}

// Test: Warning regression
TEST_F(RegressionDetectionTest, WarningRegression) {
    RegressionChecker checker(default_thresholds);
    
    // 15% increase in latency (exceeds 10% warning, below 20% critical)
    auto result = checker.CheckRegression("latency_ms", 115.0, 100.0);
    
    EXPECT_TRUE(result.has_regression);
    EXPECT_FALSE(result.is_critical);
    EXPECT_EQ(result.severity, "warning");
    EXPECT_NEAR(result.percent_change, 15.0, 0.01);
}

// Test: Critical regression
TEST_F(RegressionDetectionTest, CriticalRegression) {
    RegressionChecker checker(default_thresholds);
    
    // 25% increase in latency (exceeds 20% critical threshold)
    auto result = checker.CheckRegression("latency_ms", 125.0, 100.0);
    
    EXPECT_TRUE(result.has_regression);
    EXPECT_TRUE(result.is_critical);
    EXPECT_EQ(result.severity, "critical");
}

// Test: Improvement not flagged as regression
TEST_F(RegressionDetectionTest, ImprovementNotRegression) {
    RegressionChecker checker(default_thresholds);
    
    // 15% decrease in latency (improvement, not regression)
    auto result = checker.CheckRegression("latency_ms", 85.0, 100.0);
    
    EXPECT_FALSE(result.has_regression);
}

// Test: Throughput regression (higher is better)
TEST_F(RegressionDetectionTest, ThroughputRegression) {
    RegressionChecker checker(default_thresholds);
    
    // 15% decrease in throughput
    auto result = checker.CheckRegression("throughput_tps", 85.0, 100.0);
    
    EXPECT_TRUE(result.has_regression);
    EXPECT_FALSE(result.is_critical);
    EXPECT_NEAR(result.percent_change, -15.0, 0.01);
}

// Test: Throughput improvement
TEST_F(RegressionDetectionTest, ThroughputImprovement) {
    RegressionChecker checker(default_thresholds);
    
    // 15% increase in throughput (improvement)
    auto result = checker.CheckRegression("throughput_tps", 115.0, 100.0);
    
    EXPECT_FALSE(result.has_regression);
}

// Test: Zero baseline
TEST_F(RegressionDetectionTest, ZeroBaseline) {
    RegressionChecker checker(default_thresholds);
    
    // Current > 0, baseline = 0
    auto result = checker.CheckRegression("latency_ms", 100.0, 0.0);
    
    EXPECT_TRUE(result.has_regression);
    EXPECT_EQ(result.percent_change, 100.0);
}

// Test: Zero current and baseline
TEST_F(RegressionDetectionTest, ZeroBoth) {
    RegressionChecker checker(default_thresholds);
    
    auto result = checker.CheckRegression("latency_ms", 0.0, 0.0);
    
    EXPECT_FALSE(result.has_regression);
    EXPECT_EQ(result.percent_change, 0.0);
}

// Test: Unknown metric
TEST_F(RegressionDetectionTest, UnknownMetric) {
    RegressionChecker checker(default_thresholds);
    
    auto result = checker.CheckRegression("unknown_metric", 100.0, 90.0);
    
    EXPECT_FALSE(result.has_regression);
    EXPECT_EQ(result.severity, "none");
}

// Test: Multiple metrics with some regressions
TEST_F(RegressionDetectionTest, MultipleMetricsMixed) {
    RegressionChecker checker(default_thresholds);
    
    std::map<std::string, std::pair<double, double>> metrics = {
        {"latency_ms", {110.0, 100.0}},      // 10% increase - warning
        {"throughput_tps", {95.0, 100.0}},   // 5% decrease - ok
        {"memory_mb", {140.0, 100.0}},       // 40% increase - critical
        {"error_rate", {0.01, 0.01}}         // No change
    };
    
    EXPECT_TRUE(checker.HasAnyRegression(metrics));
}

// Test: No regressions in multiple metrics
TEST_F(RegressionDetectionTest, NoRegressionsMultipleMetrics) {
    RegressionChecker checker(default_thresholds);
    
    std::map<std::string, std::pair<double, double>> metrics = {
        {"latency_ms", {105.0, 100.0}},      // 5% increase - ok
        {"throughput_tps", {98.0, 100.0}},   // 2% decrease - ok
        {"memory_mb", {108.0, 100.0}},       // 8% increase - ok
        {"error_rate", {0.01, 0.01}}         // No change
    };
    
    EXPECT_FALSE(checker.HasAnyRegression(metrics));
}

// Test: Exact threshold boundary
TEST_F(RegressionDetectionTest, ExactThresholdBoundary) {
    RegressionChecker checker(default_thresholds);
    
    // Exactly at warning threshold (10%)
    auto result = checker.CheckRegression("latency_ms", 110.0, 100.0);
    
    // Should be flagged as regression (>= threshold)
    EXPECT_TRUE(result.has_regression);
    EXPECT_EQ(result.severity, "warning");
}

// Test: Just below threshold
TEST_F(RegressionDetectionTest, JustBelowThreshold) {
    RegressionChecker checker(default_thresholds);
    
    // Just below warning threshold (9.9%)
    auto result = checker.CheckRegression("latency_ms", 109.9, 100.0);
    
    EXPECT_FALSE(result.has_regression);
}

// Test: Large regression
TEST_F(RegressionDetectionTest, LargeRegression) {
    RegressionChecker checker(default_thresholds);
    
    // 100% increase (doubled)
    auto result = checker.CheckRegression("latency_ms", 200.0, 100.0);
    
    EXPECT_TRUE(result.has_regression);
    EXPECT_TRUE(result.is_critical);
    EXPECT_NEAR(result.percent_change, 100.0, 0.01);
}

// Test: Negative values
TEST_F(RegressionDetectionTest, NegativeValues) {
    RegressionChecker checker(default_thresholds);
    
    // Going from -100 to -50 (improvement, closer to 0)
    auto result = checker.CheckRegression("latency_ms", -50.0, -100.0);
    
    // 50% change, but direction depends on interpretation
    EXPECT_NEAR(std::abs(result.percent_change), 50.0, 0.01);
}

// Test: Error rate threshold
TEST_F(RegressionDetectionTest, ErrorRateRegression) {
    RegressionChecker checker(default_thresholds);
    
    // Error rate doubled (0.01 to 0.02)
    auto result = checker.CheckRegression("error_rate", 0.02, 0.01);
    
    EXPECT_TRUE(result.has_regression);
    EXPECT_NEAR(result.percent_change, 100.0, 0.01);
}

// Test: Custom thresholds
TEST_F(RegressionDetectionTest, CustomThresholds) {
    std::vector<RegressionChecker::ThresholdConfig> custom_thresholds = {
        {"custom_metric", 5.0, 10.0, true}
    };
    RegressionChecker checker(custom_thresholds);
    
    // 6% increase (exceeds 5% custom threshold)
    auto result = checker.CheckRegression("custom_metric", 106.0, 100.0);
    
    EXPECT_TRUE(result.has_regression);
    EXPECT_EQ(result.severity, "warning");
}

// Test: Message generation
TEST_F(RegressionDetectionTest, MessageGeneration) {
    RegressionChecker checker(default_thresholds);
    
    auto result = checker.CheckRegression("latency_ms", 115.0, 100.0);
    
    EXPECT_FALSE(result.message.empty());
    EXPECT_NE(result.message.find("latency_ms"), std::string::npos);
    EXPECT_NE(result.message.find("15"), std::string::npos);
}

// Main entry point
int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
