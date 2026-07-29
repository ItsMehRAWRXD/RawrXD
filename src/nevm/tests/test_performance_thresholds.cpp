//============================================================================
// test_performance_thresholds.cpp
// RawrXD N-EVM - Unit Tests for Performance Thresholds
//============================================================================

#include "../nevm_performance_thresholds.hpp"

using namespace RawrXD::NEVM;

TEST(PerformanceThresholds_Defaults) {
    PerformanceThresholds thresholds;
    
    // Default values should be reasonable
    ASSERT_GT(thresholds.max_latency_ms, 0.0);
    ASSERT_GT(thresholds.min_throughput_tps, 0.0);
    ASSERT_GT(thresholds.max_memory_mb, 0.0);
    ASSERT_GT(thresholds.max_cpu_percent, 0.0);
    ASSERT_GT(thresholds.max_gpu_percent, 0.0);
    
    return true;
}

TEST(PerformanceThresholds_Validate_Pass) {
    PerformanceThresholds thresholds;
    thresholds.max_latency_ms = 100.0;
    thresholds.min_throughput_tps = 1000.0;
    thresholds.max_memory_mb = 1024.0;
    
    PerformanceMetrics metrics;
    metrics.latency_ms = 50.0;
    metrics.throughput_tps = 2000.0;
    metrics.memory_mb = 512.0;
    
    ASSERT_TRUE(thresholds.Validate(metrics));
    
    return true;
}

TEST(PerformanceThresholds_Validate_LatencyFail) {
    PerformanceThresholds thresholds;
    thresholds.max_latency_ms = 100.0;
    
    PerformanceMetrics metrics;
    metrics.latency_ms = 150.0;  // Exceeds threshold
    metrics.throughput_tps = 2000.0;
    metrics.memory_mb = 512.0;
    
    ASSERT_FALSE(thresholds.Validate(metrics));
    
    return true;
}

TEST(PerformanceThresholds_Validate_ThroughputFail) {
    PerformanceThresholds thresholds;
    thresholds.min_throughput_tps = 1000.0;
    
    PerformanceMetrics metrics;
    metrics.latency_ms = 50.0;
    metrics.throughput_tps = 500.0;  // Below threshold
    metrics.memory_mb = 512.0;
    
    ASSERT_FALSE(thresholds.Validate(metrics));
    
    return true;
}

TEST(PerformanceThresholds_Validate_MemoryFail) {
    PerformanceThresholds thresholds;
    thresholds.max_memory_mb = 1024.0;
    
    PerformanceMetrics metrics;
    metrics.latency_ms = 50.0;
    metrics.throughput_tps = 2000.0;
    metrics.memory_mb = 2048.0;  // Exceeds threshold
    
    ASSERT_FALSE(thresholds.Validate(metrics));
    
    return true;
}

TEST(PerformanceThresholds_ToJSON) {
    PerformanceThresholds thresholds;
    thresholds.max_latency_ms = 100.0;
    thresholds.min_throughput_tps = 1000.0;
    thresholds.max_memory_mb = 1024.0;
    thresholds.max_cpu_percent = 80.0;
    thresholds.max_gpu_percent = 90.0;
    
    auto json = thresholds.ToJSON();
    
    ASSERT_EQ(100.0, json["max_latency_ms"].asDouble());
    ASSERT_EQ(1000.0, json["min_throughput_tps"].asDouble());
    ASSERT_EQ(1024.0, json["max_memory_mb"].asDouble());
    ASSERT_EQ(80.0, json["max_cpu_percent"].asDouble());
    ASSERT_EQ(90.0, json["max_gpu_percent"].asDouble());
    
    return true;
}

TEST(PerformanceThresholds_FromJSON) {
    Json::Value json;
    json["max_latency_ms"] = 150.0;
    json["min_throughput_tps"] = 2000.0;
    json["max_memory_mb"] = 2048.0;
    json["max_cpu_percent"] = 85.0;
    json["max_gpu_percent"] = 95.0;
    
    auto thresholds = PerformanceThresholds::FromJSON(json);
    
    ASSERT_EQ(150.0, thresholds.max_latency_ms);
    ASSERT_EQ(2000.0, thresholds.min_throughput_tps);
    ASSERT_EQ(2048.0, thresholds.max_memory_mb);
    ASSERT_EQ(85.0, thresholds.max_cpu_percent);
    ASSERT_EQ(95.0, thresholds.max_gpu_percent);
    
    return true;
}

TEST(PerformanceBudget_Allocate) {
    PerformanceBudget budget;
    
    // Allocate budget
    ASSERT_TRUE(budget.Allocate("kernel1", 50.0));
    ASSERT_TRUE(budget.Allocate("kernel2", 30.0));
    ASSERT_TRUE(budget.Allocate("kernel3", 20.0));
    
    // Total should be 100%
    ASSERT_EQ(100.0, budget.GetTotalAllocated());
    
    return true;
}

TEST(PerformanceBudget_Allocate_Overflow) {
    PerformanceBudget budget;
    
    // Allocate 80%
    ASSERT_TRUE(budget.Allocate("kernel1", 80.0));
    
    // Try to allocate another 30% (should fail, total would be 110%)
    ASSERT_FALSE(budget.Allocate("kernel2", 30.0));
    
    return true;
}

TEST(PerformanceBudget_Consume) {
    PerformanceBudget budget;
    budget.Allocate("kernel1", 50.0);
    
    // Consume within budget
    ASSERT_TRUE(budget.Consume("kernel1", 30.0));
    ASSERT_EQ(30.0, budget.GetConsumed("kernel1"));
    
    // Consume more
    ASSERT_TRUE(budget.Consume("kernel1", 15.0));
    ASSERT_EQ(45.0, budget.GetConsumed("kernel1"));
    
    return true;
}

TEST(PerformanceBudget_Consume_Exceed) {
    PerformanceBudget budget;
    budget.Allocate("kernel1", 50.0);
    
    // Try to consume more than allocated
    ASSERT_FALSE(budget.Consume("kernel1", 60.0));
    ASSERT_EQ(0.0, budget.GetConsumed("kernel1"));
    
    return true;
}

TEST(PerformanceBudget_Reset) {
    PerformanceBudget budget;
    budget.Allocate("kernel1", 50.0);
    budget.Consume("kernel1", 30.0);
    
    ASSERT_EQ(30.0, budget.GetConsumed("kernel1"));
    
    budget.Reset();
    
    ASSERT_EQ(0.0, budget.GetConsumed("kernel1"));
    ASSERT_EQ(0.0, budget.GetTotalAllocated());
    
    return true;
}

TEST(RegressionChecker_Baseline) {
    RegressionChecker checker;
    
    // Set baseline
    PerformanceMetrics baseline;
    baseline.latency_ms = 100.0;
    baseline.throughput_tps = 1000.0;
    baseline.memory_mb = 512.0;
    
    checker.SetBaseline(baseline);
    
    // Same metrics should not be regression
    ASSERT_FALSE(checker.IsRegression(baseline));
    
    return true;
}

TEST(RegressionChecker_LatencyRegression) {
    RegressionChecker checker;
    
    PerformanceMetrics baseline;
    baseline.latency_ms = 100.0;
    baseline.throughput_tps = 1000.0;
    checker.SetBaseline(baseline);
    
    // Higher latency is regression (>10% threshold)
    PerformanceMetrics current;
    current.latency_ms = 120.0;  // 20% increase
    current.throughput_tps = 1000.0;
    
    ASSERT_TRUE(checker.IsRegression(current));
    
    return true;
}

TEST(RegressionChecker_ThroughputRegression) {
    RegressionChecker checker;
    
    PerformanceMetrics baseline;
    baseline.latency_ms = 100.0;
    baseline.throughput_tps = 1000.0;
    checker.SetBaseline(baseline);
    
    // Lower throughput is regression (>10% threshold)
    PerformanceMetrics current;
    current.latency_ms = 100.0;
    current.throughput_tps = 800.0;  // 20% decrease
    
    ASSERT_TRUE(checker.IsRegression(current));
    
    return true;
}

TEST(RegressionChecker_NoRegression) {
    RegressionChecker checker;
    
    PerformanceMetrics baseline;
    baseline.latency_ms = 100.0;
    baseline.throughput_tps = 1000.0;
    checker.SetBaseline(baseline);
    
    // Small changes within threshold
    PerformanceMetrics current;
    current.latency_ms = 105.0;  // 5% increase (within 10% threshold)
    current.throughput_tps = 950.0;  // 5% decrease (within 10% threshold)
    
    ASSERT_FALSE(checker.IsRegression(current));
    
    return true;
}

TEST(RegressionChecker_GetDelta) {
    RegressionChecker checker;
    
    PerformanceMetrics baseline;
    baseline.latency_ms = 100.0;
    baseline.throughput_tps = 1000.0;
    checker.SetBaseline(baseline);
    
    PerformanceMetrics current;
    current.latency_ms = 110.0;
    current.throughput_tps = 900.0;
    
    auto delta = checker.GetDelta(current);
    
    ASSERT_NEAR(10.0, delta.latency_delta_percent, 0.1);  // 10% increase
    ASSERT_NEAR(-10.0, delta.throughput_delta_percent, 0.1);  // 10% decrease
    
    return true;
}
