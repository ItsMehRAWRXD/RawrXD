//============================================================================
// test_performance_thresholds.hpp
// RawrXD N-EVM - Performance Thresholds Unit Tests
//============================================================================

#pragma once

#include "test_framework.hpp"
#include "../nevm_performance_thresholds.hpp"

namespace RawrXD {
namespace NEVM {
namespace Tests {

//============================================================================
// Performance Threshold Tests
//============================================================================

TestResult PerformanceTests_BudgetThroughput() {
    PerformanceBudget budget;
    budget.tok_s_min = 30.0f;
    budget.tok_s_max = 50.0f;
    
    // Within range
    TEST_ASSERT_EQ(true, budget.CheckThroughput(35.0f));
    TEST_ASSERT_EQ(true, budget.CheckThroughput(30.0f));
    TEST_ASSERT_EQ(true, budget.CheckThroughput(50.0f));
    
    // Below minimum
    TEST_ASSERT_EQ(false, budget.CheckThroughput(25.0f));
    
    // Above maximum
    TEST_ASSERT_EQ(false, budget.CheckThroughput(55.0f));
    
    TEST_SUCCESS();
}

TestResult PerformanceTests_BudgetMemory() {
    PerformanceBudget budget;
    budget.memory_max_mb = 8192.0f;
    budget.memory_min_mb = 4096.0f;
    
    // Within range
    TEST_ASSERT_EQ(true, budget.CheckMemory(6000.0f));
    TEST_ASSERT_EQ(true, budget.CheckMemory(4096.0f));
    TEST_ASSERT_EQ(true, budget.CheckMemory(8192.0f));
    
    // Below minimum
    TEST_ASSERT_EQ(false, budget.CheckMemory(2048.0f));
    
    // Above maximum
    TEST_ASSERT_EQ(false, budget.CheckMemory(10240.0f));
    
    TEST_SUCCESS();
}

TestResult PerformanceTests_BudgetLatency() {
    PerformanceBudget budget;
    budget.latency_p99_ms_max = 100.0f;
    budget.latency_p95_ms_max = 80.0f;
    budget.latency_mean_ms_max = 60.0f;
    
    // Within budget
    TEST_ASSERT_EQ(true, budget.CheckLatency(90.0f, 70.0f, 50.0f));
    
    // P99 too high
    TEST_ASSERT_EQ(false, budget.CheckLatency(110.0f, 70.0f, 50.0f));
    
    // P95 too high
    TEST_ASSERT_EQ(false, budget.CheckLatency(90.0f, 90.0f, 50.0f));
    
    // Mean too high
    TEST_ASSERT_EQ(false, budget.CheckLatency(90.0f, 70.0f, 70.0f));
    
    TEST_SUCCESS();
}

TestResult PerformanceTests_RegressionCheck() {
    PerformanceBudget budget;
    budget.regression_threshold_pct = -5.0f;  // Allow 5% regression
    
    // No regression (improvement)
    TEST_ASSERT_EQ(true, budget.CheckRegression(105.0f, 100.0f));
    
    // Small regression (within threshold)
    TEST_ASSERT_EQ(true, budget.CheckRegression(96.0f, 100.0f));
    
    // Large regression (exceeds threshold)
    TEST_ASSERT_EQ(false, budget.CheckRegression(90.0f, 100.0f));
    
    // No baseline (should pass)
    TEST_ASSERT_EQ(true, budget.CheckRegression(100.0f, 0.0f));
    
    TEST_SUCCESS();
}

TestResult PerformanceTests_BudgetJSON() {
    PerformanceBudget budget;
    budget.tok_s_min = 30.0f;
    budget.memory_max_mb = 8192.0f;
    budget.regression_threshold_pct = -5.0f;
    
    Json::Value json = budget.ToJSON();
    
    TEST_ASSERT_NEAR(30.0f, json["tok_s_min"].asFloat(), 0.001f);
    TEST_ASSERT_NEAR(8192.0f, json["memory_max_mb"].asFloat(), 0.001f);
    TEST_ASSERT_NEAR(-5.0f, json["regression_threshold_pct"].asFloat(), 0.001f);
    
    // Round-trip
    PerformanceBudget restored = PerformanceBudget::FromJSON(json);
    TEST_ASSERT_NEAR(budget.tok_s_min, restored.tok_s_min, 0.001f);
    TEST_ASSERT_NEAR(budget.memory_max_mb, restored.memory_max_mb, 0.001f);
    
    TEST_SUCCESS();
}

TestResult PerformanceTests_PredefinedBudgets() {
    auto conservative = PerformanceBudget::Conservative();
    auto aggressive = PerformanceBudget::Aggressive();
    
    // Conservative should be more lenient
    TEST_ASSERT(conservative.tok_s_min < aggressive.tok_s_min);
    TEST_ASSERT(conservative.memory_max_mb > aggressive.memory_max_mb);
    TEST_ASSERT(conservative.regression_threshold_pct < aggressive.regression_threshold_pct);
    
    TEST_SUCCESS();
}

TestResult PerformanceTests_RegressionChecker() {
    RegressionChecker checker;
    PerformanceBudget budget;
    budget.tok_s_min = 30.0f;
    budget.regression_threshold_pct = -5.0f;
    
    // Check throughput
    checker.CheckThroughput(35.0f, 40.0f, budget);
    
    // Should have one result
    TEST_ASSERT_EQ(1ULL, checker.results.size());
    TEST_ASSERT_EQ(true, checker.results[0].passed);
    
    // Check memory
    checker.CheckMemory(8000.0f, 7000.0f, budget);
    
    // Should have two results
    TEST_ASSERT_EQ(2ULL, checker.results.size());
    
    // All should pass
    TEST_ASSERT_EQ(true, checker.AllPassed());
    
    TEST_SUCCESS();
}

TestResult PerformanceTests_RegressionCheckerFailure() {
    RegressionChecker checker;
    PerformanceBudget budget;
    budget.tok_s_min = 30.0f;
    budget.regression_threshold_pct = -5.0f;
    
    // Check with regression
    checker.CheckThroughput(25.0f, 40.0f, budget);
    
    // Should fail
    TEST_ASSERT_EQ(false, checker.AllPassed());
    TEST_ASSERT_EQ(false, checker.results[0].passed);
    
    TEST_SUCCESS();
}

//============================================================================
// Registration
//============================================================================

void RegisterPerformanceThresholdTests(TestFramework& framework) {
    REGISTER_TEST(framework, PerformanceTests, BudgetThroughput);
    REGISTER_TEST(framework, PerformanceTests, BudgetMemory);
    REGISTER_TEST(framework, PerformanceTests, BudgetLatency);
    REGISTER_TEST(framework, PerformanceTests, RegressionCheck);
    REGISTER_TEST(framework, PerformanceTests, BudgetJSON);
    REGISTER_TEST(framework, PerformanceTests, PredefinedBudgets);
    REGISTER_TEST(framework, PerformanceTests, RegressionChecker);
    REGISTER_TEST(framework, PerformanceTests, RegressionCheckerFailure);
}

} // namespace Tests
} // namespace NEVM
} // namespace RawrXD
