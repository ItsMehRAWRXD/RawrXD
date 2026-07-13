// End-to-End Test Suite
// Copyright (c) 2026 RawrXD Team

#pragma once

#include "integrated_runner.hpp"
#include "mock_backend_server.hpp"
#include <string>
#include <vector>

namespace rawrxd::benchmark::testing {

// ============================================================================
// End-to-End Test Suite
// ============================================================================

class EndToEndTestSuite {
public:
    // Run all E2E tests
    static std::vector<TestResult> RunAllTests();
    
    // Test categories
    static std::vector<TestResult> RunSmokeTests();
    static std::vector<TestResult> RunIntegrationTests();
    static std::vector<TestResult> RunPerformanceTests();
    static std::vector<TestResult> RunRegressionTests();
    static std::vector<TestResult> RunChaosTests();

private:
    // Smoke Tests (quick validation)
    static TestResult TestSovereignConnection();
    static TestResult TestOllamaConnection();
    static TestResult TestSimpleInference();
    static TestResult TestBasicAgent();
    static TestResult TestBasicSwarm();
    
    // Integration Tests
    static TestResult TestFullBenchmarkLifecycle();
    static TestResult TestConfigurationLoading();
    static TestResult TestResultValidation();
    static TestResult TestBaselineComparison();
    static TestResult TestReportGeneration();
    static TestResult TestParallelExecution();
    
    // Performance Tests
    static TestResult TestInferenceLatency();
    static TestResult TestThroughputMeasurement();
    static TestResult TestResourceSampling();
    static TestResult TestConcurrentLoad();
    static TestResult TestMemoryUsage();
    
    // Regression Tests
    static TestResult TestDeterministicResults();
    static TestResult TestConsistentLatency();
    static TestResult TestNoMemoryLeaks();
    static TestResult TestGracefulDegradation();
    static TestResult TestRecoveryFromFailure();
    
    // Chaos Tests
    static TestResult TestBackendFailure();
    static TestResult TestNetworkInterruption();
    static TestResult TestTimeoutHandling();
    static TestResult TestRetryBehavior();
    static TestResult TestPartialFailure();
};

// ============================================================================
// Test Scenarios
// ============================================================================

struct TestScenario {
    std::string name;
    std::string description;
    std::vector<std::string> steps;
    std::vector<std::string> expected_results;
    int estimated_duration_seconds;
    bool requires_real_backend;
};

class TestScenarioLibrary {
public:
    static std::vector<TestScenario> GetSmokeScenarios();
    static std::vector<TestScenario> GetIntegrationScenarios();
    static std::vector<TestScenario> GetPerformanceScenarios();
    static std::vector<TestScenario> GetRegressionScenarios();
    static std::vector<TestScenario> GetChaosScenarios();
    
    static TestScenario GetScenario(const std::string& name);
    static std::vector<std::string> GetScenarioNames();
};

// ============================================================================
// E2E Test Runner
// ============================================================================

class EndToEndTestRunner {
public:
    static int Run(int argc, char** argv);
    static std::vector<TestResult> RunScenario(const std::string& scenario_name);
    static std::vector<TestResult> RunCategory(const std::string& category);
    
    // Configuration
    void SetUseRealBackends(bool use_real) { use_real_backends_ = use_real; }
    void SetVerbose(bool verbose) { verbose_ = verbose; }
    void SetTimeout(int timeout_seconds) { timeout_seconds_ = timeout_seconds; }
    
private:
    bool use_real_backends_ = false;
    bool verbose_ = false;
    int timeout_seconds_ = 300;
    
    std::unique_ptr<CITestEnvironment> mock_env_;
    
    bool Initialize();
    void Shutdown();
    TestResult ExecuteScenario(const TestScenario& scenario);
};

// ============================================================================
// Test Report Generator
// ============================================================================

class E2ETestReport {
public:
    struct Summary {
        int total_tests = 0;
        int passed = 0;
        int failed = 0;
        int skipped = 0;
        double total_duration_seconds = 0.0;
        std::string timestamp;
        std::string git_commit;
        std::string git_branch;
    };
    
    static std::string GenerateJsonReport(const std::vector<TestResult>& results,
                                           const Summary& summary);
    static std::string GenerateHtmlReport(const std::vector<TestResult>& results,
                                           const Summary& summary);
    static std::string GenerateMarkdownReport(const std::vector<TestResult>& results,
                                               const Summary& summary);
    static std::string GenerateJUnitReport(const std::vector<TestResult>& results,
                                             const Summary& summary);
    
    static Summary CalculateSummary(const std::vector<TestResult>& results);
};

// ============================================================================
// Load Test Suite
// ============================================================================

class LoadTestSuite {
public:
    struct LoadConfig {
        int concurrent_requests = 10;
        int total_requests = 100;
        int ramp_up_seconds = 5;
        int duration_seconds = 60;
        double target_rps = 10.0;  // requests per second
    };
    
    struct LoadResult {
        int total_requests = 0;
        int successful_requests = 0;
        int failed_requests = 0;
        double average_latency_ms = 0.0;
        double p95_latency_ms = 0.0;
        double p99_latency_ms = 0.0;
        double actual_rps = 0.0;
        double duration_seconds = 0.0;
        bool passed = false;
    };
    
    static LoadResult RunLoadTest(const LoadConfig& config,
                                   BackendType backend,
                                   const std::string& endpoint);
    
    static std::vector<LoadResult> RunComparisonLoadTest(const LoadConfig& config,
                                                          const std::string& sovereign_endpoint,
                                                          const std::string& ollama_endpoint);
    
    static std::string GenerateReport(const std::vector<LoadResult>& results);
};

// ============================================================================
// Stress Test Suite
// ============================================================================

class StressTestSuite {
public:
    struct StressConfig {
        int initial_concurrent = 1;
        int max_concurrent = 100;
        int step_size = 10;
        int step_duration_seconds = 30;
        double max_acceptable_latency_ms = 10000.0;
        double min_acceptable_success_rate = 0.95;
    };
    
    struct StressResult {
        int max_sustainable_concurrent = 0;
        double breaking_point_latency = 0.0;
        double breaking_point_success_rate = 0.0;
        std::vector<std::pair<int, double>> latency_by_concurrency;
        std::vector<std::pair<int, double>> success_rate_by_concurrency;
        bool passed = false;
    };
    
    static StressResult RunStressTest(const StressConfig& config,
                                       BackendType backend,
                                       const std::string& endpoint);
    
    static std::string GenerateReport(const StressResult& result);
};

// ============================================================================
// Benchmark Validation Suite
// ============================================================================

class BenchmarkValidationSuite {
public:
    // Validate benchmark correctness
    static TestResult ValidateStatisticalCorrectness();
    static TestResult ValidateConfidenceIntervals();
    static TestResult ValidateOutlierDetection();
    static TestResult ValidateWarmupEffectiveness();
    static TestResult ValidateSampleSizeAdequacy();
    
    // Validate benchmark integrity
    static TestResult ValidateNoDataLoss();
    static TestResult ValidateTimestampAccuracy();
    static TestResult ValidateMetricConsistency();
    static TestResult ValidateResultReproducibility();
    static TestResult ValidateErrorHandling();
};

} // namespace rawrxd::benchmark::testing
