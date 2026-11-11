// Phase Z.2/5: Integration Test Suite
// RawrXD Integration Tests - Comprehensive end-to-end test suite

#pragma once

#include <cstring>
#include <vector>
#include <memory>
#include <functional>
#include <chrono>
#include <optional>
#include <unordered_map>

namespace RawrXD {
namespace Integration {

// Test category
enum class TestCategory {
    SMOKE,           // Basic functionality
    REGRESSION,      // Prevent regressions
    PERFORMANCE,   // Performance benchmarks
    STRESS,          // Load testing
    SECURITY,        // Security validation
    COMPATIBILITY,   // Version compatibility
    EDGE_CASE        // Edge case handling
};

// Test priority
enum class TestPriority {
    CRITICAL,        // Must pass
    HIGH,            // Important
    MEDIUM,          // Normal
    LOW              // Nice to have
};

// Test result
enum class TestResultStatus {
    NOT_RUN,
    RUNNING,
    PASSED,
    FAILED,
    SKIPPED,
    TIMED_OUT,
    ERROR
};

// Test assertion
struct TestAssertion {
    std::string description;
    bool passed;
    std::string expected;
    std::string actual;
    std::string file;
    uint32_t line;
};

// Test case
struct TestCase {
    std::string test_id;
    std::string name;
    std::string description;
    TestCategory category;
    TestPriority priority;
    
    // Execution
    std::function<void()> setup;
    std::function<void()> teardown;
    std::function<void()> test_function;
    std::chrono::seconds timeout;
    
    // Requirements
    std::vector<std::string> required_subsystems;
    std::vector<std::string> required_features;
    
    // Results
    TestResultStatus status;
    std::chrono::milliseconds execution_time;
    std::vector<TestAssertion> assertions;
    std::string error_message;
    std::string stack_trace;
};

// Test suite
struct TestSuite {
    std::string suite_id;
    std::string name;
    std::string description;
    TestCategory category;
    
    // Tests
    std::vector<TestCase> tests;
    
    // Execution
    std::function<void()> suite_setup;
    std::function<void()> suite_teardown;
    
    // Configuration
    bool parallel_execution;
    uint32_t max_parallel_tests;
    std::chrono::seconds timeout;
    
    // Results
    uint32_t tests_run;
    uint32_t tests_passed;
    uint32_t tests_failed;
    uint32_t tests_skipped;
    std::chrono::milliseconds total_execution_time;
};

// Test run configuration
struct TestRunConfig {
    // Filter
    std::vector<std::string> include_categories;
    std::vector<std::string> exclude_categories;
    std::vector<std::string> include_tests;
    std::vector<std::string> exclude_tests;
    TestPriority min_priority;
    
    // Execution
    bool stop_on_first_failure;
    bool parallel_execution;
    uint32_t parallel_jobs;
    std::chrono::seconds timeout;
    uint32_t retry_count;
    
    // Output
    std::string output_format;  // "console", "json", "xml", "html"
    std::string output_path;
    bool verbose;
    bool capture_output;
};

// Test run result
struct TestRunResult {
    std::string run_id;
    std::chrono::system_clock::time_point started_at;
    std::chrono::system_clock::time_point completed_at;
    
    // Summary
    uint32_t total_tests;
    uint32_t tests_run;
    uint32_t tests_passed;
    uint32_t tests_failed;
    uint32_t tests_skipped;
    uint32_t tests_timed_out;
    uint32_t tests_error;
    
    // Timing
    std::chrono::milliseconds total_duration;
    std::chrono::milliseconds average_test_duration;
    std::chrono::milliseconds slowest_test_duration;
    std::string slowest_test_name;
    
    // Results by category
    std::unordered_map<TestCategory, uint32_t> passed_by_category;
    std::unordered_map<TestCategory, uint32_t> failed_by_category;
    
    // Detailed results
    std::vector<TestCase> test_results;
    
    // Status
    bool all_passed;
    double pass_rate;
};

// Integration test interface
class IIntegrationTestSuite {
public:
    virtual ~IIntegrationTestSuite() = default;
    
    // Initialization
    virtual bool Initialize(const std::string& config_path) = 0;
    virtual void Shutdown() = 0;
    
    // Test registration
    virtual std::string RegisterTest(const TestCase& test) = 0;
    virtual bool UnregisterTest(const std::string& test_id) = 0;
    virtual std::string RegisterSuite(const TestSuite& suite) = 0;
    virtual bool UnregisterSuite(const std::string& suite_id) = 0;
    
    // Test queries
    virtual std::vector<TestCase> ListTests() = 0;
    virtual std::vector<TestCase> ListTestsByCategory(TestCategory category) = 0;
    virtual std::vector<TestCase> ListTestsByPriority(TestPriority priority) = 0;
    virtual std::optional<TestCase> GetTest(const std::string& test_id) = 0;
    virtual std::vector<TestSuite> ListSuites() = 0;
    
    // Test execution
    virtual TestRunResult RunTest(const std::string& test_id) = 0;
    virtual TestRunResult RunSuite(const std::string& suite_id) = 0;
    virtual TestRunResult RunAll(const TestRunConfig& config = {}) = 0;
    virtual TestRunResult RunFiltered(const TestRunConfig& config) = 0;
    
    // Test control
    virtual bool SkipTest(const std::string& test_id, const std::string& reason) = 0;
    virtual bool RetryTest(const std::string& test_id) = 0;
    virtual bool CancelRunningTests() = 0;
    
    // Assertions
    virtual void AssertTrue(bool condition, const std::string& message,
                           const std::string& file, uint32_t line) = 0;
    virtual void AssertFalse(bool condition, const std::string& message,
                            const std::string& file, uint32_t line) = 0;
    virtual void AssertEqual(const std::string& expected, const std::string& actual,
                            const std::string& message,
                            const std::string& file, uint32_t line) = 0;
    virtual void AssertEqual(int64_t expected, int64_t actual,
                            const std::string& message,
                            const std::string& file, uint32_t line) = 0;
    virtual void AssertEqual(double expected, double actual, double tolerance,
                            const std::string& message,
                            const std::string& file, uint32_t line) = 0;
    virtual void AssertNull(const void* ptr, const std::string& message,
                           const std::string& file, uint32_t line) = 0;
    virtual void AssertNotNull(const void* ptr, const std::string& message,
                              const std::string& file, uint32_t line) = 0;
    virtual void AssertThrows(std::function<void()> func, const std::string& message,
                             const std::string& file, uint32_t line) = 0;
    virtual void Fail(const std::string& message,
                     const std::string& file, uint32_t line) = 0;
    
    // Reporting
    virtual std::string GenerateReport(const TestRunResult& result,
                                      const std::string& format = "console") = 0;
    virtual bool SaveReport(const TestRunResult& result,
                           const std::string& path,
                           const std::string& format = "json") = 0;
    virtual std::string GenerateCoverageReport() = 0;
    
    // History
    virtual std::vector<TestRunResult> GetTestHistory(uint32_t limit = 100) = 0;
    virtual std::optional<TestRunResult> GetLastRun() = 0;
    virtual bool CompareWithBaseline(const TestRunResult& current) = 0;
    
    // Statistics
    virtual struct TestStatistics {
        uint32_t total_tests;
        uint32_t total_suites;
        uint32_t total_runs;
        double overall_pass_rate;
        std::chrono::milliseconds average_run_duration;
        std::unordered_map<TestCategory, uint32_t> tests_by_category;
        std::unordered_map<TestPriority, uint32_t> tests_by_priority;
        std::vector<std::string> flaky_tests;
    } GetStatistics() = 0;
};

// Test macros
#define RAWRXD_TEST_ASSERT_TRUE(condition, message) \
    if (RawrXD::Integration::g_integration_tests) { \
        RawrXD::Integration::g_integration_tests->AssertTrue(condition, message, __FILE__, __LINE__); \
    }

#define RAWRXD_TEST_ASSERT_FALSE(condition, message) \
    if (RawrXD::Integration::g_integration_tests) { \
        RawrXD::Integration::g_integration_tests->AssertFalse(condition, message, __FILE__, __LINE__); \
    }

#define RAWRXD_TEST_ASSERT_EQUAL(expected, actual, message) \
    if (RawrXD::Integration::g_integration_tests) { \
        RawrXD::Integration::g_integration_tests->AssertEqual(expected, actual, message, __FILE__, __LINE__); \
    }

#define RAWRXD_TEST_ASSERT_NULL(ptr, message) \
    if (RawrXD::Integration::g_integration_tests) { \
        RawrXD::Integration::g_integration_tests->AssertNull(ptr, message, __FILE__, __LINE__); \
    }

#define RAWRXD_TEST_ASSERT_NOT_NULL(ptr, message) \
    if (RawrXD::Integration::g_integration_tests) { \
        RawrXD::Integration::g_integration_tests->AssertNotNull(ptr, message, __FILE__, __LINE__); \
    }

#define RAWRXD_TEST_FAIL(message) \
    if (RawrXD::Integration::g_integration_tests) { \
        RawrXD::Integration::g_integration_tests->Fail(message, __FILE__, __LINE__); \
    }

// Global integration test suite
extern std::unique_ptr<IIntegrationTestSuite> g_integration_tests;

// Initialize integration tests
bool InitializeIntegrationTests(const std::string& config_path);
void ShutdownIntegrationTests();
bool AreIntegrationTestsEnabled();

// Predefined test suites
namespace PredefinedTests {

// Smoke tests
void RegisterSmokeTests();

// Core subsystem tests
void RegisterCoreTests();
void RegisterInferenceTests();
void RegisterAgenticTests();
void RegisterMemoryTests();
void RegisterMetacognitiveTests();

// Integration tests
void RegisterEndToEndTests();
void RegisterPerformanceTests();
void RegisterStressTests();
void RegisterSecurityTests();

// Full test suite
void RegisterAllTests();

} // namespace PredefinedTests

} // namespace Integration
} // namespace RawrXD
