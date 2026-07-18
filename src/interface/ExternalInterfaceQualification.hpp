/**
 * ExternalInterfaceQualification.hpp
 *
 * Phase D.2 Batch 5/5: External Interface Qualification
 *
 * Validation and qualification tests for the external interface layer.
 * Ensures all interface components meet quality and reliability standards.
 *
 * Test Categories:
 *   - API Gateway Tests
 *   - Query Engine Tests
 *   - Tool Contract Tests
 *   - Human Interaction Tests
 *   - Integration Tests
 *   - Performance Tests
 */

#pragma once

#include "SovereignAPIGateway.hpp"
#include "SovereignQueryEngine.hpp"
#include "ISovereignTool.hpp"
#include "HumanInteractionProtocol.hpp"

#include <string>
#include <vector>
#include <map>
#include <functional>
#include <chrono>

namespace Interface {

/**
 * Test result
 */
struct TestResult {
    std::string testId;
    std::string testName;
    std::string category;
    bool passed{false};
    std::string errorMessage;
    int64_t executionTimeMs{0};
    std::map<std::string, std::string> metrics;
    
    std::string ToJson() const;
    void Print() const;
};

/**
 * Test suite result
 */
struct TestSuiteResult {
    std::string suiteName;
    int totalTests{0};
    int passedTests{0};
    int failedTests{0};
    int skippedTests{0};
    int64_t totalExecutionTimeMs{0};
    std::vector<TestResult> results;
    
    std::string ToJson() const;
    void Print() const;
    double GetPassRate() const;
};

/**
 * Qualification report
 */
struct QualificationReport {
    std::string reportId;
    int64_t timestampMs{0};
    std::string version;
    std::vector<TestSuiteResult> suites;
    
    int GetTotalTests() const;
    int GetPassedTests() const;
    int GetFailedTests() const;
    double GetOverallPassRate() const;
    bool IsQualified() const;
    
    std::string ToJson() const;
    void Print() const;
    void SaveToFile(const std::string& path) const;
};

/**
 * Test configuration
 */
struct QualificationConfig {
    int apiGatewayPort{8080};
    int queryTimeoutMs{5000};
    int toolTimeoutMs{10000};
    int approvalTimeoutMs{30000};
    int maxConcurrentTests{10};
    bool runPerformanceTests{true};
    bool runStressTests{false};
    std::vector<std::string> includeCategories;
    std::vector<std::string> excludeCategories;
    
    std::string ToJson() const;
};

/**
 * Test function type
 */
using TestFunction = std::function<TestResult());

/**
 * Test case
 */
struct TestCase {
    std::string testId;
    std::string testName;
    std::string category;
    std::string description;
    TestFunction function;
    bool enabled{true};
};

/**
 * External Interface Qualification
 *
 * Runs comprehensive tests on all external interface components.
 */
class ExternalInterfaceQualification {
public:
    ExternalInterfaceQualification();
    ~ExternalInterfaceQualification();

    // Disable copy
    ExternalInterfaceQualification(const ExternalInterfaceQualification&) = delete;
    ExternalInterfaceQualification& operator=(const ExternalInterfaceQualification&) = delete;

    /**
     * Initialize qualification
     */
    bool Initialize(const QualificationConfig& config);

    /**
     * Run all tests
     */
    QualificationReport RunAllTests();

    /**
     * Run test category
     */
    TestSuiteResult RunCategory(const std::string& category);

    /**
     * Run specific test
     */
    TestResult RunTest(const std::string& testId);

    /**
     * Register test
     */
    void RegisterTest(const TestCase& testCase);

    /**
     * Get available tests
     */
    std::vector<TestCase> GetAvailableTests() const;

    /**
     * Print status
     */
    void PrintStatus() const;

private:
    QualificationConfig config_;
    bool initialized_{false};
    std::vector<TestCase> testCases_;
    
    // Component instances for testing
    std::unique_ptr<SovereignAPIGateway> apiGateway_;
    std::unique_ptr<SovereignQueryEngine> queryEngine_;
    std::unique_ptr<SovereignToolRegistry> toolRegistry_;
    std::unique_ptr<HumanInteractionProtocol> humanProtocol_;
    
    // Test registration
    void RegisterAllTests();
    
    // API Gateway Tests
    void RegisterAPIGatewayTests();
    TestResult TestAPIGatewayInitialization();
    TestResult TestAPIGatewayRouteRegistration();
    TestResult TestAPIGatewayRequestHandling();
    TestResult TestAPIGatewayAuthentication();
    TestResult TestAPIGatewayRateLimiting();
    TestResult TestAPIGatewayCORS();
    
    // Query Engine Tests
    void RegisterQueryEngineTests();
    TestResult TestQueryEngineInitialization();
    TestResult TestQueryEngineBasicQueries();
    TestResult TestQueryEngineCaching();
    TestResult TestQueryEngineErrorHandling();
    TestResult TestQueryEnginePerformance();
    
    // Tool Contract Tests
    void RegisterToolContractTests();
    TestResult TestToolRegistryInitialization();
    TestResult TestToolRegistration();
    TestResult TestToolExecution();
    TestResult TestToolAsyncExecution();
    TestResult TestToolCancellation();
    TestResult TestStateQueryTool();
    TestResult TestGraphMutationTool();
    TestResult TestCheckpointTool();
    
    // Human Interaction Tests
    void RegisterHumanInteractionTests();
    TestResult TestHumanProtocolInitialization();
    TestResult TestCommandParsing();
    TestResult TestIntentTranslation();
    TestResult TestApprovalGate();
    TestResult TestNotificationSystem();
    TestResult TestCommandExecution();
    
    // Integration Tests
    void RegisterIntegrationTests();
    TestResult TestAPIQueryIntegration();
    TestResult TestQueryToolIntegration();
    TestResult TestHumanToolIntegration();
    TestResult TestEndToEndWorkflow();
    
    // Performance Tests
    void RegisterPerformanceTests();
    TestResult TestAPIThroughput();
    TestResult TestQueryLatency();
    TestResult TestToolExecutionLatency();
    TestResult TestConcurrentOperations();
    
    // Helpers
    int64_t GetCurrentTimeMs() const;
    TestResult CreateTestResult(const std::string& testId, 
                                 const std::string& testName,
                                 const std::string& category,
                                 bool passed,
                                 const std::string& error = "");
};

/**
 * Qualification CLI
 */
class ExternalInterfaceQualificationCLI {
public:
    static void PrintBanner();
    static void PrintUsage();
    static int Run(int argc, char* argv[]);
    
private:
    static QualificationConfig ParseArgs(int argc, char* argv[]);
    static void PrintReport(const QualificationReport& report);
};

} // namespace Interface
