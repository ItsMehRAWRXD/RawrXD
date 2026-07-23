#pragma once

#include "SwarmOrchestrator.hpp"
#include <vector>
#include <string>
#include <map>

namespace rawrxd {
namespace swarm {

// Test specification
struct TestSpec {
    std::string name;
    std::string type;           // "unit", "integration", "e2e", "load", "security"
    std::string target;         // file or component being tested
    std::vector<std::string> testCases;
    std::vector<std::string> mocks;
    std::vector<std::string> assertions;
    int coverageTarget{80};     // percentage
};

// Load test configuration
struct LoadTestConfig {
    std::string endpoint;
    std::string method;
    int concurrentUsers{100};
    int rampUpSeconds{30};
    int durationSeconds{300};
    int targetRPS{1000};
    int maxResponseTimeMs{200};
    double errorRateThreshold{0.01}; // 1%
};

// QA Hive - 50 parallel testing agents
class QAHive {
public:
    struct TestResults {
        struct TestCase {
            std::string name;
            bool passed;
            std::string duration;
            std::string error;
        };
        
        std::string testFile;
        int totalTests{0};
        int passed{0};
        int failed{0};
        int skipped{0};
        double duration{0.0};
        double coverage{0.0};
        std::vector<TestCase> cases;
        std::string report;
    };
    
    struct LoadTestResults {
        int totalRequests{0};
        int successfulRequests{0};
        int failedRequests{0};
        double avgResponseTime{0.0};
        double p50ResponseTime{0.0};
        double p95ResponseTime{0.0};
        double p99ResponseTime{0.0};
        double maxResponseTime{0.0};
        double requestsPerSecond{0.0};
        double errorRate{0.0};
        bool passed{false};
        std::string bottleneck;
    };
    
    // Main test execution - runs in parallel
    std::vector<TestResults> runTestSuite(const std::vector<TestSpec>& specs);
    
    // Unit test generators
    std::string generateUnitTest(const TestSpec& spec);
    std::string generateReactTest(const std::string& componentPath);
    std::string generateVueTest(const std::string& componentPath);
    std::string generateAPITest(const APIEndpoint& endpoint);
    std::string generateServiceTest(const ServiceSpec& spec);
    
    // Integration tests
    std::string generateIntegrationTest(
        const std::vector<std::string>& components,
        const std::string& scenario
    );
    std::string generateDatabaseIntegrationTest(const DatabaseSchema& schema);
    std::string generateAPIIntegrationTest(const std::vector<ServiceSpec>& services);
    
    // E2E tests
    std::string generateE2ETest(const std::string& userFlow);
    std::string generateCypressTest(const std::string& flow);
    std::string generatePlaywrightTest(const std::string& flow);
    std::string generateSeleniumTest(const std::string& flow);
    
    // Load testing
    std::string generateLoadTestScript(const LoadTestConfig& config);
    LoadTestResults runLoadTest(const LoadTestConfig& config);
    std::string generateK6Script(const LoadTestConfig& config);
    std::string generateArtilleryConfig(const LoadTestConfig& config);
    std::string generateJMeterConfig(const LoadTestConfig& config);
    
    // Security testing
    std::string generateSecurityTest(const std::string& endpoint);
    std::string generateSQLInjectionTest(const APIEndpoint& endpoint);
    std::string generateXSSPreventionTest(const std::string& component);
    std::string generateCSRFTest(const APIEndpoint& endpoint);
    std::string generateAuthBypassTest(const APIEndpoint& endpoint);
    
    // Coverage analysis
    std::string generateCoverageReport(const std::vector<TestResults>& results);
    std::string identifyCoverageGaps(const std::vector<TestResults>& results);
    std::vector<std::string> suggestAdditionalTests(const std::string& sourceFile);
    
    // Performance profiling
    std::string generatePerformanceProfile(const std::string& component);
    std::string identifyBottlenecks(const LoadTestResults& results);
    std::string generateOptimizationSuggestions(const std::string& profile);
    
    // Test utilities
    std::string generateMockData(const std::string& schema);
    std::string generateFixture(const std::string& model);
    std::string generateFactory(const std::string& model);
    std::string generateTestHelpers();
    
    // Continuous testing
    std::string generateGitHubActionsWorkflow();
    std::string generateGitLabCIPipeline();
    std::string generatePreCommitHooks();
};

} // namespace swarm
} // namespace rawrxd
