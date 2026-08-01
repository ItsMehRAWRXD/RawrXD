// ============================================================================
// CertificationTestSuite.hpp — VAL-064 through VAL-067 Certification Tests
// Validates: Codec Layer, Backend Router, Agent Communication, MultiResponse
// ============================================================================
#pragma once

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include <functional>
#include <chrono>
#include <memory>

namespace RawrXD {
namespace Certification {

using json = nlohmann::json;

// ============================================================================
// Test Result
// ============================================================================
struct TestResult {
    std::string id;
    std::string name;
    std::string category;
    bool passed = false;
    std::string error;
    double durationMs = 0.0;
    json details;
};

// ============================================================================
// Certification Report
// ============================================================================
struct CertificationReport {
    std::string suite;
    std::string timestamp;
    int totalTests = 0;
    int passedTests = 0;
    int failedTests = 0;
    double totalDurationMs = 0.0;
    std::vector<TestResult> results;
    bool allPassed() const { return failedTests == 0; }
    
    json toJSON() const {
        json j;
        j["suite"] = suite;
        j["timestamp"] = timestamp;
        j["total"] = totalTests;
        j["passed"] = passedTests;
        j["failed"] = failedTests;
        j["duration_ms"] = totalDurationMs;
        j["all_passed"] = allPassed();
        
        json resultsJson = json::array();
        for (const auto& r : results) {
            json rj;
            rj["id"] = r.id;
            rj["name"] = r.name;
            rj["category"] = r.category;
            rj["passed"] = r.passed;
            rj["error"] = r.error;
            rj["duration_ms"] = r.durationMs;
            resultsJson.push_back(rj);
        }
        j["results"] = resultsJson;
        return j;
    }
};

// ============================================================================
// Test Callback
// ============================================================================
using TestCallback = std::function<void(const std::string& testId, 
                                         const std::string& status,
                                         float progress)>;

// ============================================================================
// Certification Test Suite
// ============================================================================
class CertificationTestSuite {
public:
    CertificationTestSuite();
    ~CertificationTestSuite();

    // Initialization
    bool Initialize();
    void Shutdown();

    // Run specific certification
    CertificationReport RunVAL064_CodecLayer();
    CertificationReport RunVAL065_BackendRouter();
    CertificationReport RunVAL066_AgentCommunication();
    CertificationReport RunVAL067_MultiResponse();

    // Run all certifications
    CertificationReport RunAll();

    // Run specific test by ID
    TestResult RunTest(const std::string& testId);

    // Callbacks
    void SetTestCallback(TestCallback cb) { m_testCb = cb; }

    // Export report
    bool ExportReport(const CertificationReport& report, const std::string& path);
    bool ExportAllReports(const std::string& directory);

    // List available tests
    std::vector<std::string> ListTests() const;
    std::vector<std::string> ListCategories() const;

private:
    // VAL-064: Codec Layer Tests
    TestResult Test_064_001_StoredBlock();
    TestResult Test_064_002_FixedHuffman();
    TestResult Test_064_003_DynamicHuffman();
    TestResult Test_064_004_MultiBlock();
    TestResult Test_064_005_LargeDictionary();
    TestResult Test_064_006_InvalidStream();
    TestResult Test_064_007_TruncatedInput();
    TestResult Test_064_008_LargeAsset();

    // VAL-065: Backend Router Tests
    TestResult Test_065_001_LocalBackend();
    TestResult Test_065_002_OllamaBackend();
    TestResult Test_065_003_CloudBackend();
    TestResult Test_065_004_FallbackBehavior();
    TestResult Test_065_005_LatencyTracking();
    TestResult Test_065_006_HealthCheck();
    TestResult Test_065_007_Failover();

    // VAL-066: Agent Communication Tests
    TestResult Test_066_001_Streaming();
    TestResult Test_066_002_ToolCalls();
    TestResult Test_066_003_Cancellation();
    TestResult Test_066_004_Telemetry();
    TestResult Test_066_005_ErrorRecovery();
    TestResult Test_066_006_ConcurrentRequests();

    // VAL-067: MultiResponse Tests
    TestResult Test_067_001_TemplateExecution();
    TestResult Test_067_002_ParallelMode();
    TestResult Test_067_003_SessionPersistence();
    TestResult Test_067_004_Ranking();
    TestResult Test_067_005_Consensus();
    TestResult Test_067_006_Performance();

    // Helpers
    TestResult MakeResult(const std::string& id, const std::string& name,
                          const std::string& category, bool passed,
                          const std::string& error = "",
                          double durationMs = 0.0);
    void ReportProgress(const std::string& testId, const std::string& status, float progress);

private:
    TestCallback m_testCb;
    bool m_initialized = false;
};

} // namespace Certification
} // namespace RawrXD
