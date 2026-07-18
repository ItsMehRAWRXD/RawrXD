// HTTP Client Unit Tests
// Copyright (c) 2026 RawrXD Team

#pragma once

#include "http_client.hpp"
#include <string>
#include <vector>
#include <functional>

namespace rawrxd::benchmark::testing {

// ============================================================================
// Test Result
// ============================================================================

struct TestResult {
    std::string test_name;
    bool passed = false;
    std::string error_message;
    double duration_ms = 0.0;
    
    void AssertTrue(bool condition, const std::string& message) {
        if (!condition) {
            passed = false;
            error_message = message;
        }
    }
    
    void AssertFalse(bool condition, const std::string& message) {
        AssertTrue(!condition, message);
    }
    
    void AssertEqual(auto expected, auto actual, const std::string& message) {
        if (expected != actual) {
            passed = false;
            error_message = message + " (expected: " + std::to_string(expected) + 
                           ", actual: " + std::to_string(actual) + ")";
        }
    }
    
    void AssertNotNull(const void* ptr, const std::string& message) {
        AssertTrue(ptr != nullptr, message);
    }
    
    void AssertNull(const void* ptr, const std::string& message) {
        AssertTrue(ptr == nullptr, message);
    }
};

// ============================================================================
// HTTP Client Test Suite
// ============================================================================

class HttpClientTestSuite {
public:
    // Run all tests
    static std::vector<TestResult> RunAllTests();
    
    // Individual test categories
    static std::vector<TestResult> RunConnectionTests();
    static std::vector<TestResult> RunRequestTests();
    static std::vector<TestResult> RunResponseTests();
    static std::vector<TestResult> RunRetryTests();
    static std::vector<TestResult> RunTimeoutTests();
    static std::vector<TestResult> RunPoolTests();
    static std::vector<TestResult> RunUrlTests();
    static std::vector<TestResult> RunUtilityTests();

private:
    // Connection Tests
    static TestResult TestInitializeShutdown();
    static TestResult TestMultipleInitialize();
    static TestResult TestConnectionPoolCreation();
    static TestResult TestConnectionPoolLimits();
    
    // Request Tests
    static TestResult TestSimpleGet();
    static TestResult TestSimplePost();
    static TestResult TestPostJson();
    static TestResult TestCustomHeaders();
    static TestResult TestRequestBuilder();
    
    // Response Tests
    static TestResult TestResponseParsing();
    static TestResult TestStatusCodeHandling();
    static TestResult TestHeaderParsing();
    static TestResult TestBodyExtraction();
    static TestResult TestErrorResponse();
    
    // Retry Tests
    static TestResult TestRetryPolicyCreation();
    static TestResult TestExponentialBackoff();
    static TestResult TestMaxRetryLimit();
    static TestResult TestRetryableErrorDetection();
    static TestResult TestNonRetryableError();
    
    // Timeout Tests
    static TestResult TestConnectionTimeout();
    static TestResult TestReadTimeout();
    static TestResult TestTotalTimeout();
    static TestResult TestTimeoutManager();
    
    // Pool Tests
    static TestResult TestConnectionAcquire();
    static TestResult TestConnectionRelease();
    static TestResult TestPoolExhaustion();
    static TestResult TestIdleTimeout();
    static TestResult TestPoolStats();
    
    // URL Tests
    static TestResult TestUrlParsingSimple();
    static TestResult TestUrlParsingWithPort();
    static TestResult TestUrlParsingWithPath();
    static TestResult TestUrlParsingHttps();
    static TestResult TestUrlParsingInvalid();
    
    // Utility Tests
    static TestResult TestUrlEncode();
    static TestResult TestUrlDecode();
    static TestResult TestHeaderNormalization();
    static TestResult TestStatusTextLookup();
};

// ============================================================================
// Test Runner
// ============================================================================

class HttpClientTestRunner {
public:
    // Run all tests and print results
    static int Run(int argc, char** argv);
    
    // Run specific test category
    static std::vector<TestResult> RunCategory(const std::string& category);
    
    // Print test results
    static void PrintResults(const std::vector<TestResult>& results);
    
    // Generate test report
    static std::string GenerateReport(const std::vector<TestResult>& results);
    
    // Get summary statistics
    static std::pair<int, int> GetSummary(const std::vector<TestResult>& results);
};

// ============================================================================
// Mock HTTP Server for Testing
// ============================================================================

class MockHttpServer {
public:
    MockHttpServer(int port = 18080);
    ~MockHttpServer();
    
    // Start/stop server
    bool Start();
    void Stop();
    bool IsRunning() const { return running_; }
    
    // Configure responses
    void SetResponse(const std::string& path, int status_code, 
                     const std::string& body,
                     const std::map<std::string, std::string>& headers = {});
    
    void SetDelayedResponse(const std::string& path, int delay_ms,
                            int status_code, const std::string& body);
    
    void SetErrorResponse(const std::string& path, int error_code);
    
    // Request tracking
    int GetRequestCount(const std::string& path) const;
    std::string GetLastRequestBody(const std::string& path) const;
    void ClearRequestHistory();
    
    // Get server URL
    std::string GetUrl() const { return "http://localhost:" + std::to_string(port_); }

private:
    int port_;
    bool running_ = false;
    int server_fd_ = -1;
    
    struct MockResponse {
        int status_code = 200;
        std::string body;
        std::map<std::string, std::string> headers;
        int delay_ms = 0;
        bool is_error = false;
    };
    
    std::map<std::string, MockResponse> responses_;
    std::map<std::string, int> request_counts_;
    std::map<std::string, std::string> last_request_bodies_;
    
    void HandleRequest(int client_fd);
    std::string BuildResponse(const MockResponse& response);
};

// ============================================================================
// Test Fixtures
// ============================================================================

class HttpClientTestFixture {
public:
    HttpClientTestFixture();
    ~HttpClientTestFixture();
    
    void SetUp();
    void TearDown();
    
    HttpClient* GetClient() { return &client_; }
    MockHttpServer* GetServer() { return &server_; }
    
protected:
    HttpClient client_;
    MockHttpServer server_;
};

// ============================================================================
// Assertion Macros (for convenience)
// ============================================================================

#define ASSERT_TRUE(result, condition, message) \
    result.AssertTrue(condition, message)

#define ASSERT_FALSE(result, condition, message) \
    result.AssertFalse(condition, message)

#define ASSERT_EQ(result, expected, actual, message) \
    result.AssertEqual(expected, actual, message)

#define ASSERT_NE(result, expected, actual, message) \
    result.AssertTrue(expected != actual, message)

#define ASSERT_NULL(result, ptr, message) \
    result.AssertNull(ptr, message)

#define ASSERT_NOT_NULL(result, ptr, message) \
    result.AssertNotNull(ptr, message)

} // namespace rawrxd::benchmark::testing
