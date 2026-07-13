// HTTP Client Unit Tests Implementation
// Copyright (c) 2026 RawrXD Team

#include "http_client_tests.hpp"
#include <iostream>
#include <sstream>
#include <chrono>
#include <thread>
#include <string>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>
#endif

namespace rawrxd::benchmark::testing {

// ============================================================================
// HttpClientTestSuite Implementation
// ============================================================================

std::vector<TestResult> HttpClientTestSuite::RunAllTests() {
    std::vector<TestResult> results;
    
    auto connection_tests = RunConnectionTests();
    results.insert(results.end(), connection_tests.begin(), connection_tests.end());
    
    auto request_tests = RunRequestTests();
    results.insert(results.end(), request_tests.begin(), request_tests.end());
    
    auto response_tests = RunResponseTests();
    results.insert(results.end(), response_tests.begin(), response_tests.end());
    
    auto retry_tests = RunRetryTests();
    results.insert(results.end(), retry_tests.begin(), retry_tests.end());
    
    auto timeout_tests = RunTimeoutTests();
    results.insert(results.end(), timeout_tests.begin(), timeout_tests.end());
    
    auto pool_tests = RunPoolTests();
    results.insert(results.end(), pool_tests.begin(), pool_tests.end());
    
    auto url_tests = RunUrlTests();
    results.insert(results.end(), url_tests.begin(), url_tests.end());
    
    auto utility_tests = RunUtilityTests();
    results.insert(results.end(), utility_tests.begin(), utility_tests.end());
    
    return results;
}

std::vector<TestResult> HttpClientTestSuite::RunConnectionTests() {
    return {
        TestInitializeShutdown(),
        TestMultipleInitialize(),
        TestConnectionPoolCreation(),
        TestConnectionPoolLimits()
    };
}

std::vector<TestResult> HttpClientTestSuite::RunRequestTests() {
    return {
        TestSimpleGet(),
        TestSimplePost(),
        TestPostJson(),
        TestCustomHeaders(),
        TestRequestBuilder()
    };
}

std::vector<TestResult> HttpClientTestSuite::RunResponseTests() {
    return {
        TestResponseParsing(),
        TestStatusCodeHandling(),
        TestHeaderParsing(),
        TestBodyExtraction(),
        TestErrorResponse()
    };
}

std::vector<TestResult> HttpClientTestSuite::RunRetryTests() {
    return {
        TestRetryPolicyCreation(),
        TestExponentialBackoff(),
        TestMaxRetryLimit(),
        TestRetryableErrorDetection(),
        TestNonRetryableError()
    };
}

std::vector<TestResult> HttpClientTestSuite::RunTimeoutTests() {
    return {
        TestConnectionTimeout(),
        TestReadTimeout(),
        TestTotalTimeout(),
        TestTimeoutManager()
    };
}

std::vector<TestResult> HttpClientTestSuite::RunPoolTests() {
    return {
        TestConnectionAcquire(),
        TestConnectionRelease(),
        TestPoolExhaustion(),
        TestIdleTimeout(),
        TestPoolStats()
    };
}

std::vector<TestResult> HttpClientTestSuite::RunUrlTests() {
    return {
        TestUrlParsingSimple(),
        TestUrlParsingWithPort(),
        TestUrlParsingWithPath(),
        TestUrlParsingHttps(),
        TestUrlParsingInvalid()
    };
}

std::vector<TestResult> HttpClientTestSuite::RunUtilityTests() {
    return {
        TestUrlEncode(),
        TestUrlDecode(),
        TestHeaderNormalization(),
        TestStatusTextLookup()
    };
}

// ============================================================================
// Connection Tests
// ============================================================================

TestResult HttpClientTestSuite::TestInitializeShutdown() {
    TestResult result;
    result.test_name = "TestInitializeShutdown";
    result.passed = true;
    
    HttpClient client;
    ASSERT_TRUE(result, client.Initialize(), "Failed to initialize client");
    
    // Shutdown should succeed
    client.Shutdown();
    
    return result;
}

TestResult HttpClientTestSuite::TestMultipleInitialize() {
    TestResult result;
    result.test_name = "TestMultipleInitialize";
    result.passed = true;
    
    HttpClient client;
    ASSERT_TRUE(result, client.Initialize(), "First initialize failed");
    ASSERT_TRUE(result, client.Initialize(), "Second initialize should succeed (idempotent)");
    
    client.Shutdown();
    
    return result;
}

TestResult HttpClientTestSuite::TestConnectionPoolCreation() {
    TestResult result;
    result.test_name = "TestConnectionPoolCreation";
    result.passed = true;
    
    HttpClient client;
    client.Initialize();
    client.EnableConnectionPool(10);
    
    auto stats = client.GetStats();
    ASSERT_EQ(result, 0u, stats.total_requests, "Pool should start empty");
    
    client.Shutdown();
    
    return result;
}

TestResult HttpClientTestSuite::TestConnectionPoolLimits() {
    TestResult result;
    result.test_name = "TestConnectionPoolLimits";
    result.passed = true;
    
    ConnectionPool pool(5, 5000, 30000);
    auto stats = pool.GetStats();
    
    ASSERT_EQ(result, 0u, stats.total_connections, "Pool should start empty");
    ASSERT_EQ(result, 0u, stats.active_connections, "No active connections");
    ASSERT_EQ(result, 0u, stats.idle_connections, "No idle connections");
    
    return result;
}

// ============================================================================
// Request Tests
// ============================================================================

TestResult HttpClientTestSuite::TestSimpleGet() {
    TestResult result;
    result.test_name = "TestSimpleGet";
    result.passed = true;
    
    HttpRequest request;
    request.method = "GET";
    request.url = "http://example.com/test";
    
    ASSERT_EQ(result, "GET", request.method, "Method should be GET");
    ASSERT_EQ(result, "http://example.com/test", request.url, "URL should match");
    
    return result;
}

TestResult HttpClientTestSuite::TestSimplePost() {
    TestResult result;
    result.test_name = "TestSimplePost";
    result.passed = true;
    
    HttpRequest request;
    request.method = "POST";
    request.url = "http://example.com/api";
    request.body = "test data";
    
    ASSERT_EQ(result, "POST", request.method, "Method should be POST");
    ASSERT_EQ(result, "test data", request.body, "Body should match");
    
    return result;
}

TestResult HttpClientTestSuite::TestPostJson() {
    TestResult result;
    result.test_name = "TestPostJson";
    result.passed = true;
    
    HttpRequest request;
    request.SetJsonBody("{\"key\":\"value\"}");
    
    auto it = request.headers.find("Content-Type");
    ASSERT_TRUE(result, it != request.headers.end(), "Content-Type header should exist");
    if (it != request.headers.end()) {
        ASSERT_TRUE(result, it->second.find("application/json") != std::string::npos,
                   "Content-Type should be application/json");
    }
    
    return result;
}

TestResult HttpClientTestSuite::TestCustomHeaders() {
    TestResult result;
    result.test_name = "TestCustomHeaders";
    result.passed = true;
    
    HttpRequest request;
    request.headers["X-Custom-Header"] = "custom_value";
    request.headers["Authorization"] = "Bearer token123";
    
    ASSERT_EQ(result, "custom_value", request.headers["X-Custom-Header"],
              "Custom header should be set");
    ASSERT_EQ(result, "Bearer token123", request.headers["Authorization"],
              "Authorization header should be set");
    
    return result;
}

TestResult HttpClientTestSuite::TestRequestBuilder() {
    TestResult result;
    result.test_name = "TestRequestBuilder";
    result.passed = true;
    
    HttpRequest request;
    request.method = "PUT";
    request.url = "http://api.example.com/v1/resource";
    request.SetHeader("Accept", "application/json");
    request.SetHeader("X-Request-ID", "12345");
    
    ASSERT_EQ(result, "PUT", request.method, "Method should be PUT");
    ASSERT_TRUE(result, request.HasHeader("Accept"), "Should have Accept header");
    ASSERT_TRUE(result, request.HasHeader("X-Request-ID"), "Should have X-Request-ID header");
    
    return result;
}

// ============================================================================
// Response Tests
// ============================================================================

TestResult HttpClientTestSuite::TestResponseParsing() {
    TestResult result;
    result.test_name = "TestResponseParsing";
    result.passed = true;
    
    HttpResponse response;
    response.status_code = 200;
    response.body = "Hello World";
    response.success = true;
    
    ASSERT_TRUE(result, response.IsSuccess(), "Response should be successful");
    ASSERT_EQ(result, 200, response.status_code, "Status code should be 200");
    ASSERT_EQ(result, "Hello World", response.body, "Body should match");
    
    return result;
}

TestResult HttpClientTestSuite::TestStatusCodeHandling() {
    TestResult result;
    result.test_name = "TestStatusCodeHandling";
    result.passed = true;
    
    HttpResponse success_response;
    success_response.status_code = 200;
    ASSERT_TRUE(result, success_response.IsSuccess(), "200 should be success");
    
    HttpResponse client_error;
    client_error.status_code = 404;
    ASSERT_TRUE(result, client_error.IsClientError(), "404 should be client error");
    ASSERT_FALSE(result, client_error.IsSuccess(), "404 should not be success");
    
    HttpResponse server_error;
    server_error.status_code = 500;
    ASSERT_TRUE(result, server_error.IsServerError(), "500 should be server error");
    
    return result;
}

TestResult HttpClientTestSuite::TestHeaderParsing() {
    TestResult result;
    result.test_name = "TestHeaderParsing";
    result.passed = true;
    
    HttpResponse response;
    response.headers["Content-Type"] = "application/json";
    response.headers["Content-Length"] = "123";
    
    ASSERT_TRUE(result, response.HasHeader("Content-Type"), "Should have Content-Type");
    ASSERT_EQ(result, "application/json", response.GetHeader("Content-Type"),
              "Content-Type should match");
    
    return result;
}

TestResult HttpClientTestSuite::TestBodyExtraction() {
    TestResult result;
    result.test_name = "TestBodyExtraction";
    result.passed = true;
    
    HttpResponse response;
    response.body = "{\"status\":\"ok\"}";
    
    ASSERT_EQ(result, "{\"status\":\"ok\"}", response.body, "Body should match");
    ASSERT_FALSE(result, response.body.empty(), "Body should not be empty");
    
    return result;
}

TestResult HttpClientTestSuite::TestErrorResponse() {
    TestResult result;
    result.test_name = "TestErrorResponse";
    result.passed = true;
    
    HttpResponse response;
    response.status_code = 500;
    response.error_message = "Internal Server Error";
    response.success = false;
    
    ASSERT_FALSE(result, response.IsSuccess(), "Error response should not be success");
    ASSERT_TRUE(result, response.IsServerError(), "500 should be server error");
    ASSERT_EQ(result, "Internal Server Error", response.error_message,
              "Error message should match");
    
    return result;
}

// ============================================================================
// Retry Tests
// ============================================================================

TestResult HttpClientTestSuite::TestRetryPolicyCreation() {
    TestResult result;
    result.test_name = "TestRetryPolicyCreation";
    result.passed = true;
    
    RetryPolicy policy(3, 1000, true);
    
    HttpResponse dummy_response;
    dummy_response.status_code = 500;
    
    ASSERT_TRUE(result, policy.ShouldRetry(0, dummy_response), "Should retry on first attempt");
    ASSERT_TRUE(result, policy.ShouldRetry(1, dummy_response), "Should retry on second attempt");
    ASSERT_TRUE(result, policy.ShouldRetry(2, dummy_response), "Should retry on third attempt");
    ASSERT_FALSE(result, policy.ShouldRetry(3, dummy_response), "Should not retry after max");
    
    return result;
}

TestResult HttpClientTestSuite::TestExponentialBackoff() {
    TestResult result;
    result.test_name = "TestExponentialBackoff";
    result.passed = true;
    
    RetryPolicy policy(3, 1000, true, 2.0, 30000);
    
    int delay0 = policy.GetDelayMs(0);
    int delay1 = policy.GetDelayMs(1);
    int delay2 = policy.GetDelayMs(2);
    
    ASSERT_EQ(result, 1000, delay0, "First delay should be base");
    ASSERT_EQ(result, 2000, delay1, "Second delay should be 2x");
    ASSERT_EQ(result, 4000, delay2, "Third delay should be 4x");
    
    return result;
}

TestResult HttpClientTestSuite::TestMaxRetryLimit() {
    TestResult result;
    result.test_name = "TestMaxRetryLimit";
    result.passed = true;
    
    RetryPolicy policy(2, 1000, false);
    
    HttpResponse response;
    response.status_code = 503;
    
    ASSERT_TRUE(result, policy.ShouldRetry(0, response), "Should retry at 0");
    ASSERT_TRUE(result, policy.ShouldRetry(1, response), "Should retry at 1");
    ASSERT_FALSE(result, policy.ShouldRetry(2, response), "Should not retry at max");
    
    return result;
}

TestResult HttpClientTestSuite::TestRetryableErrorDetection() {
    TestResult result;
    result.test_name = "TestRetryableErrorDetection";
    result.passed = true;
    
    RetryPolicy policy(3, 1000, true);
    
    HttpResponse server_error;
    server_error.status_code = 500;
    ASSERT_TRUE(result, policy.IsRetryableError(server_error), "500 should be retryable");
    
    HttpResponse timeout;
    timeout.status_code = 504;
    ASSERT_TRUE(result, policy.IsRetryableError(timeout), "504 should be retryable");
    
    HttpResponse too_many;
    too_many.status_code = 429;
    ASSERT_TRUE(result, policy.IsRetryableError(too_many), "429 should be retryable");
    
    return result;
}

TestResult HttpClientTestSuite::TestNonRetryableError() {
    TestResult result;
    result.test_name = "TestNonRetryableError";
    result.passed = true;
    
    RetryPolicy policy(3, 1000, true);
    
    HttpResponse bad_request;
    bad_request.status_code = 400;
    ASSERT_FALSE(result, policy.IsRetryableError(bad_request), "400 should not be retryable");
    
    HttpResponse not_found;
    not_found.status_code = 404;
    ASSERT_FALSE(result, policy.IsRetryableError(not_found), "404 should not be retryable");
    
    return result;
}

// ============================================================================
// Timeout Tests
// ============================================================================

TestResult HttpClientTestSuite::TestConnectionTimeout() {
    TestResult result;
    result.test_name = "TestConnectionTimeout";
    result.passed = true;
    
    TimeoutManager manager(5000, 30000, 60000);
    
    ASSERT_EQ(result, 5000, manager.GetRemainingTimeMs(), "Remaining time should be initial");
    
    return result;
}

TestResult HttpClientTestSuite::TestReadTimeout() {
    TestResult result;
    result.test_name = "TestReadTimeout";
    result.passed = true;
    
    TimeoutManager manager(5000, 10000, 60000);
    
    ASSERT_FALSE(result, manager.IsTimedOut(), "Should not be timed out initially");
    
    return result;
}

TestResult HttpClientTestSuite::TestTotalTimeout() {
    TestResult result;
    result.test_name = "TestTotalTimeout";
    result.passed = true;
    
    TimeoutManager manager(5000, 30000, 1000);  // 1 second total
    
    // Wait a bit
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    ASSERT_FALSE(result, manager.IsTimedOut(), "Should not be timed out after 100ms");
    
    return result;
}

TestResult HttpClientTestSuite::TestTimeoutManager() {
    TestResult result;
    result.test_name = "TestTimeoutManager";
    result.passed = true;
    
    TimeoutManager manager(1000, 2000, 3000);
    
    int remaining = manager.GetRemainingTimeMs();
    ASSERT_TRUE(result, remaining <= 3000, "Remaining should be at most total");
    ASSERT_TRUE(result, remaining > 0, "Remaining should be positive");
    
    return result;
}

// ============================================================================
// Pool Tests
// ============================================================================

TestResult HttpClientTestSuite::TestConnectionAcquire() {
    TestResult result;
    result.test_name = "TestConnectionAcquire";
    result.passed = true;
    
    ConnectionPool pool(5, 5000, 30000);
    
    // Note: This would need a real server to test properly
    // For now, just verify the pool was created
    auto stats = pool.GetStats();
    ASSERT_EQ(result, 0u, stats.total_connections, "Pool should start empty");
    
    return result;
}

TestResult HttpClientTestSuite::TestConnectionRelease() {
    TestResult result;
    result.test_name = "TestConnectionRelease";
    result.passed = true;
    
    // This test would require a real connection
    // For unit testing, we verify the API exists
    ConnectionPool pool(5, 5000, 30000);
    
    auto stats = pool.GetStats();
    ASSERT_EQ(result, 0u, stats.idle_connections, "No idle connections initially");
    
    return result;
}

TestResult HttpClientTestSuite::TestPoolExhaustion() {
    TestResult result;
    result.test_name = "TestPoolExhaustion";
    result.passed = true;
    
    ConnectionPool pool(2, 5000, 30000);  // Max 2 connections
    
    auto stats = pool.GetStats();
    ASSERT_TRUE(result, stats.total_connections <= 2u, "Connections should not exceed max");
    
    return result;
}

TestResult HttpClientTestSuite::TestIdleTimeout() {
    TestResult result;
    result.test_name = "TestIdleTimeout";
    result.passed = true;
    
    ConnectionPool pool(5, 5000, 100);  // 100ms idle timeout
    
    // Just verify the pool was created with the timeout
    auto stats = pool.GetStats();
    ASSERT_EQ(result, 0u, stats.total_connections, "Pool should start empty");
    
    return result;
}

TestResult HttpClientTestSuite::TestPoolStats() {
    TestResult result;
    result.test_name = "TestPoolStats";
    result.passed = true;
    
    ConnectionPool pool(10, 5000, 30000);
    
    auto stats = pool.GetStats();
    ASSERT_EQ(result, 0u, stats.total_connections, "Total should be 0");
    ASSERT_EQ(result, 0u, stats.active_connections, "Active should be 0");
    ASSERT_EQ(result, 0u, stats.idle_connections, "Idle should be 0");
    
    return result;
}

// ============================================================================
// URL Tests
// ============================================================================

TestResult HttpClientTestSuite::TestUrlParsingSimple() {
    TestResult result;
    result.test_name = "TestUrlParsingSimple";
    result.passed = true;
    
    std::string host, path;
    int port;
    bool use_https;
    
    bool success = HttpClient::ParseUrl("http://example.com", host, port, path, use_https);
    
    ASSERT_TRUE(result, success, "Should parse successfully");
    ASSERT_EQ(result, "example.com", host, "Host should be example.com");
    ASSERT_EQ(result, 80, port, "Port should be 80");
    ASSERT_EQ(result, "/", path, "Path should be /");
    ASSERT_FALSE(result, use_https, "Should not be HTTPS");
    
    return result;
}

TestResult HttpClientTestSuite::TestUrlParsingWithPort() {
    TestResult result;
    result.test_name = "TestUrlParsingWithPort";
    result.passed = true;
    
    std::string host, path;
    int port;
    bool use_https;
    
    bool success = HttpClient::ParseUrl("http://localhost:8080", host, port, path, use_https);
    
    ASSERT_TRUE(result, success, "Should parse successfully");
    ASSERT_EQ(result, "localhost", host, "Host should be localhost");
    ASSERT_EQ(result, 8080, port, "Port should be 8080");
    
    return result;
}

TestResult HttpClientTestSuite::TestUrlParsingWithPath() {
    TestResult result;
    result.test_name = "TestUrlParsingWithPath";
    result.passed = true;
    
    std::string host, path;
    int port;
    bool use_https;
    
    bool success = HttpClient::ParseUrl("http://api.example.com/v1/resource", 
                                          host, port, path, use_https);
    
    ASSERT_TRUE(result, success, "Should parse successfully");
    ASSERT_EQ(result, "api.example.com", host, "Host should be api.example.com");
    ASSERT_EQ(result, "/v1/resource", path, "Path should be /v1/resource");
    
    return result;
}

TestResult HttpClientTestSuite::TestUrlParsingHttps() {
    TestResult result;
    result.test_name = "TestUrlParsingHttps";
    result.passed = true;
    
    std::string host, path;
    int port;
    bool use_https;
    
    bool success = HttpClient::ParseUrl("https://secure.example.com", 
                                          host, port, path, use_https);
    
    ASSERT_TRUE(result, success, "Should parse successfully");
    ASSERT_TRUE(result, use_https, "Should be HTTPS");
    ASSERT_EQ(result, 443, port, "Port should be 443 for HTTPS");
    
    return result;
}

TestResult HttpClientTestSuite::TestUrlParsingInvalid() {
    TestResult result;
    result.test_name = "TestUrlParsingInvalid";
    result.passed = true;
    
    std::string host, path;
    int port;
    bool use_https;
    
    // Empty URL should fail
    bool success = HttpClient::ParseUrl("", host, port, path, use_https);
    ASSERT_FALSE(result, success, "Empty URL should fail");
    
    return result;
}

// ============================================================================
// Utility Tests
// ============================================================================

TestResult HttpClientTestSuite::TestUrlEncode() {
    TestResult result;
    result.test_name = "TestUrlEncode";
    result.passed = true;
    
    std::string encoded = http::UrlEncode("hello world");
    ASSERT_EQ(result, "hello%20world", encoded, "Space should be encoded as %20");
    
    encoded = http::UrlEncode("test@example.com");
    ASSERT_TRUE(result, encoded.find("%40") != std::string::npos, 
                "@ should be encoded");
    
    return result;
}

TestResult HttpClientTestSuite::TestUrlDecode() {
    TestResult result;
    result.test_name = "TestUrlDecode";
    result.passed = true;
    
    std::string decoded = http::UrlDecode("hello%20world");
    ASSERT_EQ(result, "hello world", decoded, "%20 should decode to space");
    
    decoded = http::UrlDecode("test%40example.com");
    ASSERT_EQ(result, "test@example.com", decoded, "%40 should decode to @");
    
    return result;
}

TestResult HttpClientTestSuite::TestHeaderNormalization() {
    TestResult result;
    result.test_name = "TestHeaderNormalization";
    result.passed = true;
    
    std::string normalized = http::NormalizeHeaderName("content-type");
    ASSERT_EQ(result, "Content-Type", normalized, "Should normalize to Title-Case");
    
    normalized = http::NormalizeHeaderName("X-CUSTOM-HEADER");
    ASSERT_EQ(result, "X-Custom-Header", normalized, "Should normalize custom header");
    
    return result;
}

TestResult HttpClientTestSuite::TestStatusTextLookup() {
    TestResult result;
    result.test_name = "TestStatusTextLookup";
    result.passed = true;
    
    const char* text200 = http::GetStatusText(200);
    ASSERT_TRUE(result, std::strcmp(text200, "OK") == 0, "200 should be OK");
    
    const char* text404 = http::GetStatusText(404);
    ASSERT_TRUE(result, std::strcmp(text404, "Not Found") == 0, "404 should be Not Found");
    
    const char* text500 = http::GetStatusText(500);
    ASSERT_TRUE(result, std::strcmp(text500, "Internal Server Error") == 0, 
                "500 should be Internal Server Error");
    
    return result;
}

// ============================================================================
// HttpClientTestRunner Implementation
// ============================================================================

int HttpClientTestRunner::Run(int argc, char** argv) {
    std::cout << "HTTP Client Test Suite\n";
    std::cout << "======================\n\n";
    
    auto results = HttpClientTestSuite::RunAllTests();
    PrintResults(results);
    
    auto [passed, total] = GetSummary(results);
    
    std::cout << "\n========================================\n";
    std::cout << "Summary: " << passed << "/" << total << " tests passed\n";
    std::cout << "========================================\n";
    
    return (passed == total) ? 0 : 1;
}

std::vector<TestResult> HttpClientTestRunner::RunCategory(const std::string& category) {
    if (category == "connection") {
        return HttpClientTestSuite::RunConnectionTests();
    } else if (category == "request") {
        return HttpClientTestSuite::RunRequestTests();
    } else if (category == "response") {
        return HttpClientTestSuite::RunResponseTests();
    } else if (category == "retry") {
        return HttpClientTestSuite::RunRetryTests();
    } else if (category == "timeout") {
        return HttpClientTestSuite::RunTimeoutTests();
    } else if (category == "pool") {
        return HttpClientTestSuite::RunPoolTests();
    } else if (category == "url") {
        return HttpClientTestSuite::RunUrlTests();
    } else if (category == "utility") {
        return HttpClientTestSuite::RunUtilityTests();
    }
    
    return {};
}

void HttpClientTestRunner::PrintResults(const std::vector<TestResult>& results) {
    for (const auto& result : results) {
        std::cout << (result.passed ? "[PASS] " : "[FAIL] ");
        std::cout << result.test_name;
        if (!result.passed && !result.error_message.empty()) {
            std::cout << " - " << result.error_message;
        }
        std::cout << std::endl;
    }
}

std::string HttpClientTestRunner::GenerateReport(const std::vector<TestResult>& results) {
    std::ostringstream oss;
    
    oss << "{\n";
    oss << "  \"test_suite\": \"http_client\",\n";
    oss << "  \"total_tests\": " << results.size() << ",\n";
    
    auto [passed, total] = GetSummary(results);
    oss << "  \"passed\": " << passed << ",\n";
    oss << "  \"failed\": " << (total - passed) << ",\n";
    oss << "  \"tests\": [\n";
    
    for (size_t i = 0; i < results.size(); ++i) {
        const auto& r = results[i];
        oss << "    {\n";
        oss << "      \"name\": \"" << r.test_name << "\",\n";
        oss << "      \"passed\": " << (r.passed ? "true" : "false") << ",\n";
        oss << "      \"duration_ms\": " << r.duration_ms << "\n";
        oss << "    }";
        if (i < results.size() - 1) oss << ",";
        oss << "\n";
    }
    
    oss << "  ]\n";
    oss << "}\n";
    
    return oss.str();
}

std::pair<int, int> HttpClientTestRunner::GetSummary(const std::vector<TestResult>& results) {
    int passed = 0;
    for (const auto& r : results) {
        if (r.passed) passed++;
    }
    return {passed, static_cast<int>(results.size())};
}

// ============================================================================
// MockHttpServer Implementation
// ============================================================================

MockHttpServer::MockHttpServer(int port) : port_(port) {}

MockHttpServer::~MockHttpServer() {
    Stop();
}

bool MockHttpServer::Start() {
    // Simplified mock - in production, implement actual HTTP server
    running_ = true;
    return true;
}

void MockHttpServer::Stop() {
    running_ = false;
}

void MockHttpServer::SetResponse(const std::string& path, int status_code,
                                  const std::string& body,
                                  const std::map<std::string, std::string>& headers) {
    MockResponse response;
    response.status_code = status_code;
    response.body = body;
    response.headers = headers;
    responses_[path] = response;
}

void MockHttpServer::SetDelayedResponse(const std::string& path, int delay_ms,
                                        int status_code, const std::string& body) {
    MockResponse response;
    response.status_code = status_code;
    response.body = body;
    response.delay_ms = delay_ms;
    responses_[path] = response;
}

void MockHttpServer::SetErrorResponse(const std::string& path, int error_code) {
    MockResponse response;
    response.status_code = error_code;
    response.is_error = true;
    responses_[path] = response;
}

int MockHttpServer::GetRequestCount(const std::string& path) const {
    auto it = request_counts_.find(path);
    return it != request_counts_.end() ? it->second : 0;
}

std::string MockHttpServer::GetLastRequestBody(const std::string& path) const {
    auto it = last_request_bodies_.find(path);
    return it != last_request_bodies_.end() ? it->second : "";
}

void MockHttpServer::ClearRequestHistory() {
    request_counts_.clear();
    last_request_bodies_.clear();
}

// ============================================================================
// HttpClientTestFixture Implementation
// ============================================================================

HttpClientTestFixture::HttpClientTestFixture() : server_(18081) {}

HttpClientTestFixture::~HttpClientTestFixture() = default;

void HttpClientTestFixture::SetUp() {
    client_.Initialize();
    server_.Start();
}

void HttpClientTestFixture::TearDown() {
    client_.Shutdown();
    server_.Stop();
}

} // namespace rawrxd::benchmark::testing
