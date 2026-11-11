// Mock Backend Server for CI/CD Testing
// Copyright (c) 2026 RawrXD Team

#pragma once

#include "http_client.hpp"
#include <string>
#include <map>
#include <vector>
#include <functional>
#include <thread>
#include <mutex>

namespace rawrxd::benchmark::testing {

// ============================================================================
// Mock Response Definition
// ============================================================================

struct MockResponse {
    int status_code = 200;
    std::string body;
    std::map<std::string, std::string> headers;
    int delay_ms = 0;
    bool is_error = false;
    std::function<std::string(const std::string&)> dynamic_handler;
    
    static MockResponse Json(const std::string& json_body, int status = 200);
    static MockResponse Error(int status, const std::string& message);
    static MockResponse Delayed(int delay_ms, const std::string& body);
    static MockResponse Dynamic(std::function<std::string(const std::string&)> handler);
};

// ============================================================================
// Mock HTTP Server
// ============================================================================

class MockHttpServer {
public:
    MockHttpServer(int port = 18080);
    virtual ~MockHttpServer();
    
    // Server lifecycle
    bool Start();
    void Stop();
    bool IsRunning() const { return running_; }
    int GetPort() const { return port_; }
    std::string GetUrl() const { return "http://localhost:" + std::to_string(port_); }
    
    // Response configuration
    void SetResponse(const std::string& path, const MockResponse& response);
    void SetDefaultResponse(const MockResponse& response);
    void ClearResponses();
    
    // Request tracking
    int GetRequestCount(const std::string& path) const;
    int GetTotalRequestCount() const;
    std::string GetLastRequestBody(const std::string& path) const;
    std::map<std::string, std::string> GetLastRequestHeaders(const std::string& path) const;
    void ClearRequestHistory();
    
    // Wait for requests
    bool WaitForRequests(int count, int timeout_ms = 5000);
    bool WaitForRequest(const std::string& path, int timeout_ms = 5000);

protected:
    int port_;
    bool running_ = false;
    int server_fd_ = -1;
    std::thread server_thread_;
    
    mutable std::mutex responses_mutex_;
    mutable std::mutex requests_mutex_;
    
    std::map<std::string, MockResponse> responses_;
    MockResponse default_response_;
    
    struct RequestRecord {
        std::string body;
        std::map<std::string, std::string> headers;
        std::string timestamp;
    };
    std::map<std::string, std::vector<RequestRecord>> request_history_;
    
    void ServerLoop();
    void HandleClient(int client_fd);
    std::string ParseRequest(const std::string& request, std::string& path, 
                              std::map<std::string, std::string>& headers);
    std::string BuildHttpResponse(const MockResponse& response);
    void RecordRequest(const std::string& path, const std::string& body,
                       const std::map<std::string, std::string>& headers);
};

// ============================================================================
// Mock Sovereign Server
// ============================================================================

class MockSovereignServer : public MockHttpServer {
public:
    MockSovereignServer(int port = 18080);
    
    void SetupDefaultResponses();
    
    // API response setters
    void SetGenerateResponse(const std::string& text, int tokens, double tps, 
                              double latency_ms);
    void SetAgentResponse(const std::string& agent_id, const std::string& status,
                           double spawn_time_ms);
    void SetSwarmResponse(const std::string& swarm_id,
                           const std::vector<std::string>& agent_ids,
                           double spawn_time_ms);
    void SetSEGResponse(const std::string& graph_id, int nodes, int edges,
                         double build_time_ms);
    void SetDecisionResponse(const std::string& selected_option, double confidence,
                               const std::string& reasoning, double decision_time_ms);
    void SetHealthResponse(bool healthy, const std::string& version,
                            const std::map<std::string, std::string>& capabilities);
    void SetMetricsResponse(double cpu_percent, double memory_mb, 
                             double gpu_percent, double gpu_memory_mb);
    
    // Simulate errors
    void SimulateError(const std::string& path, int status_code, 
                       const std::string& error_message);
    void SimulateTimeout(const std::string& path, int delay_ms);
    void SimulateIntermittentFailure(const std::string& path, int fail_every_n);
};

// ============================================================================
// Mock Ollama Server
// ============================================================================

class MockOllamaServer : public MockHttpServer {
public:
    MockOllamaServer(int port = 18081);
    
    void SetupDefaultResponses();
    
    // API response setters
    void SetGenerateResponse(const std::string& text, const std::string& model,
                              int eval_count, int eval_duration_ns,
                              int total_duration_ns);
    void SetChatResponse(const std::string& model, const std::string& role,
                          const std::string& content, int eval_count, 
                          int eval_duration_ns);
    void SetModelListResponse(const std::vector<std::map<std::string, std::string>>& models);
    void SetPullResponse(const std::string& status, const std::string& digest = "",
                          int total = 0, int completed = 0);
    void SetPsResponse(const std::vector<std::map<std::string, std::string>>& running_models);
    void SetEmbedResponse(const std::vector<double>& embedding);
    
    // Simulate errors
    void SimulateModelNotFound(const std::string& model);
    void SimulateTimeout(int delay_ms);
    void SimulateRateLimit(int retry_after_seconds);
};

// ============================================================================
// CI/CD Test Configuration
// ============================================================================

struct CITestConfig {
    // Server ports
    int sovereign_port = 18080;
    int ollama_port = 18081;
    
    // Test timeouts
    int startup_timeout_ms = 5000;
    int request_timeout_ms = 30000;
    int shutdown_timeout_ms = 5000;
    
    // Mock response delays
    int min_delay_ms = 10;
    int max_delay_ms = 100;
    
    // Failure simulation
    bool simulate_failures = false;
    double failure_rate = 0.1;  // 10%
    int intermittent_fail_every = 5;
    
    // Performance thresholds
    double max_acceptable_latency_ms = 5000.0;
    double min_acceptable_throughput = 10.0;
    double min_success_rate = 0.95;
    
    static CITestConfig Fast();      // Fast config for quick CI
    static CITestConfig Thorough();  // Thorough config for nightly builds
    static CITestConfig Stress();    // Stress test config
};

// ============================================================================
// CI Test Environment
// ============================================================================

class CITestEnvironment {
public:
    CITestEnvironment();
    ~CITestEnvironment();
    
    bool Initialize(const CITestConfig& config = CITestConfig::Fast());
    void Shutdown();
    
    MockSovereignServer* GetSovereignServer() { return &sovereign_server_; }
    MockOllamaServer* GetOllamaServer() { return &ollama_server_; }
    
    // Create backend configs pointing to mock servers
    BenchmarkConfig CreateSovereignConfig();
    BenchmarkConfig CreateOllamaConfig();
    
    // Wait for servers to be ready
    bool WaitForServers(int timeout_ms = 5000);
    
    // Reset server state
    void ResetServers();

private:
    CITestConfig config_;
    MockSovereignServer sovereign_server_;
    MockOllamaServer ollama_server_;
    bool initialized_ = false;
};

// ============================================================================
// Test Data Generators
// ============================================================================

namespace test_data {
    // Sample prompts
    std::string SimplePrompt();
    std::string CodePrompt();
    std::string LongPrompt(size_t tokens);
    std::string StructuredPrompt();
    
    // Expected responses
    std::string SimpleResponse();
    std::string CodeResponse();
    std::string StructuredResponse();
    
    // JSON builders
    std::string BuildSovereignGenerateJson(const std::string& text, int tokens, double tps);
    std::string BuildOllamaGenerateJson(const std::string& text, const std::string& model,
                                         int eval_count, int eval_duration_ns);
    std::string BuildSovereignAgentJson(const std::string& agent_id, const std::string& status);
    std::string BuildOllamaModelListJson(const std::vector<std::string>& models);
    
} // namespace test_data

} // namespace rawrxd::benchmark::testing
