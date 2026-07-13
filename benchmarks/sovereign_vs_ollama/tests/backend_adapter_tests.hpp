// Backend Adapter Integration Tests
// Copyright (c) 2026 RawrXD Team

#pragma once

#include "sovereign_backend.hpp"
#include "ollama_backend.hpp"
#include "http_client_tests.hpp"
#include <string>
#include <vector>
#include <memory>

namespace rawrxd::benchmark::testing {

// ============================================================================
// Backend Adapter Test Suite
// ============================================================================

class BackendAdapterTestSuite {
public:
    // Run all backend tests
    static std::vector<TestResult> RunAllTests();
    
    // Individual test categories
    static std::vector<TestResult> RunSovereignTests();
    static std::vector<TestResult> RunOllamaTests();
    static std::vector<TestResult> RunComparisonTests();
    static std::vector<TestResult> RunFactoryTests();
    static std::vector<TestResult> RunHealthCheckTests();

private:
    // Sovereign Backend Tests
    static TestResult TestSovereignInitialization();
    static TestResult TestSovereignGenerate();
    static TestResult TestSovereignAgentSpawn();
    static TestResult TestSovereignSwarm();
    static TestResult TestSovereignSEG();
    static TestResult TestSovereignDecision();
    static TestResult TestSovereignHealthCheck();
    static TestResult TestSovereignResourceMetrics();
    
    // Ollama Backend Tests
    static TestResult TestOllamaInitialization();
    static TestResult TestOllamaGenerate();
    static TestResult TestOllamaChat();
    static TestResult TestOllamaModelList();
    static TestResult TestOllamaSimulatedAgent();
    static TestResult TestOllamaDecision();
    static TestResult TestOllamaHealthCheck();
    
    // Comparison Tests
    static TestResult TestBackendParity();
    static TestResult TestLatencyComparison();
    static TestResult TestThroughputComparison();
    static TestResult TestFeatureMatrix();
    static TestResult TestErrorHandlingComparison();
    
    // Factory Tests
    static TestResult TestFactoryCreateSovereign();
    static TestResult TestFactoryCreateOllama();
    static TestResult TestFactoryCreateByName();
    static TestResult TestFactoryAvailability();
    static TestResult TestFactoryInvalidBackend();
    
    // Health Check Tests
    static TestResult TestSovereignHealthEndpoint();
    static TestResult TestOllamaHealthEndpoint();
    static TestResult TestHealthCheckTimeout();
    static TestResult TestHealthCheckRetry();
    static TestResult TestWaitForReady();
};

// ============================================================================
// Mock Sovereign Server
// ============================================================================

class MockSovereignServer : public MockHttpServer {
public:
    MockSovereignServer(int port = 18080);
    ~MockSovereignServer();
    
    // Setup default responses
    void SetupDefaultResponses();
    
    // Configure specific responses
    void SetGenerateResponse(const std::string& text, int tokens, double tps);
    void SetAgentResponse(const std::string& agent_id, const std::string& status);
    void SetSwarmResponse(const std::string& swarm_id, 
                          const std::vector<std::string>& agent_ids);
    void SetSEGResponse(const std::string& graph_id, int nodes, int edges);
    void SetDecisionResponse(const std::string& selected_option, double confidence);
    void SetHealthResponse(bool healthy, const std::string& version);
    void SetMetricsResponse(double cpu, double memory, double gpu);
};

// ============================================================================
// Mock Ollama Server
// ============================================================================

class MockOllamaServer : public MockHttpServer {
public:
    MockOllamaServer(int port = 18081);
    ~MockOllamaServer();
    
    // Setup default responses
    void SetupDefaultResponses();
    
    // Configure specific responses
    void SetGenerateResponse(const std::string& text, int eval_count, int eval_duration);
    void SetChatResponse(const std::string& role, const std::string& content);
    void SetModelListResponse(const std::vector<std::string>& models);
    void SetPullResponse(const std::string& status);
    void SetHealthResponse(bool healthy);
};

// ============================================================================
// Backend Test Fixture
// ============================================================================

class BackendTestFixture {
public:
    BackendTestFixture();
    ~BackendTestFixture();
    
    void SetUp();
    void TearDown();
    
    // Get adapters
    SovereignBackendAdapter* GetSovereignAdapter() { return sovereign_adapter_.get(); }
    OllamaBackendAdapter* GetOllamaAdapter() { return ollama_adapter_.get(); }
    
    // Get mock servers
    MockSovereignServer* GetSovereignServer() { return &sovereign_server_; }
    MockOllamaServer* GetOllamaServer() { return &ollama_server_; }
    
    // Configuration helpers
    BenchmarkConfig CreateSovereignConfig();
    BenchmarkConfig CreateOllamaConfig();

protected:
    std::unique_ptr<SovereignBackendAdapter> sovereign_adapter_;
    std::unique_ptr<OllamaBackendAdapter> ollama_adapter_;
    MockSovereignServer sovereign_server_;
    MockOllamaServer ollama_server_;
};

// ============================================================================
// Integration Test Runner
// ============================================================================

class BackendIntegrationTestRunner {
public:
    static int Run(int argc, char** argv);
    static std::vector<TestResult> RunCategory(const std::string& category);
    static void PrintResults(const std::vector<TestResult>& results);
    static std::string GenerateReport(const std::vector<TestResult>& results);
};

// ============================================================================
// Feature Matrix
// ============================================================================

struct FeatureMatrix {
    struct Feature {
        std::string name;
        bool sovereign_supported;
        bool ollama_supported;
        std::string notes;
    };
    
    std::vector<Feature> features;
    
    void AddFeature(const std::string& name, bool sovereign, bool ollama, 
                    const std::string& notes = "");
    void Print() const;
    std::string ToJson() const;
    
    static FeatureMatrix Generate();
};

// ============================================================================
// Performance Comparison
// ============================================================================

struct PerformanceComparison {
    std::string benchmark_name;
    double sovereign_latency_ms;
    double ollama_latency_ms;
    double sovereign_throughput_tps;
    double ollama_throughput_tps;
    double latency_difference_percent;
    double throughput_difference_percent;
    bool sovereign_faster;
    bool sovereign_higher_throughput;
    
    void CalculateDifferences();
    std::string ToString() const;
    std::string ToJson() const;
};

class PerformanceComparator {
public:
    static PerformanceComparison Compare(const std::string& benchmark_name,
                                          const BenchmarkResult& sovereign_result,
                                          const BenchmarkResult& ollama_result);
    
    static std::vector<PerformanceComparison> CompareAll(
        const std::vector<BenchmarkResult>& sovereign_results,
        const std::vector<BenchmarkResult>& ollama_results);
    
    static std::string GenerateReport(const std::vector<PerformanceComparison>& comparisons);
};

} // namespace rawrxd::benchmark::testing
