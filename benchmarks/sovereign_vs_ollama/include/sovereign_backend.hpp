// Sovereign Backend Adapter
// Connects to RawrXD Sovereign Runtime via HTTP API
// Copyright (c) 2026 RawrXD Team

#pragma once

#include "benchmark_common.hpp"
#include "http_client.hpp"
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <chrono>

namespace rawrxd::benchmark {

// ============================================================================
// Sovereign API Types
// ============================================================================

struct SovereignGenerateRequest {
    std::string prompt;
    std::string model;
    int max_tokens = 512;
    float temperature = 0.0f;
    int seed = 42;
    bool stream = false;
    
    std::string ToJson() const;
};

struct SovereignGenerateResponse {
    std::string text;
    int tokens_generated = 0;
    double generation_time_ms = 0.0;
    double tokens_per_second = 0.0;
    bool success = false;
    std::string error_message;
    
    static SovereignGenerateResponse FromJson(const std::string& json);
};

struct SovereignAgentRequest {
    std::string role;
    std::string context;
    std::map<std::string, std::string> capabilities;
    
    std::string ToJson() const;
};

struct SovereignAgentResponse {
    std::string agent_id;
    std::string status;
    double spawn_time_ms = 0.0;
    bool success = false;
    std::string error_message;
    
    static SovereignAgentResponse FromJson(const std::string& json);
};

struct SovereignSwarmRequest {
    int count = 1;
    std::string task;
    std::string coordination_strategy = "round_robin";
    
    std::string ToJson() const;
};

struct SovereignSwarmResponse {
    std::vector<std::string> agent_ids;
    std::string swarm_id;
    double spawn_time_ms = 0.0;
    bool success = false;
    std::string error_message;
    
    static SovereignSwarmResponse FromJson(const std::string& json);
};

struct SovereignSEGRequest {
    std::string plan;
    std::map<std::string, std::string> parameters;
    
    std::string ToJson() const;
};

struct SovereignSEGResponse {
    std::string graph_id;
    std::string graph_json;
    double build_time_ms = 0.0;
    int node_count = 0;
    int edge_count = 0;
    bool success = false;
    std::string error_message;
    
    static SovereignSEGResponse FromJson(const std::string& json);
};

struct SovereignDecisionRequest {
    std::string context;
    std::vector<std::string> options;
    std::map<std::string, double> weights;
    
    std::string ToJson() const;
};

struct SovereignDecisionResponse {
    std::string selected_option;
    double confidence = 0.0;
    std::string reasoning;
    double decision_time_ms = 0.0;
    bool success = false;
    std::string error_message;
    
    static SovereignDecisionResponse FromJson(const std::string& json);
};

struct SovereignHealthResponse {
    bool healthy = false;
    std::string version;
    std::map<std::string, std::string> capabilities;
    double uptime_seconds = 0.0;
    
    static SovereignHealthResponse FromJson(const std::string& json);
};

// ============================================================================
// Sovereign Backend Adapter
// ============================================================================

class SovereignBackendAdapter : public BackendAdapter {
public:
    SovereignBackendAdapter();
    ~SovereignBackendAdapter() override;
    
    // BackendAdapter interface
    bool Initialize(const BenchmarkConfig& config) override;
    void Shutdown() override;
    
    // Core inference
    std::string Generate(const std::string& prompt, int max_tokens) override;
    double GetLastLatencyMs() const override { return last_latency_ms_; }
    double GetLastTokensPerSec() const override { return last_tokens_per_sec_; }
    
    // Agent operations
    std::string SpawnAgent(const std::string& role, const std::string& context) override;
    bool DestroyAgent(const std::string& agent_id) override;
    std::vector<std::string> ListAgents() override;
    
    // Swarm operations
    std::vector<std::string> SpawnSwarm(int count, const std::string& task) override;
    std::vector<std::string> ExecuteSwarm(const std::vector<std::string>& agents,
                                           const std::string& task) override;
    
    // SEG operations
    bool SupportsSEG() const override { return true; }
    std::string CreateExecutionGraph(const std::string& plan) override;
    bool ExecuteGraph(const std::string& graph_id) override;
    
    // Decision operations
    std::string MakeDecision(const std::string& context,
                              const std::vector<std::string>& options) override;
    
    // Resource sampling
    ResourceMetrics GetResourceUsage() override;
    
    // Sovereign-specific methods
    bool HealthCheck();
    std::string GetVersion();
    bool WaitForReady(int timeout_seconds = 30);
    
    // Statistics
    struct Stats {
        uint64_t total_requests = 0;
        uint64_t successful_requests = 0;
        uint64_t failed_requests = 0;
        double average_latency_ms = 0.0;
        double total_tokens_generated = 0.0;
        double total_generation_time_ms = 0.0;
    };
    Stats GetStats() const;
    void ResetStats();
    
private:
    // Configuration
    std::string endpoint_ = "http://localhost:8080";
    std::string model_name_ = "phi-3-mini-Q4";
    int default_max_tokens_ = 512;
    float default_temperature_ = 0.0f;
    int default_seed_ = 42;
    
    // HTTP client
    std::unique_ptr<HttpClient> http_client_;
    
    // State
    bool initialized_ = false;
    double last_latency_ms_ = 0.0;
    double last_tokens_per_sec_ = 0.0;
    std::map<std::string, std::string> active_agents_;
    std::map<std::string, std::string> active_graphs_;
    
    // Statistics
    mutable std::mutex stats_mutex_;
    Stats stats_;
    
    // Internal methods
    std::string BuildUrl(const std::string& path);
    bool ParseEndpoint(const std::string& endpoint, std::string& host, int& port);
    void UpdateStats(bool success, double latency_ms, int tokens = 0);
    
    // Retry logic
    template<typename Func>
    auto ExecuteWithRetry(Func&& func, int max_retries = 3) -> decltype(func());
};

// Factory function declaration
std::unique_ptr<BackendAdapter> CreateSovereignBackendAdapter();

} // namespace rawrxd::benchmark
