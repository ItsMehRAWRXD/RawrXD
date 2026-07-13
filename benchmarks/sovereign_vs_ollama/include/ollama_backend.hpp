// Ollama Backend Adapter
// Connects to Ollama API via HTTP
// Copyright (c) 2026 RawrXD Team

#pragma once

#include "benchmark_common.hpp"
#include "http_client.hpp"
#include <string>
#include <vector>
#include <map>
#include <memory>

namespace rawrxd::benchmark {

// ============================================================================
// Ollama API Types
// ============================================================================

struct OllamaGenerateRequest {
    std::string model;
    std::string prompt;
    std::vector<std::string> images;  // For multimodal models
    std::string format;              // "json" for JSON output
    
    // Options
    struct Options {
        int numa = 0;
        int num_ctx = 2048;
        int num_keep = 5;
        int seed = 42;
        int num_predict = -1;
        int top_k = 40;
        float top_p = 0.9f;
        float temperature = 0.0f;
        float repeat_penalty = 1.1f;
        int repeat_last_n = 64;
        float tfs_z = 1.0f;
        float mirostat = 0.0f;
        float mirostat_eta = 0.1f;
        float mirostat_tau = 5.0f;
        int num_gpu = 1;
        int main_gpu = 0;
        bool low_vram = false;
        bool f16_kv = true;
        int vocab_only = 0;
        int use_mmap = 1;
        int use_mlock = 0;
        int num_thread = 0;  // 0 = auto
        
        std::string ToJson() const;
    } options;
    
    bool stream = false;
    std::string raw = "";  // Raw prompt (no template)
    
    std::string ToJson() const;
};

struct OllamaGenerateResponse {
    std::string model;
    std::string created_at;
    std::string response;
    bool done = false;
    
    // Only present when done=true
    struct DoneData {
        std::string context;  // Base64-encoded context
        int total_duration = 0;
        int load_duration = 0;
        int prompt_eval_count = 0;
        int prompt_eval_duration = 0;
        int eval_count = 0;
        int eval_duration = 0;
    } done_data;
    
    bool success = false;
    std::string error_message;
    
    static OllamaGenerateResponse FromJson(const std::string& json);
    
    // Calculate tokens per second
    double GetTokensPerSecond() const {
        if (done_data.eval_duration > 0) {
            return static_cast<double>(done_data.eval_count) / 
                   (done_data.eval_duration / 1e9);  // Convert ns to s
        }
        return 0.0;
    }
    
    // Calculate total latency in ms
    double GetTotalLatencyMs() const {
        return done_data.total_duration / 1e6;  // Convert ns to ms
    }
};

struct OllamaChatMessage {
    std::string role;      // "system", "user", or "assistant"
    std::string content;
    std::vector<std::string> images;  // For multimodal
    
    std::string ToJson() const;
    static OllamaChatMessage FromJson(const std::string& json);
};

struct OllamaChatRequest {
    std::string model;
    std::vector<OllamaChatMessage> messages;
    OllamaGenerateRequest::Options options;
    std::string format;
    bool stream = false;
    std::string keep_alive = "5m";
    
    std::string ToJson() const;
};

struct OllamaChatResponse {
    std::string model;
    std::string created_at;
    OllamaChatMessage message;
    bool done = false;
    OllamaGenerateResponse::DoneData done_data;
    
    bool success = false;
    std::string error_message;
    
    static OllamaChatResponse FromJson(const std::string& json);
};

struct OllamaModelInfo {
    std::string name;
    std::string modified_at;
    int64_t size = 0;
    std::string digest;
    struct Details {
        std::string format;
        std::string family;
        std::vector<std::string> families;
        std::string parameter_size;
        std::string quantization_level;
    } details;
};

struct OllamaListResponse {
    std::vector<OllamaModelInfo> models;
    bool success = false;
    std::string error_message;
    
    static OllamaListResponse FromJson(const std::string& json);
};

struct OllamaPullRequest {
    std::string name;
    bool insecure = false;
    bool stream = false;
};

struct OllamaPullResponse {
    std::string status;
    std::string digest;
    int total = 0;
    int completed = 0;
    bool success = false;
    std::string error_message;
    
    static OllamaPullResponse FromJson(const std::string& json);
};

struct OllamaEmbedRequest {
    std::string model;
    std::string prompt;
    std::vector<std::string> options;
    bool truncate = true;
    std::string keep_alive = "5m";
};

struct OllamaEmbedResponse {
    std::vector<double> embedding;
    bool success = false;
    std::string error_message;
    
    static OllamaEmbedResponse FromJson(const std::string& json);
};

struct OllamaPsResponse {
    struct RunningModel {
        std::string name;
        std::string model;
        int64_t size = 0;
        std::string digest;
        struct Details {
            std::string parent_model;
            std::string format;
            std::string family;
            std::vector<std::string> families;
            std::string parameter_size;
            std::string quantization_level;
        } details;
        int64_t expires_at = 0;
        int64_t size_vram = 0;
    };
    
    std::vector<RunningModel> models;
    bool success = false;
    std::string error_message;
    
    static OllamaPsResponse FromJson(const std::string& json);
};

// ============================================================================
// Ollama Backend Adapter
// ============================================================================

class OllamaBackendAdapter : public BackendAdapter {
public:
    OllamaBackendAdapter();
    ~OllamaBackendAdapter() override;
    
    // BackendAdapter interface
    bool Initialize(const BenchmarkConfig& config) override;
    void Shutdown() override;
    
    // Core inference
    std::string Generate(const std::string& prompt, int max_tokens) override;
    double GetLastLatencyMs() const override { return last_latency_ms_; }
    double GetLastTokensPerSec() const override { return last_tokens_per_sec_; }
    
    // Agent operations (Ollama doesn't natively support agents, simulate)
    std::string SpawnAgent(const std::string& role, const std::string& context) override;
    bool DestroyAgent(const std::string& agent_id) override;
    std::vector<std::string> ListAgents() override;
    
    // Swarm operations (Ollama doesn't natively support swarms, simulate)
    std::vector<std::string> SpawnSwarm(int count, const std::string& task) override;
    std::vector<std::string> ExecuteSwarm(const std::vector<std::string>& agents,
                                           const std::string& task) override;
    
    // SEG operations (Ollama doesn't support SEG)
    bool SupportsSEG() const override { return false; }
    std::string CreateExecutionGraph(const std::string& plan) override;
    bool ExecuteGraph(const std::string& graph_id) override;
    
    // Decision operations (use chat API)
    std::string MakeDecision(const std::string& context,
                              const std::vector<std::string>& options) override;
    
    // Resource sampling
    ResourceMetrics GetResourceUsage() override;
    
    // Ollama-specific methods
    bool HealthCheck();
    std::vector<OllamaModelInfo> ListModels();
    bool PullModel(const std::string& model_name);
    bool DeleteModel(const std::string& model_name);
    bool IsModelRunning(const std::string& model_name);
    bool WaitForModelReady(const std::string& model_name, int timeout_seconds = 60);
    
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
    std::string endpoint_ = "http://localhost:11434";
    std::string model_name_ = "phi3:mini";
    int default_max_tokens_ = 512;
    float default_temperature_ = 0.0f;
    int default_seed_ = 42;
    
    // HTTP client
    std::unique_ptr<HttpClient> http_client_;
    
    // State
    bool initialized_ = false;
    double last_latency_ms_ = 0.0;
    double last_tokens_per_sec_ = 0.0;
    
    // Simulated agents (Ollama doesn't have native agents)
    std::map<std::string, std::pair<std::string, std::string>> simulated_agents_;
    int next_agent_id_ = 1;
    
    // Statistics
    mutable std::mutex stats_mutex_;
    Stats stats_;
    
    // Internal methods
    std::string BuildUrl(const std::string& path);
    bool ParseEndpoint(const std::string& endpoint, std::string& host, int& port);
    void UpdateStats(bool success, double latency_ms, int tokens = 0);
    
    // Agent simulation
    std::string SimulateAgentPrompt(const std::string& role, 
                                     const std::string& context,
                                     const std::string& task);
    std::string SimulateDecisionPrompt(const std::string& context,
                                        const std::vector<std::string>& options);
    
    // Retry logic
    template<typename Func>
    auto ExecuteWithRetry(Func&& func, int max_retries = 3) -> decltype(func());
};

// Factory function declaration
std::unique_ptr<BackendAdapter> CreateOllamaBackendAdapter();

} // namespace rawrxd::benchmark
