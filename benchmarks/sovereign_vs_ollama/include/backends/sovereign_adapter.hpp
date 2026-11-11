// sovereign_adapter.hpp
// HTTP adapter for RawrXD Sovereign Runtime

#ifndef SOVEREIGN_ADAPTER_HPP
#define SOVEREIGN_ADAPTER_HPP

#include "benchmark_common.hpp"
#include <string>
#include <memory>
#include <chrono>

// Forward declare CURL
typedef void CURL;

namespace Benchmark {
namespace Backends {

// Request/Result structures
struct InferenceRequest {
    std::string model;
    std::string prompt;
    float temperature = 0.0f;
    int max_tokens = 256;
    std::optional<int> seed;
};

struct InferenceResult {
    bool success = false;
    std::string error_message;
    
    // Timing
    double time_to_first_token_ms = 0.0;
    double total_latency_ms = 0.0;
    
    // Throughput
    int tokens_generated = 0;
    double tokens_per_second = 0.0;
    
    // Output
    std::string generated_text;
};

struct AgentSpawnRequest {
    std::string agent_type;
    std::string task_description;
    int swarm_size = 1;
};

struct AgentSpawnResult {
    bool success = false;
    std::string error_message;
    
    std::string agent_id;
    double spawn_time_ms = 0.0;
    double memory_mb = 0.0;
};

struct SwarmRequest {
    std::string task;
    int agent_count = 16;
    std::string coordination_strategy = "consensus";
};

struct SwarmResult {
    bool success = false;
    std::string error_message;
    
    double total_time_ms = 0.0;
    int tasks_completed = 0;
    double efficiency = 0.0;
};

// Sovereign Adapter Class
class SovereignAdapter {
public:
    explicit SovereignAdapter(const std::string& base_url = "http://localhost:8080");
    ~SovereignAdapter();
    
    // Connection
    bool IsAvailable();
    std::string GetBackendName() const;
    std::string GetBackendVersion();
    
    // Core operations
    InferenceResult RunInference(const InferenceRequest& request);
    AgentSpawnResult SpawnAgent(const AgentSpawnRequest& request);
    SwarmResult ExecuteSwarm(const SwarmRequest& request);
    
private:
    std::string base_url_;
    CURL* curl_;
    
    // HTTP helpers
    bool HttpGet(const std::string& endpoint, std::string& response);
    bool HttpPost(const std::string& endpoint, const std::string& json_body, std::string& response);
    
    // Response parsers
    InferenceResult ParseInferenceResponse(const std::string& json);
    AgentSpawnResult ParseAgentSpawnResponse(const std::string& json);
    SwarmResult ParseSwarmResponse(const std::string& json);
    std::string ParseVersion(const std::string& json);
    
    // Utilities
    std::string EscapeJson(const std::string& input);
};

} // namespace Backends
} // namespace Benchmark

#endif // SOVEREIGN_ADAPTER_HPP
