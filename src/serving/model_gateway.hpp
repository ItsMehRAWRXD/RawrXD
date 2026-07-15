#pragma once

#include "model_registry.hpp"
#include "traffic_router.hpp"
#include "ab_testing.hpp"
#include <memory>
#include <thread>
#include <atomic>

namespace rawrxd {
namespace serving {

// Gateway configuration
struct GatewayConfig {
    // Server settings
    std::string host = "0.0.0.0";
    int port = 8080;
    int threads = 0;  // 0 = auto-detect
    
    // Timeouts
    std::chrono::seconds request_timeout{300};
    std::chrono::seconds keepalive_timeout{60};
    
    // Limits
    size_t max_request_size = 100 * 1024 * 1024;  // 100MB
    size_t max_concurrent_requests = 1000;
    size_t request_queue_size = 10000;
    
    // Features
    bool enable_cors = true;
    bool enable_compression = true;
    bool enable_request_logging = true;
    bool enable_metrics = true;
    
    // Authentication
    bool require_auth = false;
    std::string auth_header = "Authorization";
    std::string api_key_prefix = "Bearer ";
};

// Request/Response types
struct InferenceRequest {
    std::string request_id;
    std::string model_id;
    std::string version_id;  // Optional
    std::string prompt;
    std::unordered_map<std::string, std::string> parameters;
    std::unordered_map<std::string, std::string> metadata;
    std::chrono::system_clock::time_point received_at;
};

struct InferenceResponse {
    std::string request_id;
    std::string model_id;
    std::string version_id;
    std::string generated_text;
    size_t tokens_generated;
    size_t tokens_prompt;
    float latency_ms;
    bool cached;
    std::unordered_map<std::string, std::string> metadata;
};

// Model gateway for multi-model serving
class ModelGateway {
public:
    explicit ModelGateway(const GatewayConfig& config = {});
    ~ModelGateway();
    
    // Lifecycle
    bool initialize();
    bool start();
    bool stop();
    bool isRunning() const;
    
    // Component access
    ModelRegistry& getRegistry();
    TrafficRouter& getRouter();
    ABTestingFramework& getABTesting();
    
    // Request handling
    InferenceResponse handleRequest(const InferenceRequest& request);
    std::vector<InferenceResponse> handleBatch(const std::vector<InferenceRequest>& requests);
    
    // Streaming support
    using StreamCallback = std::function<void(const std::string& chunk, bool done)>;
    void handleStreamRequest(const InferenceRequest& request, StreamCallback callback);
    
    // Health and metrics
    struct HealthStatus {
        bool healthy;
        std::string status;
        size_t active_requests;
        size_t queued_requests;
        float requests_per_second;
        float avg_latency_ms;
        std::unordered_map<std::string, std::string> component_status;
    };
    HealthStatus getHealth() const;
    
    struct Metrics {
        size_t total_requests;
        size_t successful_requests;
        size_t failed_requests;
        size_t cached_requests;
        float avg_latency_ms;
        float p95_latency_ms;
        float p99_latency_ms;
        std::unordered_map<std::string, size_t> model_requests;
        std::unordered_map<std::string, size_t> error_counts;
    };
    Metrics getMetrics() const;
    void resetMetrics();
    
    // Prometheus metrics export
    std::string exportPrometheusMetrics() const;
    
    // Admin operations
    bool reloadConfiguration();
    std::vector<std::string> getActiveModels() const;
    bool warmupModel(const std::string& model_id, const std::string& version_id);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// Gateway builder for easy configuration
class GatewayBuilder {
public:
    GatewayBuilder& withHost(const std::string& host);
    GatewayBuilder& withPort(int port);
    GatewayBuilder& withThreads(int threads);
    GatewayBuilder& withTimeout(std::chrono::seconds timeout);
    GatewayBuilder& withMaxRequestSize(size_t size);
    GatewayBuilder& withCORS(bool enabled);
    GatewayBuilder& withCompression(bool enabled);
    GatewayBuilder& withAuth(bool required);
    
    std::unique_ptr<ModelGateway> build();

private:
    GatewayConfig config_;
};

// Request metrics collector
class RequestMetricsCollector {
public:
    void recordRequest(const std::string& model_id,
                      const std::string& version_id,
                      float latency_ms,
                      bool success,
                      bool cached);
    
    void recordTokens(const std::string& model_id,
                     size_t prompt_tokens,
                     size_t generated_tokens);
    
    void recordError(const std::string& model_id,
                    const std::string& error_type);
    
    // Get aggregated metrics
    struct AggregatedMetrics {
        size_t total_requests;
        size_t successful_requests;
        size_t failed_requests;
        float avg_latency_ms;
        float p95_latency_ms;
        float p99_latency_ms;
        size_t total_tokens_prompt;
        size_t total_tokens_generated;
    };
    AggregatedMetrics getMetrics(const std::string& model_id = "") const;
    
    // Export
    std::string exportJSON() const;
    std::string exportPrometheus() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace serving
} // namespace rawrxd
