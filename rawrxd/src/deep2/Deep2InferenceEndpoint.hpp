#pragma once
#include <string>
#include <vector>
#include <map>
#include <optional>
#include <memory>
#include <mutex>
#include <chrono>
#include <functional>

namespace rawrxd::deep2 {

// ───────────────────────────────────────────────────────────────
// HTTP endpoint request/response
// ───────────────────────────────────────────────────────────────
struct EndpointRequest {
    std::string method;
    std::string path;
    std::map<std::string, std::string> headers;
    std::string body;
    std::string content_type;
};

struct EndpointResponse {
    int status_code = 200;
    std::map<std::string, std::string> headers;
    std::string body;
    std::string content_type = "application/json";
    float latency_ms = 0.0f;
};

// ───────────────────────────────────────────────────────────────
// Inference endpoint — REST API for model inference
// ───────────────────────────────────────────────────────────────
class Deep2InferenceEndpoint {
public:
    using RequestHandler = std::function<EndpointResponse(const EndpointRequest&)>;

    Deep2InferenceEndpoint();
    ~Deep2InferenceEndpoint();

    // Lifecycle
    bool Initialize(const std::string& bind_address, uint16_t port);
    void Shutdown();
    bool IsRunning() const;

    // Routing
    void RegisterRoute(const std::string& method, const std::string& path, RequestHandler handler);
    void UnregisterRoute(const std::string& method, const std::string& path);

    // Default handlers
    void SetHealthCheckHandler(RequestHandler handler);
    void SetInferenceHandler(RequestHandler handler);
    void SetModelInfoHandler(RequestHandler handler);

    // Metrics
    uint64_t GetRequestCount() const;
    uint64_t GetErrorCount() const;
    float GetAvgLatencyMs() const;
    void ResetMetrics();

    // Control
    void SetMaxConcurrentRequests(size_t max);
    void SetRequestTimeoutMs(uint32_t ms);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace rawrxd::deep2
