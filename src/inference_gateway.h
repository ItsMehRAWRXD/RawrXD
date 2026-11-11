#pragma once
#ifndef RAWRXD_INFERENCE_GATEWAY_H
#define RAWRXD_INFERENCE_GATEWAY_H

#include "execution_policy.h"
#include "execution_capability.h"
#include <string>
#include <functional>
#include <vector>
#include <optional>
#include <mutex>

namespace RawrXD {

// ============================================================================
// Centralized Inference Gateway
// ALL model execution MUST pass through this gate
// No exceptions. No bypass. No raw backend calls.
// ============================================================================

struct InferenceRequest {
    std::string model;
    std::string prompt;
    float temperature = 0.7f;
    int maxTokens = 2048;
    std::string systemPrompt;
    bool stream = false;
    
    // Optional policy override (uses global if not set)
    std::optional<RuntimeMode> runtimeMode;
    std::optional<bool> allowRemote;
};

struct InferenceResponse {
    bool success = false;
    std::string text;
    std::string error;
    ExecutionPath executionPath = ExecutionPath::LOCAL_GGUF;
    std::string routingLog;
    int64_t latencyMs = 0;
};

// ============================================================================
// The ONE gateway for ALL inference
// ============================================================================
class InferenceGateway {
public:
    using StreamCallback = std::function<void(const std::string& chunk, bool complete)>;
    using DecisionCallback = std::function<void(const InferenceResponse&)>;

    static InferenceGateway& instance();

    // Main entry point - ALL inference goes here
    InferenceResponse execute(const InferenceRequest& request);
    
    // Streaming variant
    void executeStream(const InferenceRequest& request, StreamCallback callback);
    
    // Async variant
    void executeAsync(const InferenceRequest& request, 
                      std::function<void(const InferenceResponse&)> callback);

    // Policy enforcement
    void setGlobalRuntimeMode(RuntimeMode mode);
    RuntimeMode getGlobalRuntimeMode() const;
    
    // Observability
    std::vector<std::string> getRecentTraces(int count = 10) const;
    void setTraceCallback(std::function<void(const InferenceResponse&)> cb);

    // Validation
    bool validateRequest(const InferenceRequest& request, std::string& error) const;

private:
    InferenceGateway();
    ~InferenceGateway() = default;
    
    InferenceGateway(const InferenceGateway&) = delete;
    InferenceGateway& operator=(const InferenceGateway&) = delete;

    // Internal execution paths
    InferenceResponse executeLocalGGUF(const InferenceRequest& request);
    InferenceResponse executeLocalOllama(const InferenceRequest& request);
    InferenceResponse executeRemoteCloud(const InferenceRequest& request);
    
    // Tracing
    mutable std::mutex m_traceMutex;
    std::vector<InferenceResponse> m_recentTraces;
    std::function<void(const InferenceResponse&)> m_traceCallback;
    
    // Policy
    RuntimeMode m_globalMode = RuntimeMode::HybridControlled;
};

// ============================================================================
// Convenience helpers (all route through gateway)
// ============================================================================
inline InferenceResponse Generate(const std::string& model, 
                                   const std::string& prompt,
                                   float temperature = 0.7f) {
    InferenceRequest req;
    req.model = model;
    req.prompt = prompt;
    req.temperature = temperature;
    return InferenceGateway::instance().execute(req);
}

inline void GenerateStream(const std::string& model,
                           const std::string& prompt,
                           InferenceGateway::StreamCallback callback) {
    InferenceRequest req;
    req.model = model;
    req.prompt = prompt;
    req.stream = true;
    InferenceGateway::instance().executeStream(req, callback);
}

} // namespace RawrXD

#endif // RAWRXD_INFERENCE_GATEWAY_H
