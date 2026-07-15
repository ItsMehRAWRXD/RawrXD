#include "inference_gateway.h"
#include "universal_model_router.h"
#include "cpu_inference_engine.h"
#include "cloud_api_client.h"
#include <chrono>
#include <thread>
#include <sstream>

namespace RawrXD {

// ============================================================================
// Singleton
// ============================================================================
InferenceGateway& InferenceGateway::instance() {
    static InferenceGateway instance;
    return instance;
}

InferenceGateway::InferenceGateway() 
    : m_globalMode(RuntimeMode::HybridControlled) {
}

// ============================================================================
// Main entry point - THE ONLY GATE
// ============================================================================
InferenceResponse InferenceGateway::execute(const InferenceRequest& request) {
    InferenceResponse response;
    auto startTime = std::chrono::steady_clock::now();

    // Step 1: Validate request
    std::string validationError;
    if (!validateRequest(request, validationError)) {
        response.success = false;
        response.error = validationError;
        return response;
    }

    // Step 2: Determine policy
    RuntimeMode mode = request.runtimeMode.value_or(m_globalMode);
    ModelExecutionProfile profile;
    profile.runtimeMode = mode;
    profile.allowLocal = true;
    profile.allowRemote = request.allowRemote.value_or(
        mode == RuntimeMode::FullyDistributed);

    // Step 3: Policy decision
    auto& policyRouter = GetGlobalPolicyRouter();
    ExecutionPath path = policyRouter.decideExecutionPath(
        request.model, profile, true, false); // TODO: detect actual availability

    response.executionPath = path;
    response.routingLog = policyRouter.getLastDecisionLog();

    // Step 4: Execute through chosen path
    switch (path) {
        case ExecutionPath::LOCAL_GGUF:
            response = executeLocalGGUF(request);
            break;
        case ExecutionPath::LOCAL_OLLAMA:
            response = executeLocalOllama(request);
            break;
        case ExecutionPath::REMOTE_CLOUD:
            if (profile.allowRemote) {
                response = executeRemoteCloud(request);
            } else {
                response.success = false;
                response.error = "Cloud execution blocked by policy";
                response.executionPath = ExecutionPath::LOCAL_OLLAMA;
            }
            break;
        default:
            response.success = false;
            response.error = "Unknown execution path";
    }

    // Step 5: Record latency and trace
    auto endTime = std::chrono::steady_clock::now();
    response.latencyMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        endTime - startTime).count();

    {
        std::lock_guard<std::mutex> lock(m_traceMutex);
        m_recentTraces.push_back(response);
        if (m_recentTraces.size() > 100) {
            m_recentTraces.erase(m_recentTraces.begin());
        }
    }

    if (m_traceCallback) {
        m_traceCallback(response);
    }

    // Step 6: Log result
    fprintf(stderr, "[InferenceGateway] Result: %s path=%s latency=%lldms\n",
        response.success ? "SUCCESS" : "FAILED",
        response.routingLog.c_str(),
        response.latencyMs);

    return response;
}

// ============================================================================
// Streaming execution
// ============================================================================
void InferenceGateway::executeStream(const InferenceRequest& request, 
                                      StreamCallback callback) {
    if (!callback) return;

    // For now, execute synchronously and simulate streaming
    // TODO: Implement true streaming through policy router
    auto response = execute(request);
    
    if (response.success) {
        // Simulate chunking
        const std::string& text = response.text;
        size_t pos = 0;
        while (pos < text.size()) {
            size_t chunkSize = std::min(size_t(10), text.size() - pos);
            callback(text.substr(pos, chunkSize), false);
            pos += chunkSize;
        }
        callback("", true);
    } else {
        callback("Error: " + response.error, true);
    }
}

// ============================================================================
// Async execution
// ============================================================================
void InferenceGateway::executeAsync(const InferenceRequest& request,
                                     std::function<void(const InferenceResponse&)> callback) {
    std::thread([this, request, callback]() {
        auto response = execute(request);
        if (callback) callback(response);
    }).detach();
}

// ============================================================================
// Validation
// ============================================================================
bool InferenceGateway::validateRequest(const InferenceRequest& request, 
                                        std::string& error) const {
    if (request.model.empty()) {
        error = "Model name required";
        return false;
    }
    if (request.prompt.empty()) {
        error = "Prompt required";
        return false;
    }
    if (request.temperature < 0.0f || request.temperature > 2.0f) {
        error = "Temperature must be 0.0-2.0";
        return false;
    }
    return true;
}

// ============================================================================
// Execution paths
// ============================================================================
InferenceResponse InferenceGateway::executeLocalGGUF(const InferenceRequest& request) {
    InferenceResponse response;
    
    // TODO: Integrate with actual GGUF loader
    // For now, fall through to Ollama
    fprintf(stderr, "[InferenceGateway] LOCAL_GGUF not yet wired, falling back to Ollama\n");
    return executeLocalOllama(request);
}

InferenceResponse InferenceGateway::executeLocalOllama(const InferenceRequest& request) {
    InferenceResponse response;
    
    // Use UniversalModelRouter's Ollama integration
    UniversalModelRouter router;
    std::string result = router.routeQuery(request.model, request.prompt, request.temperature);
    
    if (result.rfind("Error:", 0) == 0) {
        response.success = false;
        response.error = result;
    } else {
        response.success = true;
        response.text = result;
    }
    
    return response;
}

InferenceResponse InferenceGateway::executeRemoteCloud(const InferenceRequest& request) {
    InferenceResponse response;
    
    // Get capability token from TokenAuthority
    auto& authority = TokenAuthority::instance();
    std::string proof = authority.generateAuthorizationProof(
        RuntimeMode::FullyDistributed, "gateway");
    auto cap = authority.mintRemoteCloudCapability(proof);
    
    // CloudApiClient now REQUIRES a valid capability token
    CloudApiClient cloudClient(std::move(cap));
    CloudModelConfig config;
    config.model = request.model;
    config.temperature = request.temperature;
    config.maxTokens = request.maxTokens;
    
    std::string result = cloudClient.generate(request.prompt, config);
    
    if (result.rfind("Error:", 0) == 0) {
        response.success = false;
        response.error = result;
    } else {
        response.success = true;
        response.text = result;
    }
    
    return response;
}

// ============================================================================
// Policy management
// ============================================================================
void InferenceGateway::setGlobalRuntimeMode(RuntimeMode mode) {
    m_globalMode = mode;
    SetGlobalRuntimeMode(mode); // Also update policy router
}

RuntimeMode InferenceGateway::getGlobalRuntimeMode() const {
    return m_globalMode;
}

// ============================================================================
// Observability
// ============================================================================
std::vector<std::string> InferenceGateway::getRecentTraces(int count) const {
    std::lock_guard<std::mutex> lock(m_traceMutex);
    std::vector<std::string> traces;
    
    int start = std::max(0, (int)m_recentTraces.size() - count);
    for (int i = start; i < (int)m_recentTraces.size(); ++i) {
        const auto& r = m_recentTraces[i];
        std::stringstream ss;
        ss << "[" << r.latencyMs << "ms] " 
           << (r.success ? "OK" : "FAIL") 
           << " path=" << (int)r.executionPath
           << " error=" << r.error;
        traces.push_back(ss.str());
    }
    
    return traces;
}

void InferenceGateway::setTraceCallback(std::function<void(const InferenceResponse&)> cb) {
    m_traceCallback = cb;
}

} // namespace RawrXD
