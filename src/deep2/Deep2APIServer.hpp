// ============================================================================
// Deep2APIServer.hpp - REST API Server for Deep2 Engine
// Phase 0: Backend Binding - Removes Ollama dependency
// ============================================================================

#pragma once

#include "Deep2Engine.h"
#include "Deep2Discovery.h"
#include <string>
#include <functional>
#include <map>
#include <vector>
#include <memory>
#include <thread>
#include <mutex>

namespace Deep2 {

// API Request/Response types
struct APIRequest {
    std::string method;
    std::string path;
    std::map<std::string, std::string> headers;
    std::string body;
};

struct APIResponse {
    int statusCode;
    std::map<std::string, std::string> headers;
    std::string body;
};

struct BackendInfo {
    std::string name;
    std::string version;
    std::vector<std::string> capabilities;
    bool available;
};

struct GenerateRequest {
    std::string model;
    std::string prompt;
    int maxTokens;
    float temperature;
    float topP;
    int topK;
    std::vector<std::string> stopSequences;
    bool stream;
};

struct GenerateResponse {
    std::string text;
    int tokensGenerated;
    double tokensPerSecond;
    double latencyMs;
    bool done;
    std::string finishReason;
};

// Forward declarations
class Deep2Engine;

// ============================================================================
// Deep2 API Server
// ============================================================================
class Deep2APIServer {
public:
    Deep2APIServer();
    ~Deep2APIServer();

    // Initialize with engine instance
    bool Initialize(Deep2Engine* engine);

    // Start/stop server
    bool Start(int port = 11435); // Default Deep2 port (Ollama compatible)
    void Stop();
    bool IsRunning() const;

    // API Endpoints
    APIResponse HandleRequest(const APIRequest& request);

    // Specific endpoint handlers
    APIResponse GetVersion();
    APIResponse GetBackends();
    APIResponse GetHealth();
    APIResponse ListModels();
    APIResponse LoadModel(const std::string& modelId);
    APIResponse UnloadModel(const std::string& modelId);
    APIResponse Generate(const GenerateRequest& request);
    APIResponse Chat(const APIRequest& request);

    // Streaming support
    using StreamCallback = std::function<void(const std::string& chunk)>;
    void SetStreamCallback(StreamCallback cb);

    // GPU backend management
    struct GPUDeviceInfo {
        int index;
        std::string name;
        uint64_t vramBytes;
        uint32_t computeUnits;
        std::string architecture;
        bool available;
    };
    std::vector<GPUDeviceInfo> EnumerateGPUs();
    bool SelectGPU(int index);

private:
    Deep2Engine* engine_;
    bool running_;
    int port_;
    std::thread serverThread_;
    std::mutex mutex_;
    StreamCallback streamCallback_;

    // Model registry
    std::vector<ModelInfo> models_;
    std::string activeModelId_;

    // Internal handlers
    APIResponse HandleGet(const std::string& path);
    APIResponse HandlePost(const std::string& path, const std::string& body);
    APIResponse HandleDelete(const std::string& path);

    // JSON helpers
    std::string ModelsToJson() const;
    std::string BackendsToJson() const;
    std::string GenerateToJson(const GenerateResponse& response) const;
};

// ============================================================================
// Deep2 Backend Auto-Discovery
// ============================================================================
class Deep2BackendDiscovery {
public:
    struct DiscoveredBackend {
        std::string type; // "deep2", "ollama", "vllm", etc.
        std::string url;
        std::string version;
        std::vector<std::string> capabilities;
        int priority;
    };

    static std::vector<DiscoveredBackend> DiscoverBackends();
    static bool TestConnection(const std::string& url);
    static DiscoveredBackend GetPreferredBackend();
};

// ============================================================================
// Deep2 Model Bridge
// ============================================================================
class Deep2ModelBridge {
public:
    // Connect to Deep2 API server
    bool Connect(const std::string& url);
    void Disconnect();
    bool IsConnected() const;

    // Model operations
    std::vector<ModelInfo> ListModels();
    bool LoadModel(const std::string& modelId);
    bool UnloadModel();
    ModelInfo GetActiveModel() const;

    // Inference
    GenerateResponse Generate(const GenerateRequest& request);
    void GenerateStream(const GenerateRequest& request, 
                        std::function<void(const std::string&)> onToken);

    // Health check
    bool HealthCheck();

private:
    std::string baseUrl_;
    bool connected_;
    std::string activeModel_;
};

} // namespace Deep2
