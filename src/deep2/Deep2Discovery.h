// ============================================================================
// Deep2Discovery.h - Backend Auto-Discovery Utility
// Phase 0: Runtime Wiring - Removes Ollama hard dependency
// ============================================================================

#pragma once

#include <string>
#include <vector>
#include <functional>

namespace Deep2 {

// ============================================================================
// Discovered Backend Information
// ============================================================================
struct DiscoveredBackend {
    std::string type;           // "deep2", "ollama", "rawrxd", etc.
    std::string url;            // Full URL endpoint
    std::string version;        // Backend version
    std::string engine;         // Engine name (e.g., "Deep2")
    std::vector<std::string> capabilities;
    int priority = 4;           // Lower = higher priority (1 = native)
    std::string status;         // "online", "offline", "fallback"
    bool native = false;        // True for Deep2 native backend
};

// ============================================================================
// Model Information
// ============================================================================
struct ModelInfo {
    std::string id;
    std::string name;
    std::string path;
    size_t parameterCount = 0;
    size_t contextLength = 0;
    std::string quantization;
    bool loaded = false;
    size_t vramUsageMB = 0;
};

// ============================================================================
// Backend Discovery
// Automatically discovers available backends in priority order:
// 1. Deep2 Native (port 11436)
// 2. RawrXD (port 8080)
// 3. Ollama (port 11434) - fallback
// ============================================================================
class Deep2Discovery {
public:
    // Discover all available backends
    static std::vector<DiscoveredBackend> DiscoverBackends();
    
    // Get the preferred (highest priority) backend
    static DiscoveredBackend GetPreferredBackend();
    
    // Test if a backend URL is reachable
    static bool TestConnection(const std::string& url);
    
    // Get capabilities from a backend
    static std::vector<std::string> GetCapabilities(const std::string& url);
    
    // HTTP GET helper
    static std::string HttpGet(const std::string& url);
};

// ============================================================================
// Deep2 Backend Client
// High-level client for communicating with Deep2 API server
// ============================================================================
class Deep2BackendClient {
public:
    // Default constructor - auto-discovers and connects to best backend
    Deep2BackendClient();
    
    // Constructor with specific URL
    explicit Deep2BackendClient(const std::string& url);
    
    // Auto-connect to preferred backend
    bool AutoConnect();
    
    // Connect to specific URL
    bool Connect(const std::string& url);
    void Disconnect();
    bool IsConnected() const;
    
    // Get current base URL
    std::string GetBaseUrl() const;
    
    // Model operations
    std::vector<ModelInfo> ListModels();
    bool LoadModel(const std::string& modelId);
    bool UnloadModel();
    
    // Inference
    std::string Generate(const std::string& prompt, int maxTokens = 2048, 
                         float temperature = 0.8f);
    void GenerateStream(const std::string& prompt, int maxTokens,
                        float temperature,
                        std::function<void(const std::string&)> onToken);
    
    // Chat completion
    std::string Chat(const std::vector<std::pair<std::string, std::string>>& messages,
                     int maxTokens = 2048, float temperature = 0.8f);
    
    // Health check
    bool HealthCheck();
    
private:
    std::string baseUrl_;
    bool connected_;
    
    std::string HttpGet(const std::string& url);
    std::string HttpPost(const std::string& url, const std::string& body);
    size_t ParseParamSize(const std::string& paramStr);
};

// ============================================================================
// C API for external integration
// ============================================================================
extern "C" {

// Discover backends and return JSON array
__declspec(dllexport) const char* Deep2Discovery_Discover();

// Get preferred backend URL
__declspec(dllexport) const char* Deep2Discovery_GetPreferredUrl();

// Test connection to URL
__declspec(dllexport) int Deep2Discovery_Test(const char* url);

// Create backend client
__declspec(dllexport) void* Deep2BackendClient_Create();
__declspec(dllexport) void* Deep2BackendClient_CreateWithUrl(const char* url);
__declspec(dllexport) void Deep2BackendClient_Destroy(void* client);

// Client operations
__declspec(dllexport) int Deep2BackendClient_Connect(void* client, const char* url);
__declspec(dllexport) int Deep2BackendClient_IsConnected(void* client);
__declspec(dllexport) const char* Deep2BackendClient_Generate(void* client, 
    const char* prompt, int maxTokens, float temperature);

} // extern "C"

} // namespace Deep2
