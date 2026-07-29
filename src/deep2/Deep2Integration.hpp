// ============================================================================
// Deep2Integration.hpp - Complete Phase 0 Production Integration
// Unified API Gateway for RawrXD IDE ↔ Deep2 Sovereign Runtime
// ============================================================================

#pragma once

#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <map>

namespace Deep2 {

// ============================================================================
// Hardware Information Structures
// ============================================================================

struct GPUDeviceInfo {
    int index;
    std::string name;
    std::string vendor;
    std::string architecture;
    uint64_t vramBytes;
    uint32_t computeUnits;
    std::string backend; // "Vulkan", "ROCm", "CUDA", "DirectML"
    bool available;
    float utilization; // 0.0 - 1.0
};

struct CPUInfo {
    std::string architecture; // "AVX2", "AVX-512", "ARM NEON"
    int coreCount;
    bool supportsAVX2;
    bool supportsAVX512;
    bool supportsFMA;
};

struct HardwareStatus {
    CPUInfo cpu;
    std::vector<GPUDeviceInfo> gpus;
    uint64_t totalVRAM;
    uint64_t availableVRAM;
    std::string activeBackend;
};

// ============================================================================
// Model Information
// ============================================================================

struct ModelCapabilities {
    bool supportsChat;
    bool supportsCompletion;
    bool supportsEmbedding;
    bool supportsVision;
    bool supportsTools;
    size_t maxContextLength;
    std::vector<std::string> languages;
};

struct ModelInfo {
    std::string id;
    std::string name;
    std::string path;
    std::string format; // "GGUF", "ONNX", "SafeTensors"
    std::string family;
    size_t parameterCount;
    size_t contextLength;
    std::string quantization;
    size_t fileSizeBytes;
    bool loaded;
    size_t vramUsageMB;
    ModelCapabilities capabilities;
    std::string loadedAt;
};

// ============================================================================
// API Request/Response Types
// ============================================================================

struct ChatMessage {
    std::string role; // "system", "user", "assistant", "tool"
    std::string content;
    std::string name; // For tool messages
};

struct ChatRequest {
    std::string model;
    std::vector<ChatMessage> messages;
    int maxTokens = 2048;
    float temperature = 0.7f;
    float topP = 0.9f;
    int topK = 40;
    bool stream = true;
    std::vector<std::string> stopSequences;
    std::map<std::string, std::string> tools;
};

struct ChatResponse {
    ChatMessage message;
    bool done;
    std::string finishReason;
    int tokensGenerated;
    int promptTokens;
    float tokensPerSecond;
    float latencyMs;
};

struct CompletionRequest {
    std::string model;
    std::string prompt;
    std::string suffix; // For fill-in-the-middle
    int maxTokens = 256;
    float temperature = 0.2f;
    bool stream = false;
    std::vector<std::string> stopSequences;
};

struct CompletionResponse {
    std::string text;
    bool done;
    int tokensGenerated;
    float tokensPerSecond;
};

// ============================================================================
// Deep2 API Gateway - Single Port 11435
// ============================================================================

class Deep2APIGateway {
public:
    static Deep2APIGateway& Instance();
    
    // Lifecycle
    bool Initialize();
    bool Start(int port = 11435);
    void Stop();
    bool IsRunning() const;
    
    // Configuration
    void SetEngine(class Deep2Engine* engine);
    void SetHardwareSelector(class HardwareBackendSelector* selector);
    
    // API Endpoints
    std::string GetVersion();
    std::string GetHealth();
    std::string GetBackends();
    std::string GetHardware();
    std::string ListModels();
    std::string LoadModel(const std::string& modelId);
    std::string UnloadModel(const std::string& modelId);
    
    // Inference
    void Chat(const ChatRequest& request, 
              std::function<void(const ChatResponse&)> onToken,
              std::function<void(const std::string&)> onError);
    
    void Complete(const CompletionRequest& request,
                  std::function<void(const CompletionResponse&)> onToken,
                  std::function<void(const std::string&)> onError);
    
    // Telemetry
    std::string GetTelemetry();
    std::string GetTokenHeatmap();
    std::string GetGPUMetrics();
    
private:
    Deep2APIGateway();
    ~Deep2APIGateway();
    
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// ============================================================================
// Deep2 IDE Client - For IDE Integration
// ============================================================================

class Deep2IDEClient {
public:
    Deep2IDEClient();
    ~Deep2IDEClient();
    
    // Connection
    bool Connect(const std::string& url = "http://127.0.0.1:11435");
    void Disconnect();
    bool IsConnected() const;
    std::string GetEndpoint() const;
    
    // Auto-discovery - tries Deep2 first, falls back to Ollama
    bool AutoConnect();
    
    // Model Management
    std::vector<ModelInfo> ListModels();
    bool LoadModel(const std::string& modelId);
    bool UnloadModel();
    ModelInfo GetActiveModel() const;
    
    // Chat
    std::string Chat(const std::vector<ChatMessage>& messages,
                     int maxTokens = 2048,
                     float temperature = 0.7f);
    
    void ChatStream(const std::vector<ChatMessage>& messages,
                    std::function<void(const std::string&)> onToken,
                    int maxTokens = 2048,
                    float temperature = 0.7f);
    
    // Completion (for ghost text)
    std::string Complete(const std::string& prefix,
                         const std::string& suffix = "",
                         int maxTokens = 256);
    
    // Hardware Info
    HardwareStatus GetHardwareStatus();
    std::vector<GPUDeviceInfo> GetGPUDevices();
    
    // Status
    bool HealthCheck();
    std::string GetVersion();
    
private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// ============================================================================
// Global Access Functions
// ============================================================================

// Start the Deep2 API Gateway
bool Deep2_StartGateway(int port = 11435);

// Stop the gateway
void Deep2_StopGateway();

// Check if gateway is running
bool Deep2_IsGatewayRunning();

// Get the IDE client (auto-connected)
Deep2IDEClient* Deep2_GetIDEClient();

// Reset and reconnect everything
bool Deep2_ReconnectAll();

} // namespace Deep2

// ============================================================================
// C API for External Integration
// ============================================================================

extern "C" {

// Gateway control
__declspec(dllexport) bool Deep2Gateway_Start(int port);
__declspec(dllexport) void Deep2Gateway_Stop();
__declspec(dllexport) bool Deep2Gateway_IsRunning();
__declspec(dllexport) const char* Deep2Gateway_GetUrl();

// Client
__declspec(dllexport) void* Deep2Client_Create();
__declspec(dllexport) void Deep2Client_Destroy(void* client);
__declspec(dllexport) bool Deep2Client_Connect(void* client, const char* url);
__declspec(dllexport) bool Deep2Client_AutoConnect(void* client);
__declspec(dllexport) bool Deep2Client_IsConnected(void* client);

// Model operations
__declspec(dllexport) const char* Deep2Client_ListModels(void* client);
__declspec(dllexport) bool Deep2Client_LoadModel(void* client, const char* modelId);
__declspec(dllexport) bool Deep2Client_UnloadModel(void* client);

// Chat
__declspec(dllexport) const char* Deep2Client_Chat(void* client, 
    const char** messages, int messageCount, int maxTokens, float temperature);

// Hardware
__declspec(dllexport) const char* Deep2Client_GetHardware(void* client);

} // extern "C"
