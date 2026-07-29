// ============================================================================
// unified_backend_client.h - Unified Backend Client for RawrXD IDE
// Phase 0: Complete Production Integration
// Auto-discovers Deep2 (port 11436) with Ollama fallback (port 11434)
// ============================================================================

#pragma once

#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <optional>

namespace RawrXD {
namespace Backend {

// ============================================================================
// Backend Types
// ============================================================================
enum class BackendType {
    UNKNOWN,
    DEEP2_NATIVE,    // Port 11436 - Priority 1
    RAWRXD,          // Port 8080 - Priority 2  
    OLLAMA,          // Port 11434 - Priority 4 (fallback)
    REMOTE           // Custom endpoint
};

// ============================================================================
// Backend Information
// ============================================================================
struct BackendInfo {
    BackendType type = BackendType::UNKNOWN;
    std::string name;
    std::string url;
    std::string version;
    int priority = 99;
    bool available = false;
    bool native = false;
    std::vector<std::string> capabilities;
    
    // GPU info
    struct GPUDevice {
        std::string name;
        uint64_t vramBytes = 0;
        std::string architecture;
        bool available = false;
    };
    std::vector<GPUDevice> gpus;
};

// ============================================================================
// Model Information
// ============================================================================
struct ModelInfo {
    std::string id;
    std::string name;
    std::string family;
    size_t size = 0;
    std::string quantization;
    std::string parameterSize;
    bool loaded = false;
};

// ============================================================================
// Generation Request
// ============================================================================
struct GenerateRequest {
    std::string prompt;
    std::string model;
    int maxTokens = 2048;
    float temperature = 0.8f;
    float topP = 0.9f;
    int topK = 40;
    bool stream = true;
    std::vector<std::string> stopSequences;
};

// ============================================================================
// Chat Message
// ============================================================================
struct ChatMessage {
    std::string role;      // "system", "user", "assistant"
    std::string content;
};

// ============================================================================
// Generation Response
// ============================================================================
struct GenerateResponse {
    std::string text;
    bool done = false;
    int tokensGenerated = 0;
    float tokensPerSecond = 0.0f;
    std::string error;
    
    // Usage stats
    uint64_t promptTokens = 0;
    uint64_t completionTokens = 0;
    uint64_t totalTokens = 0;
};

// ============================================================================
// Unified Backend Client
// Single interface for all backends with auto-discovery
// ============================================================================
class UnifiedBackendClient {
public:
    // Construction
    UnifiedBackendClient();
    ~UnifiedBackendClient();
    
    // Disable copy, enable move
    UnifiedBackendClient(const UnifiedBackendClient&) = delete;
    UnifiedBackendClient& operator=(const UnifiedBackendClient&) = delete;
    UnifiedBackendClient(UnifiedBackendClient&&) noexcept;
    UnifiedBackendClient& operator=(UnifiedBackendClient&&) noexcept;
    
    // ============================================================================
    // Initialization
    // ============================================================================
    
    // Auto-discover and connect to best available backend
    bool Initialize();
    
    // Connect to specific URL (bypass discovery)
    bool Initialize(const std::string& url);
    
    // Shutdown
    void Shutdown();
    
    // Check if initialized
    bool IsInitialized() const;
    
    // ============================================================================
    // Backend Management
    // ============================================================================
    
    // Discover all available backends
    std::vector<BackendInfo> DiscoverBackends();
    
    // Get current backend info
    BackendInfo GetCurrentBackend() const;
    
    // Switch to specific backend by URL
    bool SwitchBackend(const std::string& url);
    
    // Get preferred backend URL (without connecting)
    static std::string GetPreferredBackendUrl();
    
    // ============================================================================
    // Model Management
    // ============================================================================
    
    // List available models
    std::vector<ModelInfo> ListModels();
    
    // Load a model
    bool LoadModel(const std::string& modelId);
    
    // Unload current model
    bool UnloadModel();
    
    // Get currently loaded model
    std::optional<ModelInfo> GetCurrentModel();
    
    // ============================================================================
    // Inference
    // ============================================================================
    
    // Generate text (blocking)
    GenerateResponse Generate(const GenerateRequest& request);
    
    // Generate text (streaming)
    using TokenCallback = std::function<void(const std::string& token)>;
    using CompletionCallback = std::function<void(const GenerateResponse& response)>;
    using ErrorCallback = std::function<void(const std::string& error)>;
    
    bool GenerateStream(const GenerateRequest& request,
                        TokenCallback onToken,
                        CompletionCallback onComplete,
                        ErrorCallback onError);
    
    // Chat completion (blocking)
    GenerateResponse Chat(const std::vector<ChatMessage>& messages,
                          const GenerateRequest& request);
    
    // Chat completion (streaming)
    bool ChatStream(const std::vector<ChatMessage>& messages,
                    const GenerateRequest& request,
                    TokenCallback onToken,
                    CompletionCallback onComplete,
                    ErrorCallback onError);
    
    // Embeddings
    std::vector<float> GetEmbeddings(const std::string& text, 
                                      const std::string& model = "");
    
    // ============================================================================
    // Health & Status
    // ============================================================================
    
    // Health check
    bool HealthCheck();
    
    // Get last error
    std::string GetLastError() const;
    
    // Get latency of last request (ms)
    double GetLastLatencyMs() const;
    
private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// ============================================================================
// Global Singleton Access
// ============================================================================

// Get or create global client
UnifiedBackendClient* GetGlobalBackendClient();

// Initialize global client (call once at startup)
bool InitializeGlobalBackend();

// Initialize with specific URL
bool InitializeGlobalBackend(const std::string& url);

// Shutdown global client
void ShutdownGlobalBackend();

// Check if backend is ready
bool IsBackendReady();

// Quick generation using global client
std::string QuickGenerate(const std::string& prompt, 
                          int maxTokens = 2048,
                          float temperature = 0.8f);

// ============================================================================
// C API for external integration
// ============================================================================
extern "C" {

// Initialize the backend system
__declspec(dllexport) bool RawrXD_Backend_Initialize();

// Initialize with specific URL
__declspec(dllexport) bool RawrXD_Backend_InitializeWithUrl(const char* url);

// Shutdown
__declspec(dllexport) void RawrXD_Backend_Shutdown();

// Check if ready
__declspec(dllexport) bool RawrXD_Backend_IsReady();

// Get current backend URL
__declspec(dllexport) const char* RawrXD_Backend_GetUrl();

// Generate text
__declspec(dllexport) const char* RawrXD_Backend_Generate(const char* prompt,
                                                           int maxTokens,
                                                           float temperature);

// Generate with full request
__declspec(dllexport) const char* RawrXD_Backend_GenerateFull(
    const char* prompt,
    const char* model,
    int maxTokens,
    float temperature,
    float topP,
    int topK);

// Free string returned by C API
__declspec(dllexport) void RawrXD_Backend_FreeString(const char* str);

} // extern "C"

} // namespace Backend
} // namespace RawrXD
