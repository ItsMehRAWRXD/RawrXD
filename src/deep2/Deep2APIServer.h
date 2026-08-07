// ============================================================================
// Deep2APIServer.h - HTTP API Server for Deep2 Native Engine
// Ollama-compatible REST API on port 11436
// ============================================================================

#ifndef DEEP2_API_SERVER_H
#define DEEP2_API_SERVER_H

#include "Deep2Engine.h"
#include <string>
#include <functional>

namespace Deep2 {

// Forward declarations
class APIServerImpl;

// ============================================================================
// API Server Configuration
// ============================================================================
struct APIServerConfig {
    int port = 11436;
    int maxConnections = 100;
    int requestTimeoutMs = 30000;
    bool enableCORS = true;
    bool enableSSE = true;  // Server-Sent Events for streaming
    std::string allowedOrigins = "*";
};

// ============================================================================
// Generation Request
// ============================================================================
struct GenerationRequest {
    std::string prompt;
    std::string model = "deep2-native";
    int maxTokens = 2048;
    float temperature = 0.8f;
    float topP = 0.9f;
    int topK = 40;
    bool stream = true;
    std::vector<std::pair<std::string, std::string>> messages;  // For chat
};

// ============================================================================
// Generation Response
// ============================================================================
struct GenerationResponse {
    std::string text;
    bool done = false;
    int tokensGenerated = 0;
    float tokensPerSecond = 0.0f;
    std::string error;
};

// ============================================================================
// HTTP API Server for Deep2
// Exposes Ollama-compatible endpoints
// ============================================================================
class APIServer {
public:
    // Callback for token generation (for streaming)
    using TokenCallback = std::function<void(const std::string& token, bool done)>;
    
    APIServer(Deep2Engine* engine);
    ~APIServer();
    
    // Start/stop server
    bool start(const APIServerConfig& config = APIServerConfig());
    void stop();
    bool isRunning() const;
    
    // Get server info
    int getPort() const;
    std::string getUrl() const;
    
    // Manual generation (for testing)
    GenerationResponse generate(const GenerationRequest& request);
    void generateStream(const GenerationRequest& request, TokenCallback callback);
    
private:
    APIServerImpl* impl_;
    Deep2Engine* engine_;
    APIServerConfig config_;
    bool running_;
};

// ============================================================================
// C API for external integration
// ============================================================================
extern "C" {

// Start server with engine
__declspec(dllexport) bool Deep2APIServer_Start(void* engine, int port);

// Stop server
__declspec(dllexport) void Deep2APIServer_Stop();

// Check if running
__declspec(dllexport) bool Deep2APIServer_IsRunning();

// Get server URL
__declspec(dllexport) const char* Deep2APIServer_GetUrl();

} // extern "C"

} // namespace Deep2

#endif // DEEP2_API_SERVER_H
