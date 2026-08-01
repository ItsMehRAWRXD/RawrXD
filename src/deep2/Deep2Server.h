// ============================================================================
// Deep2Server.h - Standalone Deep2 Inference Server
// OpenAI-compatible API for IDE integration
// ============================================================================

#pragma once

#include "Deep2Engine.h"
#include <string>
#include <functional>
#include <thread>
#include <atomic>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#endif

namespace Deep2 {

// ============================================================================
// OpenAI-compatible request/response structures
// ============================================================================
struct ChatMessage {
    std::string role;      // "system", "user", "assistant"
    std::string content;
};

struct ChatCompletionRequest {
    std::string model;
    std::vector<ChatMessage> messages;
    float temperature = 0.7f;
    int max_tokens = 256;
    float top_p = 1.0f;
    bool stream = false;
};

struct ChatCompletionResponse {
    std::string id;
    std::string object = "chat.completion";
    int created;
    std::string model;
    std::vector<ChatMessage> choices;
    std::string finish_reason;
    bool success = false;
    std::string error;
};

struct CompletionRequest {
    std::string model;
    std::string prompt;
    float temperature = 0.7f;
    int max_tokens = 256;
    float top_p = 1.0f;
    bool stream = false;
};

struct CompletionResponse {
    std::string id;
    std::string object = "text_completion";
    int created;
    std::string model;
    std::string text;
    std::string finish_reason;
    bool success = false;
    std::string error;
};

struct ModelInfo {
    std::string id;
    std::string object = "model";
    int created;
    std::string owned_by = "deep2";
};

// ============================================================================
// Deep2 Standalone Server
// ============================================================================
class Deep2Server {
public:
    Deep2Server();
    ~Deep2Server();

    // Configuration
    struct Config {
        std::string modelPath;
        int port = 11442;
        std::string host = "127.0.0.1";
        int maxContextLength = 32768;
        int numThreads = 0;  // 0 = auto
        bool enableGPU = true;
        std::string logLevel = "info";
    };

    // Lifecycle
    bool Initialize(const Config& config);
    bool Start();
    void Stop();
    bool IsRunning() const { return running_.load(); }

    // Status
    std::string GetStatus() const;
    std::string GetModelInfo() const;

private:
    // HTTP Server
    void ServerLoop();
    void HandleClient(SOCKET clientSocket);
    std::string ParseRequest(const std::string& request);
    std::string RouteRequest(const std::string& method, 
                            const std::string& path, 
                            const std::string& body);

    // API Handlers
    std::string HandleModels();
    std::string HandleChatCompletions(const std::string& body);
    std::string HandleCompletions(const std::string& body);
    std::string HandleEmbeddings(const std::string& body);
    std::string HandleHealth();

    // Streaming
    void StreamChatCompletion(SOCKET clientSocket, 
                             const ChatCompletionRequest& request);
    void StreamCompletion(SOCKET clientSocket, 
                          const CompletionRequest& request);

    // JSON serialization
    std::string ToJson(const ChatCompletionResponse& response);
    std::string ToJson(const CompletionResponse& response);
    std::string ToJson(const std::vector<ModelInfo>& models);
    std::string ToStreamChunk(const std::string& content, 
                              const std::string& model,
                              bool done = false);

    // Members
    Config config_;
    Deep2Engine engine_;
    std::atomic<bool> running_{false};
    std::atomic<bool> initialized_{false};
    std::thread serverThread_;
    SOCKET serverSocket_ = INVALID_SOCKET;
    
    ModelInfo modelInfo_;
    int requestCounter_ = 0;
};

// ============================================================================
// Utility Functions
// ============================================================================
std::string GetCurrentTimestamp();
int GetCurrentUnixTime();
std::string GenerateRequestId();
std::string EscapeJsonString(const std::string& input);

} // namespace Deep2
