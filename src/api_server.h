#pragma once
// Ollama-compatible API server connected to Deep2 InferenceEngine
// Implements: GET /api/tags, POST /api/generate, POST /api/chat

#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include <thread>
#include <mutex>
#include <atomic>
#include <unordered_map>
#include <functional>

#include "../core/InferenceEngine.hpp"

#pragma comment(lib, "Ws2_32.lib")

namespace Deep2Rom::Api {

    // Ollama API request/response structures
    struct GenerateRequest {
        std::string model;
        std::string prompt;
        std::string system;
        std::string template_;
        std::string context;
        bool stream = false;
        bool raw = false;
        uint32_t num_predict = 128;
        float temperature = 0.7f;
        float top_p = 0.9f;
        uint32_t top_k = 50;
        float frequency_penalty = 0.0f;
        float presence_penalty = 0.0f;
        uint64_t seed = 42;
    };

    struct GenerateResponse {
        std::string model;
        std::string created_at;
        std::string response;
        bool done = false;
        uint32_t total_duration = 0;
        uint32_t load_duration = 0;
        uint32_t prompt_eval_count = 0;
        uint32_t prompt_eval_duration = 0;
        uint32_t eval_count = 0;
        uint32_t eval_duration = 0;
    };

    struct ChatMessage {
        std::string role;    // "system", "user", "assistant"
        std::string content;
    };

    struct ChatRequest {
        std::string model;
        std::vector<ChatMessage> messages;
        bool stream = false;
        uint32_t num_predict = 128;
        float temperature = 0.7f;
        float top_p = 0.9f;
        uint32_t top_k = 50;
        float frequency_penalty = 0.0f;
        float presence_penalty = 0.0f;
        uint64_t seed = 42;
    };

    struct ChatResponse {
        std::string model;
        std::string created_at;
        ChatMessage message;
        bool done = false;
    };

    // Model info for /api/tags
    struct ModelInfo {
        std::string name;
        std::string modified_at;
        uint64_t size = 0;
        std::string digest;
        std::string details;
    };

    class OllamaApiServer {
    public:
        OllamaApiServer(int port = 11434);
        ~OllamaApiServer();

        // Start the API server (blocking). Returns when stopped.
        bool start();

        // Stop the API server
        void stop();

        // Set the inference engine to use for generation
        void setEngine(Deep2Rom::Inference::InferenceEngine* engine) {
            m_engine = engine;
        }

        // Register a model as available
        void registerModel(const std::string& name, const std::string& path);

        // Check if running
        bool isRunning() const { return m_running.load(); }

    private:
        int m_port;
        SOCKET m_listenSocket;
        std::thread m_serverThread;
        std::atomic<bool> m_running{ false };
        std::mutex m_modelsMutex;
        std::unordered_map<std::string, std::string> m_models; // name -> path
        Deep2Rom::Inference::InferenceEngine* m_engine = nullptr;

        // HTTP request handling
        void handleClient(SOCKET clientSocket);
        std::string extractPath(const std::string& request);
        std::string extractBody(const std::string& request);
        std::string extractHeaderValue(const std::string& request, const std::string& headerName);

        // Route handlers
        std::string handleGetTags();
        std::string handlePostGenerate(const std::string& body);
        std::string handlePostChat(const std::string& body);

        // JSON helpers (minimal, dependency-free)
        std::string escapeJson(const std::string& s);
        std::string buildJsonResponse(const GenerateResponse& resp);
        std::string buildJsonResponse(const ChatResponse& resp);
        std::string buildJsonTagsResponse();

        // Send HTTP response
        void sendResponse(SOCKET sock, int statusCode, const std::string& contentType, const std::string& body);
    };

} // namespace Deep2Rom::Api
