#pragma once
#include <string>
#include <vector>
#include <functional>
#include <memory>
#include <atomic>
#include "HttpClient.hpp"

// Optional event bus integration (enabled when building with full IDE)
#ifdef RAWRXD_ENABLE_CODEX_EVENTBUS
#include "CodexEventBus.hpp"
#endif

namespace RawrXD {
namespace Codex {

// Exit codes following sysexits.h conventions
enum class ExitCode : int {
    Success = 0,
    GeneralError = 1,
    MisuseOfCommand = 2,
    InvalidApiKey = 3,
    NetworkError = 4,
    RateLimited = 5,
    InvalidModel = 6,
    ProviderUnavailable = 7,
    JsonParseError = 8,
    Timeout = 9,
    Cancelled = 10
};

// GPT/Codex CLI Interface
class CodexCLI {
public:
    // Response callback for streaming
    using ResponseCallback = std::function<void(const std::string& chunk, bool isFinal)>;
    
    enum class Provider {
        OpenAI,
        Ollama
    };
    
    struct Config {
        std::string apiKey;
        std::string model = "gpt-4";
        std::string baseUrl = "https://api.openai.com/v1";
        Provider provider = Provider::OpenAI;
        int maxTokens = 2048;
        float temperature = 0.7f;
        int timeoutMs = 30000;
        
        // Auto-detect provider from environment
        void AutoDetect() {
            // Check for Ollama first
            const char* ollamaHost = std::getenv("OLLAMA_HOST");
            if (ollamaHost && *ollamaHost) {
                provider = Provider::Ollama;
                baseUrl = std::string("http://") + ollamaHost;
                if (baseUrl.find(":") == std::string::npos) {
                    baseUrl += ":11434";
                }
                return;
            }
            
            // Check for OLLAMA_URL
            const char* ollamaUrl = std::getenv("OLLAMA_URL");
            if (ollamaUrl && *ollamaUrl) {
                provider = Provider::Ollama;
                baseUrl = ollamaUrl;
                return;
            }
            
            // Default to localhost Ollama if no OpenAI key but Ollama might be present
            const char* openaiKey = std::getenv("OPENAI_API_KEY");
            if (!openaiKey || !*openaiKey) {
                provider = Provider::Ollama;
                baseUrl = "http://localhost:11434";
            }
        }
    };
    
    CodexCLI();
    ~CodexCLI();
    
    // Initialize with config
    bool Initialize(const Config& config);
    
    // Send prompt and get response (blocking)
    std::string Complete(const std::string& prompt);
    
    // Send prompt with streaming response
    bool CompleteStreaming(const std::string& prompt, ResponseCallback callback);
    
    // Interactive REPL mode
    void RunREPL();
    
    // Execute command from CLI args
    int ExecuteCommand(int argc, char* argv[]);
    
    // Check if initialized
    bool IsInitialized() const { return m_initialized; }
    
    // Get last error
    const char* GetLastError() const { return m_lastError.c_str(); }
    
    // Get current config
    const Config& GetConfig() const { return m_config; }
    
    // Enable/disable event bus publishing
    void SetEventBusEnabled(bool enabled) { m_eventBusEnabled = enabled; }
    
private:
    Config m_config;
    bool m_initialized = false;
    std::string m_lastError;
    HttpClient m_httpClient;
    
    // Event bus for IDE integration (optional)
    bool m_eventBusEnabled = true;
    std::atomic<uint64_t> m_sessionId{0};
    std::atomic<uint32_t> m_chunkIndex{0};
#ifdef RAWRXD_ENABLE_CODEX_EVENTBUS
    CodexEventBus m_eventBus;
#endif
    
    // HTTP client implementation
    bool HttpPost(const std::string& url, const std::string& body, std::string& response);
    bool HttpPostStreaming(const std::string& url, const std::string& body, ResponseCallback callback);
    
    // Build request JSON
    std::string BuildRequestJson(const std::string& prompt, bool stream);
    
    // Parse response
    std::string ParseResponse(const std::string& json);
    std::string ParseStreamChunk(const std::string& chunk);
    
    // Event publishing helpers
    void PublishStreamStarted(const std::string& prompt);
    void PublishStreamChunk(const std::string& chunk, bool isFinal);
    void PublishStreamCompleted();
    void PublishStreamError(const std::string& error);
};

} // namespace Codex
} // namespace RawrXD
