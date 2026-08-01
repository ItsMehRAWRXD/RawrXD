=====================================================================
// OllamaProxy — C++20, no Qt. Lightweight proxy to Ollama REST API.
// ============================================================================
// Use WinHTTP or similar in .cpp; this header declares the API only.
// ============================================================================

#include <functional>
#include <string>
#include <vector>
#include <cstdint>

/**
 * Lightweight fallback proxy to Ollama REST API.
 * Used when model exists in Ollama but not as plain .gguf, or GGUF uses
 * quantization the engine doesn't support. Preserves direct GGUF loading when possible.
 */
class OllamaProxy {
public:
    struct OllamaModelMeta {
        std::string name;
        std::string family;
        std::string parameter_size;
        std::string quantization_level;
        std::uint64_t size = 0;
        bool found = false;
    };

    using TokenFn = std::function<void(const std::string&)>;
    using CompleteFn = std::function<void()>;
    using ErrorFn = std::function<void(const std::string&)>;

    OllamaProxy() = default;
    ~OllamaProxy();

    void setModel(const std::string& modelName);
    std::string currentModel() const { return m_modelName; }

    bool isOllamaAvailable();
    bool isModelAvailable(const std::string& modelName);
    OllamaModelMeta getModelMetadata(const std::string& modelName);

    void setBaseUrl(const std::string& baseUrl);
    std::string baseUrl() const { return m_ollamaUrl; }

    void generateResponse(const std::string& prompt,
                         float temperature = 0.8f,
                         int maxTokens = 512);

    void stopGeneration();

    void setOnTokenArrived(TokenFn fn) { m_onTokenArrived = std::move(fn); }
    void setOnGenerationComplete(CompleteFn fn) { m_onGenerationComplete = std::move(fn); }
    void setOnError(ErrorFn fn) { m_onError = std::move(fn); }

private:
    void onNetworkReply();
    void onNetworkError(int code);

    std::string m_modelName;
    std::string m_ollamaUrl = "http://localhost:11434";
    void* m_networkContext = nullptr;  // WinHTTP or similar
    void* m_currentRequest = nullptr;

    std::vector<uint8_t> m_buffer;

    TokenFn m_onTokenArrived;
    CompleteFn m_onGenerationComplete;
    ErrorFn m_onError;
};
=======
#pragma once

#include "RawrXD_Foundation.h"
#include "RawrXD_SignalSlot.h"
#include <string>

using RawrXD::String;
using RawrXD::Signal;

/**
 * @class OllamaProxy
 * @brief Lightweight fallback proxy to Ollama REST API
 * 
 * Only used when:
 * 1. Model exists in Ollama registry but not as plain .gguf in OllamaModels
 * 2. GGUF uses quantization our engine doesn't support yet
 * 
 * Preserves all custom optimizations 95% of the time by using direct GGUF loading.
 * Falls back to Ollama only for edge cases (new quants, unsupported architectures).
 */
class OllamaProxy {
public:
    explicit OllamaProxy(void* parent = nullptr);
    ~OllamaProxy();
    
    // Set which Ollama model to use (e.g., "llama3.2:3b", "unlocked-350M:latest")
    void setModel(const String& modelName);
    String currentModel() const { return m_modelName; }
    
    // Check if Ollama is running and model is available
    bool isOllamaAvailable();
    bool isModelAvailable(const String& modelName);
    
    // Generate response using Ollama API with streaming
    void generateResponse(const String& prompt, 
                         float temperature = 0.8f,
                         int maxTokens = 512);
    
    // Stop current generation
    void stopGeneration();
    
    // Signals
    // Emitted for each token during streaming (compatible with AgenticEngine)
    Signal<const String&> tokenArrived;
    
    // Emitted when generation completes
    Signal<> generationComplete;
    
    // Emitted on errors
    Signal<const String&> error;
    
private:
    String m_modelName;
    bool m_isRunning;
    
    // Network handles or implementation detail
    void* m_networkManager = nullptr; // Placeholder for WinHttp handle or similar
};

