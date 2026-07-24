#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <chrono>
#include <mutex>
#include <nlohmann/json.hpp>

namespace rawrxd {
namespace swarm {

// Protocol types supported
enum class ProtocolType {
    OPENAI,         // OpenAI API compatible
    ANTHROPIC,      // Claude API
    OLLAMA,         // Ollama local API
    LLAMACPP,       // llama.cpp server
    VLLM,           // vLLM API
    TOGETHER,       // Together AI
    COHERE,         // Cohere API
    MISTRAL,        // Mistral AI
    GROQ,           // Groq API
    CUSTOM          // User-defined
};

// Request format
struct UnifiedRequest {
    std::string model;
    std::vector<std::map<std::string, std::string>> messages;
    float temperature{0.7f};
    float topP{0.9f};
    int maxTokens{-1}; // -1 = no limit
    std::vector<std::string> stopSequences;
    bool stream{false};
    std::map<std::string, std::string> metadata;
    
    // Tool calling
    std::vector<std::map<std::string, nlohmann::json>> tools;
    std::string toolChoice{"auto"}; // "auto", "none", or specific tool name
};

// Response format
struct UnifiedResponse {
    std::string id;
    std::string content;
    std::string role{"assistant"};
    std::string finishReason{"stop"}; // "stop", "length", "tool_calls"
    int promptTokens{0};
    int completionTokens{0};
    int totalTokens{0};
    std::chrono::milliseconds latency{0};
    
    // Tool calls
    std::vector<std::map<std::string, std::string>> toolCalls;
    
    // Error handling
    bool success{true};
    std::string errorMessage;
    int errorCode{0};
};

// Streaming chunk
struct StreamChunk {
    std::string content;
    std::string role;
    bool isFinished{false};
    std::string finishReason;
    int index{0};
};

// Protocol capabilities
struct ProtocolCapabilities {
    bool supportsStreaming{true};
    bool supportsTools{false};
    bool supportsVision{false};
    bool supportsJSONMode{false};
    bool supportsSystemPrompt{true};
    int maxContextLength{8192};
    std::vector<std::string> supportedModels;
};

// Provider configuration
struct ProviderConfig {
    ProtocolType type;
    std::string baseUrl;
    std::string apiKey;
    std::string defaultModel;
    std::map<std::string, std::string> headers;
    int timeoutMs{30000};
    int maxRetries{3};
    bool verifySsl{true};
};

// OpenClaw Bridge - Universal protocol translator
class OpenClawBridge {
public:
    OpenClawBridge();
    ~OpenClawBridge();
    
    // Provider management
    void registerProvider(const std::string& name, const ProviderConfig& config);
    void unregisterProvider(const std::string& name);
    bool hasProvider(const std::string& name) const;
    std::vector<std::string> listProviders() const;
    
    // Protocol detection
    ProtocolType detectProtocol(const std::string& url);
    ProtocolCapabilities getCapabilities(ProtocolType type) const;
    
    // Request translation
    std::string translateRequest(const UnifiedRequest& request, ProtocolType target);
    UnifiedResponse translateResponse(const std::string& response, ProtocolType source);
    
    // Direct API calls
    UnifiedResponse complete(const std::string& provider, const UnifiedRequest& request);
    void completeStreaming(const std::string& provider, const UnifiedRequest& request,
                          std::function<void(const StreamChunk&)> callback);
    
    // Batch processing
    std::vector<UnifiedResponse> completeBatch(const std::string& provider,
                                                  const std::vector<UnifiedRequest>& requests);
    
    // Model management
    std::vector<std::string> listModels(const std::string& provider);
    std::string getModelInfo(const std::string& provider, const std::string& model);
    
    // Health checking
    bool healthCheck(const std::string& provider);
    std::map<std::string, bool> healthCheckAll();
    
    // Fallback handling
    void setFallbackChain(const std::vector<std::string>& providers);
    UnifiedResponse completeWithFallback(const UnifiedRequest& request);
    
    // Load balancing
    void setLoadBalancer(const std::vector<std::string>& providers, 
                         const std::vector<float>& weights);
    std::string selectProviderForLoad();
    
    // Cost tracking
    float estimateCost(const UnifiedRequest& request, ProtocolType type);
    float getCostPerToken(ProtocolType type);
    
    // Streaming support
    bool supportsStreaming(const std::string& provider);
    
    // Tool calling adapters
    nlohmann::json convertToolsToOpenAI(const std::vector<std::map<std::string, nlohmann::json>>& tools);
    nlohmann::json convertToolsToAnthropic(const std::vector<std::map<std::string, nlohmann::json>>& tools);
    std::vector<std::map<std::string, std::string>> parseToolCallsOpenAI(const nlohmann::json& response);
    std::vector<std::map<std::string, std::string>> parseToolCallsAnthropic(const nlohmann::json& response);
    
    // Message format converters
    nlohmann::json convertMessagesToOpenAI(const std::vector<std::map<std::string, std::string>>& messages);
    nlohmann::json convertMessagesToAnthropic(const std::vector<std::map<std::string, std::string>>& messages);
    std::vector<std::map<std::string, std::string>> parseMessagesOpenAI(const nlohmann::json& messages);
    std::vector<std::map<std::string, std::string>> parseMessagesAnthropic(const nlohmann::json& messages);
    
    // Response format converters
    UnifiedResponse parseOpenAIResponse(const nlohmann::json& json);
    UnifiedResponse parseAnthropicResponse(const nlohmann::json& json);
    UnifiedResponse parseOllamaResponse(const nlohmann::json& json);
    UnifiedResponse parseLlamaCppResponse(const nlohmann::json& json);
    
    // Error handling
    UnifiedResponse createErrorResponse(const std::string& message, int code);
    bool isRetryableError(int code);
    
    // Metrics
    struct Metrics {
        size_t totalRequests{0};
        size_t successfulRequests{0};
        size_t failedRequests{0};
        size_t totalTokens{0};
        double avgLatencyMs{0.0};
        std::map<std::string, size_t> requestsByProvider;
    };
    Metrics getMetrics() const;
    void resetMetrics();
    
private:
    std::map<std::string, ProviderConfig> providers_;
    std::vector<std::string> fallbackChain_;
    std::map<std::string, float> loadWeights_;
    mutable std::mutex mutex_;
    
    Metrics metrics_;
    size_t currentProviderIndex_{0};
    
    // HTTP client (would use actual HTTP library in production)
    std::string httpPost(const std::string& url, const std::string& body,
                        const std::map<std::string, std::string>& headers, int timeoutMs);
    std::string httpPostStream(const std::string& url, const std::string& body,
                              const std::map<std::string, std::string>& headers,
                              std::function<void(const std::string&)> chunkCallback);
    
    // Protocol-specific formatters
    std::string formatOpenAIRequest(const UnifiedRequest& req);
    std::string formatAnthropicRequest(const UnifiedRequest& req);
    std::string formatOllamaRequest(const UnifiedRequest& req);
    std::string formatLlamaCppRequest(const UnifiedRequest& req);
    
    // Update metrics
    void recordRequest(const std::string& provider, bool success, int tokens, int latencyMs);
};

} // namespace swarm
} // namespace rawrxd
