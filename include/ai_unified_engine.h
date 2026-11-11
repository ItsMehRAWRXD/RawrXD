/**
 * ============================================================================
 * Unified AI Inference Engine
 * ============================================================================
 * 
 * Centralized LLM inference system for all AI IDE features.
 * Handles model management, streaming, caching, and rate limiting.
 */

#pragma once

#include <string>
#include <vector>
#include <functional>
#include <memory>
#include <future>
#include <chrono>

namespace RawrXD {
namespace AI {

// Inference request
struct InferenceRequest {
    std::string prompt;
    std::string systemPrompt;
    std::string model;
    float temperature = 0.2f;
    int maxTokens = 2048;
    int topK = 40;
    float topP = 0.9f;
    float repeatPenalty = 1.1f;
    std::vector<std::string> stopSequences;
    std::string contextId;  // For conversation continuity
};

// Inference response
struct InferenceResponse {
    std::string text;
    int tokensGenerated;
    int tokensPrompt;
    float generationTimeMs;
    bool truncated;
    std::string finishReason;
    std::string modelUsed;
};

// Streaming token callback
using TokenCallback = std::function<void(const std::string& token, bool isLast)>;
using ProgressCallback = std::function<void(float progress)>;

// Model information
struct ModelInfo {
    std::string name;
    std::string displayName;
    size_t contextLength;
    bool supportsStreaming;
    bool supportsFunctionCalling;
    float costPer1KTokens;
    std::vector<std::string> capabilities;
};

// Cache entry
struct CacheEntry {
    std::string key;
    InferenceResponse response;
    std::chrono::steady_clock::time_point timestamp;
    int hitCount;
};

class UnifiedAIEngine {
public:
    UnifiedAIEngine();
    ~UnifiedAIEngine();

    // Initialization
    bool initialize(const std::string& defaultModel = "codellama:latest");
    void shutdown();
    bool isReady() const;

    // Synchronous inference
    InferenceResponse complete(const InferenceRequest& request);
    
    // Asynchronous inference
    std::future<InferenceResponse> completeAsync(const InferenceRequest& request);
    
    // Streaming inference
    void completeStream(
        const InferenceRequest& request,
        TokenCallback onToken,
        ProgressCallback onProgress = nullptr
    );

    // Model management
    std::vector<ModelInfo> listAvailableModels();
    bool loadModel(const std::string& modelName);
    void unloadModel(const std::string& modelName);
    bool isModelLoaded(const std::string& modelName) const;
    void setDefaultModel(const std::string& modelName);
    std::string getDefaultModel() const;

    // Caching
    void enableCache(bool enable);
    void clearCache();
    void setCacheSize(size_t maxEntries);
    size_t getCacheSize() const;

    // Rate limiting
    void setRateLimit(int requestsPerMinute);
    int getRateLimit() const;
    int getRemainingRequests() const;

    // Performance metrics
    float getAverageLatency() const;
    float getThroughput() const;  // tokens/sec
    size_t getTotalRequests() const;

    // Context management for conversations
    std::string createContext();
    void appendToContext(const std::string& contextId, const std::string& message);
    void clearContext(const std::string& contextId);
    std::vector<std::string> getContext(const std::string& contextId) const;

    // Configuration
    void setTimeout(int milliseconds);
    void setRetryCount(int count);
    void setApiEndpoint(const std::string& endpoint);
    void setApiKey(const std::string& apiKey);

private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
    
    std::string generateCacheKey(const InferenceRequest& request);
    bool checkRateLimit();
    void updateMetrics(const InferenceResponse& response);
};

// Global instance
UnifiedAIEngine& GetAIEngine();

// Utility functions
std::string buildPromptTemplate(const std::string& task, 
                                   const std::string& code,
                                   const std::string& language = "cpp");
std::string sanitizeCode(const std::string& code);
std::string truncateContext(const std::string& context, size_t maxTokens);

} // namespace AI
} // namespace RawrXD
