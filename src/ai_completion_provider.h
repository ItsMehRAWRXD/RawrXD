#pragma once
/**
 * @file ai_completion_provider.h
 * @brief AI-powered code completion provider for RawrXD IDE
 * 
 * Provides async code completions via Deep2 Native API or fallback providers.
 * Auto-discovers backends in priority order: Deep2 -> RawrXD -> Ollama
 * Supports streaming responses, confidence scoring, and timeout fallbacks.
 */

#include <string>
#include <vector>
#include <functional>
#include <atomic>
#include "deep2/Deep2Discovery.h"

namespace RawrXD {

//=============================================================================
// Completion result structure
//=============================================================================
struct AICompletion {
    std::string text;           // The completion text
    std::string type;           // "snippet", "text", "function", "keyword"
    float confidence = 0.0f;    // 0.0 - 1.0
    std::string description;    // Optional description for tooltip
    std::string detail;         // Detailed information
    int priority = 0;           // Sorting priority
};

//=============================================================================
// AICompletionProvider class
//=============================================================================
class AICompletionProvider {
public:
    // Constructors
    explicit AICompletionProvider(void* parent = nullptr);
    ~AICompletionProvider();

    // Configuration
    void setModelEndpoint(const std::string& endpoint);  // Manual override
    void autoDiscoverEndpoint();                          // Auto-detect best backend
    void setAllowRemoteEndpoint(bool enabled);
    void setModel(const std::string& modelName);
    void setRequestTimeout(int timeoutMs);
    void setTimeoutFallback(bool enabled);
    void setMinConfidence(float threshold);
    void setMaxSuggestions(int count);

    // Completion request
    void requestCompletions(
        const std::string& prefix,
        const std::string& suffix,
        const std::string& filePath,
        const std::string& fileType,
        const std::vector<std::string>& contextLines
    );

    // Cancel pending request
    void cancelPendingRequest();

    // Status
    bool isPending() const { return m_isPending; }
    double getLastLatency() const { return m_lastLatencyMs; }
    std::string getCurrentEndpoint() const { return m_modelEndpoint; }
    bool isUsingDeep2Native() const { return m_usingDeep2Native; }

    // Callbacks
    using CompletionCallback = std::function<void(const std::vector<AICompletion>&)>;
    using ErrorCallback = std::function<void(const std::string&)>;
    using LatencyCallback = std::function<void(double)>;

    void setCompletionCallback(CompletionCallback callback) { m_completionCallback = callback; }
    void setErrorCallback(ErrorCallback callback) { m_errorCallback = callback; }
    void setLatencyCallback(LatencyCallback callback) { m_latencyCallback = callback; }

private:
    // Internal methods
    void onCompletionRequest();
    std::string formatPrompt(
        const std::string& prefix,
        const std::string& suffix,
        const std::string& fileType,
        const std::vector<std::string>& contextLines
    );
    std::string callModel(const std::string& prompt);
    std::vector<AICompletion> parseCompletions(const std::string& responseText);
    float extractConfidence(const std::string& suggestion);
    std::string generateFallbackCompletion(const std::string& prompt);
    void discoverEndpoint();

    // Configuration
    std::string m_modelEndpoint = "http://localhost:11436";  // Default to Deep2
    bool m_allowRemoteEndpoint = false;
    std::string m_modelName = "deep2-native";
    int m_requestTimeoutMs = 5000;
    bool m_useTimeoutFallback = true;
    float m_minConfidence = 0.1f;
    int m_maxSuggestions = 5;
    bool m_usingDeep2Native = true;
    bool m_endpointDiscovered = false;

    // State
    std::atomic<bool> m_isPending{false};
    std::string m_lastPrefix;
    std::string m_lastSuffix;
    std::string m_lastFileType;
    std::vector<std::string> m_lastContext;
    double m_lastLatencyMs = 0.0;

    // Callbacks
    CompletionCallback m_completionCallback;
    ErrorCallback m_errorCallback;
    LatencyCallback m_latencyCallback;
};

} // namespace RawrXD
