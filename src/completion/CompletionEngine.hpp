// ============================================================================
// CompletionEngine.hpp — Real-Time Ghost Text and FIM Completion
// Provides intelligent inline completions with sub-50ms latency
// ============================================================================
#pragma once

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include <queue>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <thread>
#include <mutex>

namespace RawrXD {
namespace Completion {

using json = nlohmann::json;

// ============================================================================
// Completion Request
// ============================================================================
struct CompletionRequest {
    std::string filePath;
    std::string language;
    std::string prefix;           // Text before cursor
    std::string suffix;           // Text after cursor (for FIM)
    std::string linePrefix;       // Current line before cursor
    std::string lineSuffix;       // Current line after cursor
    int line = 0;
    int column = 0;
    int cursorPosition = 0;
    
    // Context
    std::vector<std::string> recentEdits;
    std::vector<std::string> openFiles;
    std::vector<std::string> importedSymbols;
    
    // Preferences
    int maxSuggestions = 3;
    int maxTokens = 128;
    float temperature = 0.2f;
    bool useFIM = true;           // Fill-in-the-middle
    bool streaming = true;
};

// ============================================================================
// Completion Item
// ============================================================================
struct CompletionItem {
    std::string text;             // Full completion text
    std::string displayText;      // Shown in UI
    std::string insertText;       // Actually inserted
    std::string detail;           // Additional info
    std::string documentation;
    std::string kind;             // function, variable, class, etc.
    float confidence = 0.0f;
    int tokenCount = 0;
    std::chrono::milliseconds latency;
    bool isGhostText = false;     // Inline completion vs dropdown
};

// ============================================================================
// Completion Response
// ============================================================================
struct CompletionResponse {
    std::vector<CompletionItem> items;
    bool isIncomplete = false;
    std::chrono::milliseconds totalLatency;
    std::string modelUsed;
};

// ============================================================================
// Cache Entry
// ============================================================================
struct CacheEntry {
    std::string key;
    CompletionResponse response;
    std::chrono::system_clock::time_point timestamp;
    int hitCount = 0;
};

// ============================================================================
// Completion Engine
// High-performance completion with caching and debouncing
// ============================================================================
class CompletionEngine {
public:
    CompletionEngine();
    ~CompletionEngine();
    
    // Initialization
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const { return m_initialized; }
    
    // Configuration
    void SetDebounceMs(int ms) { m_debounceMs = ms; }
    void SetMaxCacheSize(size_t size) { m_maxCacheSize = size; }
    void SetLatencyTargetMs(int ms) { m_latencyTargetMs = ms; }
    
    // Synchronous completion (blocking)
    CompletionResponse Complete(const CompletionRequest& request);
    
    // Asynchronous completion (non-blocking with callback)
    using CompletionCallback = std::function<void(const CompletionResponse&)>;
    void CompleteAsync(const CompletionRequest& request, CompletionCallback callback);
    
    // Streaming completion (token-by-token)
    using TokenCallback = std::function<void(const std::string& token, bool isFinal)>;
    void CompleteStream(const CompletionRequest& request, TokenCallback callback);
    
    // Ghost text (inline completion)
    std::string GetGhostText(const CompletionRequest& request);
    
    // Cache management
    void ClearCache();
    size_t GetCacheSize() const;
    json GetCacheStats() const;
    
    // Prefetching
    void Prefetch(const std::string& filePath, const std::vector<int>& lines);
    
    // Cancellation
    void CancelCurrentRequest();
    bool IsRequestPending() const { return m_pending.load(); }
    
    // Performance metrics
    json GetMetrics() const;
    void ResetMetrics();
    
private:
    // Internal methods
    std::string BuildFIMPrompt(const CompletionRequest& request);
    std::string BuildStandardPrompt(const CompletionRequest& request);
    CompletionResponse GenerateCompletions(const CompletionRequest& request);
    CompletionItem PostProcess(const std::string& raw, const CompletionRequest& request);
    
    // Caching
    std::string BuildCacheKey(const CompletionRequest& request);
    bool GetFromCache(const std::string& key, CompletionResponse& response);
    void AddToCache(const std::string& key, const CompletionResponse& response);
    void EvictCache();
    
    // Debouncing
    bool ShouldDebounce(const CompletionRequest& request);
    
    // Model interaction
    std::string CallModel(const std::string& prompt, int maxTokens, float temperature);
    void CallModelStream(const std::string& prompt, 
                         int maxTokens, 
                         float temperature,
                         TokenCallback callback);
    
private:
    // Configuration
    int m_debounceMs = 50;
    int m_latencyTargetMs = 50;
    size_t m_maxCacheSize = 1000;
    
    // State
    std::atomic<bool> m_initialized{false};
    std::atomic<bool> m_pending{false};
    std::atomic<bool> m_cancelled{false};
    
    // Cache
    std::unordered_map<std::string, CacheEntry> m_cache;
    mutable std::mutex m_cacheMutex;
    
    // Request history for debouncing
    CompletionRequest m_lastRequest;
    std::chrono::system_clock::time_point m_lastRequestTime;
    std::mutex m_requestMutex;
    
    // Async processing
    std::unique_ptr<std::thread> m_workerThread;
    std::queue<std::pair<CompletionRequest, CompletionCallback>> m_requestQueue;
    std::mutex m_queueMutex;
    std::condition_variable m_queueCv;
    
    // Metrics
    struct Metrics {
        std::atomic<uint64_t> totalRequests{0};
        std::atomic<uint64_t> cacheHits{0};
        std::atomic<uint64_t> cancelledRequests{0};
        std::atomic<uint64_t> totalLatencyMs{0};
        std::atomic<uint64_t> maxLatencyMs{0};
    } m_metrics;
};

} // namespace Completion
} // namespace RawrXD
