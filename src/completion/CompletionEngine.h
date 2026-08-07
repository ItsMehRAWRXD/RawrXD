#pragma once

#include "../core/AIProvider.h"
#include <string>
#include <vector>
#include <functional>
#include <chrono>
#include <atomic>
#include <thread>
#include <mutex>

namespace RawrXD {

// ============================================================================
// Completion Engine — Real-time ghost text for IDE
// Phase 15 — Product Layer
// ============================================================================
// This is the feature users feel immediately. It transforms Deep2 from
// a "chat with AI" into "AI that types with me."
// ============================================================================

// Editor context at cursor position
struct EditorContext {
    std::string filePath;
    std::string language;
    std::string prefix;         // Text before cursor
    std::string suffix;         // Text after cursor (for FIM)
    std::string imports;        // File header / imports
    uint32_t    lineNumber = 0;
    uint32_t    columnNumber = 0;
    std::string recentEdits;    // Last N edits for temporal context
};

// Completion suggestion
struct CompletionSuggestion {
    std::string text;           // The completion text
    std::string displayText;    // Truncated for UI
    float       confidence = 0.0f;
    bool        isFullLine = false;
    uint32_t    tokens = 0;
    double      latencyMs = 0.0;
};

// Completion result
struct CompletionResult {
    bool success = false;
    std::vector<CompletionSuggestion> suggestions;
    std::string error;
    double totalLatencyMs = 0.0;
};

// Ghost text renderer interface (implemented by IDE)
class IGhostTextRenderer {
public:
    virtual ~IGhostTextRenderer() = default;
    virtual void ShowGhostText(const std::string& text, uint32_t line, uint32_t col) = 0;
    virtual void HideGhostText() = 0;
    virtual void AcceptGhostText() = 0;
    virtual bool IsGhostTextVisible() const = 0;
};

// Cancellation token for in-flight requests
class CancellationToken {
public:
    void Cancel() { cancelled_.store(true); }
    bool IsCancelled() const { return cancelled_.load(); }
    void Reset() { cancelled_.store(false); }
private:
    std::atomic<bool> cancelled_{false};
};

// ============================================================================
// CompletionEngine — The main interface
// ============================================================================
class CompletionEngine {
public:
    CompletionEngine();
    ~CompletionEngine();

    // Initialize with AI provider
    bool Initialize(AIProvider* provider);

    // Request completion (async)
    void RequestCompletion(
        const EditorContext& ctx,
        std::function<void(const CompletionResult&)> callback,
        CancellationToken* cancelToken = nullptr
    );

    // Cancel current request
    void CancelCurrentRequest();

    // Configuration
    void SetDebounceMs(uint32_t ms) { debounceMs_ = ms; }
    void SetMaxSuggestions(uint32_t max) { maxSuggestions_ = max; }
    void SetGhostTextRenderer(IGhostTextRenderer* renderer) { renderer_ = renderer; }

    // Status
    bool IsReady() const;
    bool IsRequestInFlight() const { return requestInFlight_.load(); }
    std::string GetStatus() const;

    // Statistics
    struct Stats {
        uint64_t requestsTotal = 0;
        uint64_t requestsCancelled = 0;
        uint64_t requestsSucceeded = 0;
        double avgLatencyMs = 0.0;
        double avgTokensPerSec = 0.0;
    };
    Stats GetStats() const;

private:
    class Impl;
    std::unique_ptr<Impl> pImpl;

    // Config
    uint32_t debounceMs_ = 50;           // 50ms debounce
    uint32_t maxSuggestions_ = 3;      // Top 3 suggestions
    IGhostTextRenderer* renderer_ = nullptr;

    // State
    std::atomic<bool> requestInFlight_{false};
    std::atomic<bool> initialized_{false};
    AIProvider* provider_ = nullptr;

    // Background thread for debouncing
    std::unique_ptr<std::thread> workerThread_;
    std::mutex mutex_;
};

// ============================================================================
// FIM Context Builder — Fill-in-the-middle prompt construction
// ============================================================================
class FIMContextBuilder {
public:
    // Build FIM prompt from editor context
    static std::string BuildFIMPrompt(const EditorContext& ctx);

    // Build chat-style completion prompt (for models without FIM)
    static std::string BuildChatPrompt(const EditorContext& ctx);

    // Extract relevant context (imports, class scope, etc.)
    static std::string ExtractRelevantContext(const EditorContext& ctx);

    // Truncate prefix/suffix to fit in context window
    static void TruncateToContextWindow(
        std::string& prefix,
        std::string& suffix,
        size_t maxTokens,
        size_t reserveForCompletion
    );
};

// ============================================================================
// Completion Ranker — Score and filter suggestions
// ============================================================================
class CompletionRanker {
public:
    struct ScoredSuggestion {
        CompletionSuggestion suggestion;
        float score;
    };

    // Rank suggestions by relevance
    static std::vector<ScoredSuggestion> Rank(
        const std::vector<std::string>& rawCompletions,
        const EditorContext& ctx
    );

    // Filter low-confidence suggestions
    static std::vector<CompletionSuggestion> FilterByConfidence(
        const std::vector<ScoredSuggestion>& scored,
        float threshold
    );

    // Deduplicate similar suggestions
    static std::vector<CompletionSuggestion> Deduplicate(
        const std::vector<CompletionSuggestion>& suggestions
    );
};

// ============================================================================
// Prefix/Suffix Extractor — Editor integration helpers
// ============================================================================
class PrefixSuffixExtractor {
public:
    // Extract prefix/suffix from full document
    static EditorContext ExtractFromDocument(
        const std::string& fullText,
        uint32_t cursorPos,
        const std::string& filePath,
        const std::string& language
    );

    // Extract from line-oriented buffer (for IDE integration)
    static EditorContext ExtractFromLines(
        const std::vector<std::string>& lines,
        uint32_t cursorLine,
        uint32_t cursorCol,
        const std::string& filePath,
        const std::string& language
    );

    // Get current function/class scope
    static std::string GetCurrentScope(
        const std::vector<std::string>& lines,
        uint32_t cursorLine
    );
};

// ============================================================================
// Completion Cache — LRU cache for common completions
// ============================================================================
class CompletionCache {
public:
    struct CacheKey {
        std::string prefixHash;
        std::string language;
        std::string scope;

        bool operator==(const CacheKey& other) const;
    };

    struct CacheEntry {
        CompletionResult result;
        std::chrono::steady_clock::time_point timestamp;
        uint32_t hitCount = 0;
    };

    CompletionCache(size_t maxEntries = 1000);

    // Get cached result
    bool Get(const CacheKey& key, CompletionResult& out);

    // Store result
    void Put(const CacheKey& key, const CompletionResult& result);

    // Invalidate entries for a file
    void InvalidateFile(const std::string& filePath);

    // Clear all
    void Clear();

private:
    size_t maxEntries_;
    std::unordered_map<CacheKey, CacheEntry, std::hash<CacheKey>> entries_;
    std::mutex mutex_;
};

} // namespace RawrXD
