// ============================================================================
// NativeStreamProvider.h — Ollama-backed Prediction Provider
// ============================================================================
// Implements PredictionProvider for local Ollama instances.
//
// Features:
//   - Synchronous and streaming predictions
//   - FIM (Fill-in-Middle) prompt format for Qwen2.5-Coder
//   - Cancellable in-flight requests
//   - Connection health check (IsAvailable)
//   - WinHTTP-based (no external HTTP dependencies)
//
// Pattern: PatchResult-style, no exceptions, factory results.
// Rule:    NO SOURCE FILE IS TO BE SIMPLIFIED.
// ============================================================================

#pragma once

#include <string>
#include <functional>

// PredictionProvider.h is incorrectly named - it contains test code.
// Creating minimal forward declarations here to fix build.
// TODO: Create proper PredictionProvider base class header
namespace RawrXD {
namespace Prediction {
    struct PredictionConfig {
        std::string model;
        float temperature = 0.7f;
        int maxTokens = 2048;
        int maxLines = 5;           // Max lines for ghost text
        bool useFIM = true;         // Use Fill-in-Middle format
        std::string stopSequences;  // Comma-separated stop sequences
    };
    struct PredictionContext {
        std::string prefix;
        std::string suffix;
        std::string filePath;
        std::string language;
        int cursorLine = 0;         // Cursor line position
        int cursorColumn = 0;       // Cursor column position
    };
    struct PredictionResult {
        std::string text;           // Generic text result
        std::string completion;     // Completion for ghost text (alias for text)
        bool success = false;
        int tokens = 0;
        int64_t elapsedMs = 0;
        std::string error;
        
        // Constructor to auto-populate completion from text
        PredictionResult() = default;
        explicit PredictionResult(const std::string& t) : text(t), completion(t), success(true) {}
        
        // Factory methods
        static PredictionResult Ok(const std::string& comp, int tok = 0, int64_t elapsed = 0) {
            PredictionResult r;
            r.completion = comp;
            r.text = comp;
            r.tokens = tok;
            r.elapsedMs = elapsed;
            r.success = true;
            return r;
        }
        static PredictionResult Error(const std::string& msg) {
            PredictionResult r;
            r.error = msg;
            r.success = false;
            return r;
        }
        static PredictionResult Cancelled() {
            PredictionResult r;
            r.error = "Cancelled";
            r.success = false;
            return r;
        }
    };
    // StreamTokenCallback: (token, is_final) -> should_continue
    using StreamTokenCallback = std::function<bool(const std::string&, bool)>;
    
    class PredictionProvider {
    public:
        virtual ~PredictionProvider() = default;
        virtual void Configure(const PredictionConfig& config) = 0;
        virtual bool IsAvailable() const = 0;
        virtual PredictionResult Predict(const PredictionContext& ctx) = 0;
        virtual void PredictStreaming(const PredictionContext& ctx, StreamTokenCallback callback) = 0;
        virtual void Cancel() = 0;
    };
    
    // Alias for compatibility - OllamaProvider is NativeStreamProvider
    // Moved after class declaration to avoid forward reference
    // using OllamaProvider = NativeStreamProvider;
}
}
#include <atomic>
#include <functional>
#include <mutex>
#include <string>

namespace RawrXD
{
namespace Prediction
{

class NativeStreamProvider : public PredictionProvider
{
  public:
    NativeStreamProvider();
    explicit NativeStreamProvider(const std::string& baseUrl);
    ~NativeStreamProvider() override;

    // ---- Configuration ----
    void Configure(const PredictionConfig& config) override;
    bool IsAvailable() const override;

    // ---- Synchronous prediction ----
    PredictionResult Predict(const PredictionContext& ctx) override;

    // ---- Streaming prediction ----
    void PredictStreaming(const PredictionContext& ctx, StreamTokenCallback callback) override;

    // ---- Cancellation ----
    void Cancel() override;

    // ---- Ollama-specific ----
    void SetBaseUrl(const std::string& url) { m_baseUrl = url; }
    std::string GetBaseUrl() const { return m_baseUrl; }
    bool CheckConnection() const;

    // ---- Shared HTTP surface (agent / tools — no duplicate WinHTTP scaffolds) ----
    /// Sync JSON request; empty \p body performs GET. Used for /api/tags, etc.
    std::string SyncHttpJson(const std::string& endpoint, const std::string& body, bool& success) const;
    /// POST with NDJSON response lines (Ollama stream=true). \p onLine returns false to stop early.
    void StreamHttpJsonLines(const std::string& endpoint, const std::string& jsonBody,
                             std::function<bool(const std::string& line)> onLine) const;
    /// First model name from GET /api/tags, or empty if unavailable.
    std::string GetFirstModelTag() const;

    // ---- Retry configuration ----
    void SetMaxRetries(int n) { m_maxRetries = n; }
    void SetRetryBaseDelayMs(int ms) { m_retryBaseDelayMs = ms; }

  private:
    // ---- RAII WinHTTP handle ----
    struct WinHttpHandle
    {
        void* h = nullptr;
        WinHttpHandle() = default;
        explicit WinHttpHandle(void* handle) : h(handle) {}
        ~WinHttpHandle();
        WinHttpHandle(const WinHttpHandle&) = delete;
        WinHttpHandle& operator=(const WinHttpHandle&) = delete;
        WinHttpHandle(WinHttpHandle&& o) noexcept : h(o.h) { o.h = nullptr; }
        WinHttpHandle& operator=(WinHttpHandle&& o) noexcept;
        explicit operator bool() const { return h != nullptr; }
        void* get() const { return h; }
        void reset(void* handle = nullptr);
    };

    // ---- HTTP helpers ----
    std::string PostJson(const std::string& endpoint, const std::string& body, bool& success) const;

    std::string PostJsonOnce(const std::string& endpoint, const std::string& body, bool& success) const;

    void PostJsonStreaming(const std::string& endpoint, const std::string& body,
                           std::function<bool(const std::string& chunk)> onChunk) const;

    bool PostJsonStreamingOnce(const std::string& endpoint, const std::string& body,
                               std::function<bool(const std::string& chunk)> onChunk) const;

    // ---- State ----
    std::string m_baseUrl;
    PredictionConfig m_config;
    mutable std::atomic<bool> m_cancelled{false};
    mutable std::mutex m_mutex;
    int m_maxRetries = 3;
    int m_retryBaseDelayMs = 200;
};

}  // namespace Prediction
}  // namespace RawrXD

// Deleter for forward-declared NativeStreamProvider in Win32IDE.h
struct NativeStreamProviderDeleter
{
    void operator()(RawrXD::Prediction::NativeStreamProvider* ptr) noexcept;
};

// Alias for compatibility - OllamaProvider is NativeStreamProvider
namespace RawrXD {
namespace Prediction {
    using OllamaProvider = NativeStreamProvider;
}
}
