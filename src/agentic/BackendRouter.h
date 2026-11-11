// =============================================================================
// BackendRouter.h — Inference Backend Router with Selection & Failover
// =============================================================================
// Routes inference requests between Deep2 (primary) and Ollama (backup)
// based on operating mode, health, and explicit user selection.
//
// Operating modes:
//   - auto:   Deep2 first; failover to Ollama only if Deep2 is unavailable
//   - deep2:  Deep2 only; explicit failure (no silent fallback)
//   - ollama: Ollama only; full agent capabilities
//   - manual: User selects backend/model explicitly per call
//
// Failover rules:
//   1. On generation START failure (backend unreachable, model not loaded):
//      auto mode → retry once on backup backend with full context.
//   2. On generation MID-STREAM failure (partial output received):
//      STOP and return explicit error. NEVER splice output from two models.
//   3. Tool side-effects are NOT replayed after failover — the agent layer
//      handles retry logic. BackendRouter only routes at request start.
//
// No paid API / cloud fallback. No silent fallback to cloud models.
// =============================================================================
#pragma once

#include "InferenceBackend.h"
#include "Deep2Backend.h"
#include "OllamaBackend.h"
#include <memory>
#include <atomic>
#include <mutex>
#include <thread>
#include <condition_variable>

namespace RawrXD {
namespace Agent {

// ---------------------------------------------------------------------------
// Backend operating mode
// ---------------------------------------------------------------------------
enum class BackendMode : uint8_t {
    Auto,     // Deep2 first; Ollama fallback if Deep2 unavailable
    Deep2,    // Deep2 only; explicit failure
    Ollama,   // Ollama only
    Kilo,     // Kilo Gateway only (OpenAI-compatible, cloud, needs a key)
    Manual,   // User picks backend per-call
};

inline const char* BackendModeName(BackendMode mode) {
    switch (mode) {
        case BackendMode::Auto:    return "auto";
        case BackendMode::Deep2:   return "deep2";
        case BackendMode::Ollama:  return "ollama";
        case BackendMode::Kilo:    return "kilo";
        case BackendMode::Manual:  return "manual";
        default:                   return "unknown";
    }
}

// ---------------------------------------------------------------------------
// Router configuration
// ---------------------------------------------------------------------------
struct RouterConfig {
    BackendMode mode              = BackendMode::Auto;
    bool        allow_cloud_fallback = false;  // NEVER true for local-30B
    std::string primary_endpoint  = "http://127.0.0.1:11436";
    std::string fallback_endpoint = "http://127.0.0.1:11434";
    std::string primary_model;
    std::string fallback_model    = "qwen2.5-coder:32b";
    int         health_check_interval_s = 30;
    bool        retry_from_complete_context = true;  // Retry with full history on failover
    bool        retry_after_tool_side_effects = false; // DANGER: can duplicate side-effects
};

// ---------------------------------------------------------------------------
// BackendRouter — selects backend, manages failover
// ---------------------------------------------------------------------------
class BackendRouter {
public:
    BackendRouter();
    ~BackendRouter();

    // ---- Lifecycle ----
    bool Initialize(const RouterConfig& config);
    void Shutdown();
    bool IsInitialized() const { return m_initialized.load(); }

    // ---- Backend selection ----
    void SetMode(BackendMode mode);
    BackendMode GetMode() const { return m_mode.load(); }

    void SetPrimaryModel(const std::string& model);
    void SetFallbackModel(const std::string& model);
    void SetEndpoints(const std::string& primary, const std::string& fallback);

    // ---- Health ----
    BackendHealth GetPrimaryHealth() const;
    BackendHealth GetFallbackHealth() const;
    bool CheckPrimaryHealth();
    bool CheckFallbackHealth();

    // ---- Model discovery (delegates to active backend) ----
    std::vector<std::string> ListModels(BackendKind preferred = BackendKind::Deep2);

    /// @brief Is this Ollama model served by ollama.com rather than locally?
    bool IsCloudModel(const std::string& model_name);

    /// @brief Route a reasoning model's thinking text to a sink, separately
    /// from the answer.
    void SetThinkingSink(const std::function<void(const std::string&)>& sink);

    // ---- Inference entry points ----
    // These route to the selected backend, with failover per operating mode.
    // If failover occurs, failover_info is filled with details.
    struct FailoverInfo {
        bool        did_failover       = false;
        BackendKind original_backend   = BackendKind::Deep2;
        BackendKind failover_backend   = BackendKind::Ollama;
        std::string failover_reason;
    };

    InferenceResult ChatSync(const std::vector<ChatMessage>& messages,
                             const json& tools,
                             FailoverInfo* failover_info = nullptr);

    bool ChatStream(const std::vector<ChatMessage>& messages,
                    const json& tools,
                    TokenCallback     on_token,
                    ToolCallCallback  on_tool_call,
                    DoneCallback      on_done,
                    ErrorCallback     on_error,
                    FailoverInfo*     failover_info = nullptr);

    InferenceResult FIMSync(const std::string& prefix,
                            const std::string& suffix,
                            const std::string& filename,
                            FailoverInfo* failover_info = nullptr);

    bool FIMStream(const std::string& prefix,
                   const std::string& suffix,
                   const std::string& filename,
                   TokenCallback  on_token,
                   DoneCallback   on_done,
                   ErrorCallback  on_error,
                   FailoverInfo*  failover_info = nullptr);

    // ---- Cancellation ----
    void Cancel();
    bool IsStreaming() const;

    // ---- Active backend introspection ----
    BackendKind GetActiveBackendKind() const;
    std::string GetActiveModel() const;
    std::string GetActiveEndpoint() const;
    BackendMode GetActiveMode() const { return m_mode.load(); }

    // ---- Backend access ----
    InferenceBackend& GetBackend(BackendKind kind);
    InferenceBackend* GetBackendPtr(BackendKind kind);

private:
    // ---- Backend instances ----
    std::unique_ptr<Deep2Backend> m_deep2;
    std::unique_ptr<OllamaBackend> m_ollama;

    std::atomic<bool> m_initialized{false};
    std::atomic<BackendMode> m_mode{BackendMode::Auto};
    RouterConfig m_config;

    // ---- Active backend tracking ----
    mutable std::mutex m_active_mtx;
    BackendKind m_active_kind = BackendKind::Deep2;
    std::string m_active_model;
    std::string m_active_endpoint;

    // ---- Health check thread ----
    std::thread m_health_thread;
    std::atomic<bool> m_health_running{false};
    std::condition_variable m_health_cv;
    std::mutex m_health_cv_mtx;

    // ---- Stats ----
    std::atomic<uint64_t> m_total_requests{0};
    std::atomic<uint64_t> m_failovers{0};

    // ---- Internal helpers ----
    void HealthCheckLoop();
    BackendKind SelectBackendForRequest(FailoverInfo* failover_info);
    void RouteToBackend(BackendKind kind, const std::string& model);
    bool IsBackendAvailable(BackendKind kind);
};

} // namespace Agent
} // namespace RawrXD
