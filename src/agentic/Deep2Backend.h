// =============================================================================
// Deep2Backend.h — Deep2 Native Inference Backend Adapter
// =============================================================================
// Implements InferenceBackend by communicating with the Deep2 Local Server
// (OpenAI-compatible API at 127.0.0.1:11436). Deep2 is the primary backend:
// native GGUF compute with GPU acceleration, streaming, and full inference
// capabilities. This is NOT a separate agent system — it supplies model
// inference to the shared agent/orchestrator layer.
//
// Key design:
//   - Uses WinHTTP for HTTP transport (same pattern as ollama_client.cpp)
//   - OpenAI-compatible /chat/completions and /completions endpoints
//   - Deep2-specific health endpoint at /health (per Deep2ProductionManifest.json)
//   - Full feature parity with InferenceBackend interface
//   - No paid API, no cloud fallback — explicit error on missing server
// =============================================================================
#pragma once

#include "InferenceBackend.h"
#include <atomic>
#include <mutex>
#include <deque>
#include <string>

namespace RawrXD {
namespace Agent {

class Deep2Backend : public InferenceBackend {
public:
    Deep2Backend();
    ~Deep2Backend() override;

    // ---- InferenceBackend interface ----
    bool Initialize(const BackendConfig& config) override;
    void Shutdown() override;
    bool IsInitialized() const override;

    BackendKind GetKind() const override { return BackendKind::Deep2; }
    BackendConfig GetConfig() const override;
    void SetConfig(const BackendConfig& config) override;

    BackendHealth GetHealth() const override;
    bool CheckHealth() override;

    bool Supports(BackendCapability cap) const override;

    std::vector<std::string> ListModels() override;
    bool LoadModel(const std::string& model_name) override;

    InferenceResult ChatSync(const std::vector<ChatMessage>& messages,
                             const json& tools = json::array()) override;

    bool ChatStream(const std::vector<ChatMessage>& messages,
                    const json& tools,
                    TokenCallback     on_token,
                    ToolCallCallback  on_tool_call,
                    DoneCallback      on_done,
                    ErrorCallback     on_error) override;

    InferenceResult FIMSync(const std::string& prefix,
                            const std::string& suffix,
                            const std::string& filename = "") override;

    bool FIMStream(const std::string& prefix,
                   const std::string& suffix,
                   const std::string& filename,
                   TokenCallback  on_token,
                   DoneCallback   on_done,
                   ErrorCallback  on_error) override;

    void Cancel() override;
    bool IsStreaming() const override;

    uint64_t GetTotalRequests() const override;
    double   GetAvgTokensPerSec() const override;

private:
    BackendConfig m_config;

    std::atomic<bool> m_initialized{false};
    std::atomic<bool> m_streaming{false};
    std::atomic<bool> m_cancelRequested{false};

    mutable std::mutex m_stats_mtx;
    std::atomic<uint64_t> m_totalRequests{0};
    std::atomic<uint64_t> m_totalTokens{0};
    std::atomic<double>   m_accumulatedTps{0.0};
    int                   m_consecutiveErrors{0};
    std::deque<std::string> m_recentErrors;

    // ---- HTTP helpers (WinHTTP) ----
    std::string makeGetRequest(const std::string& endpoint);
    std::string makePostRequest(const std::string& endpoint, const std::string& json_body);
    std::string makePostRequestStreaming(const std::string& endpoint,
                                         const std::string& json_body,
                                         std::function<bool(const std::string& chunk)> onChunk);

    // ---- Message/tool conversion ----
    json BuildOpenAiMessages(const std::vector<ChatMessage>& messages) const;

    // ---- Helpers ----
    BackendConfig DefaultConfig() const;
    bool     ShouldEmitError(const std::string& msg);
    void     RecordSuccess(double tps, uint64_t ptok, uint64_t ctok);
    void     RecordFailure(const std::string& error);
};

} // namespace Agent
} // namespace RawrXD
