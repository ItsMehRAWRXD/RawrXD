// =============================================================================
// OllamaBackend.h — Ollama HTTP Backend Adapter
// =============================================================================
// Implements InferenceBackend by reusing the existing WinHTTP-based
// OllamaClient (src/backend/ollama_client.cpp). No separate HTTP implementation;
// the agent/orchestrator talks to InferenceBackend, which delegates to
// OllamaClient for HTTP transport.
// =============================================================================
#pragma once

#include "InferenceBackend.h"
#include "backend/ollama_client.h"
#include <memory>
#include <mutex>
#include <atomic>
#include <deque>

namespace RawrXD {
namespace Agent {

class OllamaBackend : public InferenceBackend {
public:
    OllamaBackend();
    ~OllamaBackend() override;

    // ---- InferenceBackend interface ----
    bool Initialize(const BackendConfig& config) override;
    void Shutdown() override;
    bool IsInitialized() const override;

    BackendKind GetKind() const override { return BackendKind::Ollama; }
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
    // ---- OllamaClient delegation ----
    std::unique_ptr<Backend::OllamaClient> m_client;
    BackendConfig m_config;

    // ---- State ----
    std::atomic<bool> m_initialized{false};
    std::atomic<bool> m_streaming{false};
    std::atomic<bool> m_cancelRequested{false};

    // ---- Stats ----
    mutable std::mutex m_stats_mtx;
    std::atomic<uint64_t> m_totalRequests{0};
    std::atomic<uint64_t> m_totalTokens{0};
    std::atomic<double>   m_accumulatedTps{0.0};
    int                   m_consecutiveErrors{0};
    std::deque<std::string> m_recentErrors;

    // ---- Helpers ----
    void ConvertMessages(const std::vector<ChatMessage>& messages,
                          std::vector<Backend::OllamaChatMessage>& out) const;
    std::string ConvertToolsToJson(const json& tools) const;
    void ParseToolCallsFromResponse(const std::string& response,
                                    InferenceResult& result) const;

    BackendConfig DefaultConfig() const;
    bool     ShouldEmitError(const std::string& msg);
    void     RecordSuccess(double tps, uint64_t ptok, uint64_t ctok);
    void     RecordFailure(const std::string& error);
};

} // namespace Agent
} // namespace RawrXD
