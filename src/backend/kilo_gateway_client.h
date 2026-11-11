// =============================================================================
// kilo_gateway_client.h — Kilo Gateway Client (OpenAI-compatible, free catalog)
// =============================================================================
// The Kilo Gateway is an OpenAI-compatible HTTPS endpoint that fronts a
// catalog of free models:
//
//   GET  https://ai-gateway.kilo.ai/api/v1/models            -> the catalog
//   POST https://ai-gateway.kilo.ai/api/v1/chat/completions  -> chat (SSE)
//
// Authentication is a bearer token supplied by the caller: copy the personal
// gateway key from the bottom of the profile page at app.kilo.ai. RawrXD
// reads it from the KILO_API_KEY environment variable and the default model
// from KILO_MODEL, matching the convention already used by
// src/universal_model_router.cpp.
//
// This client is deliberately separate from the Ollama client:
//   * Ollama  -> http://127.0.0.1:11434, no auth, NDJSON stream
//   * Kilo    -> https://api.kilo.ai,     bearer auth, SSE stream
// They are different providers with different trust and cost properties, and
// conflating them would let a cloud request be mistaken for local inference.
//
// Dependency-free: WinHTTP for transport, the in-tree nlohmann/json for
// payloads. No new library, no Qt.
// =============================================================================
#pragma once

#include <string>
#include <vector>
#include <functional>
#include <atomic>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace RawrXD {
namespace Backend {

// ---------------------------------------------------------------------------
// Catalog entry
// ---------------------------------------------------------------------------
struct KiloModel {
    std::string id;
    std::string name;
    std::string description;
    bool        is_free = false;
};

// ---------------------------------------------------------------------------
// Chat reply
// ---------------------------------------------------------------------------
struct KiloResponse {
    bool        success = false;
    std::string content;
    std::string error;
    std::string finish_reason;
    uint64_t    prompt_tokens = 0;
    uint64_t    completion_tokens = 0;
    uint64_t    reasoning_tokens = 0;
    double      total_duration_ms = 0.0;
    // Reasoning models (Nemotron, DeepSeek-R1, ...) emit a long reasoning
    // stream BEFORE the answer. It is kept out of `content` so the answer is
    // never contaminated, and so the caller can see that the token budget was
    // largely spent on thinking.
    std::string reasoning;
};

// ---------------------------------------------------------------------------
// Streaming callbacks
// ---------------------------------------------------------------------------
using KiloTokenCallback = std::function<void(const std::string& token)>;
using KiloDoneCallback  = std::function<void(const std::string& full,
                                             uint64_t prompt_tokens,
                                             uint64_t completion_tokens,
                                             double tokens_per_sec)>;
using KiloErrorCallback = std::function<void(const std::string& error)>;
/// @brief Reasoning text, delivered separately from the answer.
using KiloReasoningCallback = std::function<void(const std::string& reasoning)>;

class KiloGatewayClient {
public:
    explicit KiloGatewayClient(const std::string& base_url = "https://ai-gateway.kilo.ai/api/v1");
    ~KiloGatewayClient();

    void setBaseUrl(const std::string& url) { m_base_url = url; }
    const std::string& baseUrl() const { return m_base_url; }

    // ---- Credentials ----------------------------------------------------
    // An empty key is replaced by $KILO_API_KEY. The key is never logged.
    void setApiKey(const std::string& key) { m_api_key = key; }
    const std::string& apiKey() const { return m_api_key; }
    bool hasApiKey() const;
    /// @brief The default model: $KILO_MODEL, else "kilo-auto/free".
    static std::string DefaultModel();

    // ---- Transport ------------------------------------------------------
    void setTimeoutSeconds(int seconds) { m_timeout_seconds = seconds; }
    void cancel() { m_cancelled.store(true); }
    bool wasCancelled() const { return m_cancelled.load(); }
    void clearCancel() { m_cancelled.store(false); }
    const std::string& lastError() const { return m_last_error; }

    // ---- Operations -----------------------------------------------------
    bool testConnection();
    std::vector<KiloModel> listModels();
    KiloResponse chatSync(const std::vector<std::pair<std::string, std::string>>& messages,
                          const std::string& model,
                          int max_tokens = 1024);
    bool chatStream(const std::vector<std::pair<std::string, std::string>>& messages,
                    const std::string& model,
                    int max_tokens,
                    KiloTokenCallback on_token,
                    KiloDoneCallback  on_done,
                    KiloErrorCallback on_error,
                    KiloReasoningCallback on_reasoning = nullptr);

private:
    std::string m_base_url;
    std::string m_api_key;
    int         m_timeout_seconds = 120;
    std::atomic<bool> m_cancelled{false};
    std::string m_last_error;

    bool httpRequest(const std::string& method, const std::string& path,
                      const std::string* body, std::string& out_body,
                      std::string& out_error);
};

} // namespace Backend
} // namespace RawrXD
