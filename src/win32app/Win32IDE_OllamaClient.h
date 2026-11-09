#pragma once
// Win32IDE_OllamaClient.h — Ollama HTTP client with STREAM-INTEGRITY-001 compliance
// Contract: BACKEND_ROUTE, MODEL_TAG_RESOLUTION, REQUEST_OPTIONS, HTTP_STATUS_VALIDATION,
//           NDJSON_PARSE, STREAM_CHUNK_ORDER, STREAM_FINALIZE_ONCE, TURN_ISOLATION,
//           CANCEL_STALE_TURNS, UTF8_ROUNDTRIP, RAW_VS_RENDERED_PARITY, ERROR_PROPAGATION

#include <string>
#include <vector>
#include <functional>
#include <atomic>
#include <mutex>
#include <cstdint>
#include <windows.h>
#include <winhttp.h>
#include <nlohmann/json.hpp>

#pragma comment(lib, "winhttp.lib")

using json = nlohmann::json;

namespace RawrXD {

struct OllamaOptions {
    float temperature = 0.0f;
    float top_p = 0.9f;
    int num_ctx = 8192;
    int num_predict = 4096;
    float repeat_penalty = 1.1f;
    int seed = -1;
    int num_gpu = 99;
    bool use_mmap = true;
    bool use_mlock = false;
    int num_thread = 0;
};

struct OllamaModelInfo {
    std::string name;
    std::string model_id;
    size_t parameter_size = 0;
    std::string quantization;
    std::string family;
};

struct TurnHandle {
    uint64_t request_id;
    std::atomic<bool> cancelled{false};
};

using TokenCallback = std::function<void(const std::string& token)>;
using DoneCallback = std::function<void(const std::string& full_response, uint64_t prompt_tokens, uint64_t completion_tokens, double tokens_per_sec)>;
using ErrorCallback = std::function<void(const std::string& error)>;

struct StreamState {
    std::string buffer;
    std::string accumulated_text;
    uint64_t prompt_tokens = 0;
    uint64_t completion_tokens = 0;
    std::chrono::steady_clock::time_point start_time;
    TokenCallback on_token;
    DoneCallback on_done;
    ErrorCallback on_error;
    std::atomic<bool>* cancelled;
    uint64_t request_id;
};

class OllamaClient {
public:
    explicit OllamaClient(const std::string& base_url = "http://127.0.0.1:11434");
    ~OllamaClient();

    // Disallow copy (thread state), allow move
    OllamaClient(const OllamaClient&) = delete;
    OllamaClient& operator=(const OllamaClient&) = delete;
    OllamaClient(OllamaClient&&) noexcept;
    OllamaClient& operator=(OllamaClient&&) noexcept;

    // Connection test
    bool TestConnection();
    std::string GetVersion();

    // Model management
    std::vector<OllamaModelInfo> ListModels();
    bool ResolveModelTag(const std::string& model_hint, std::string& out_tag);

    // Synchronous generation (non-streaming)
    struct GenerateResult {
        std::string text;
        uint64_t prompt_tokens = 0;
        uint64_t completion_tokens = 0;
        double tokens_per_sec = 0.0;
        double total_duration_ms = 0.0;
        bool success = false;
        std::string error;
    };
    GenerateResult GenerateSync(const std::string& model_tag,
                                const std::string& prompt,
                                const OllamaOptions& options = {});

    // Streaming generation
    // on_token called per decoded token (not per raw chunk)
    // on_done called exactly once with full response
    // on_error called on transport/parse/HTTP failure
    // Returns a TurnHandle for cancellation
    TurnHandle GenerateStream(const std::string& model_tag,
                              const std::string& prompt,
                              const OllamaOptions& options,
                              TokenCallback on_token,
                              DoneCallback on_done,
                              ErrorCallback on_error);

    // Streaming chat
    // Messages format: role/content pairs, compatible with /api/chat
    struct ChatMessage {
        std::string role;    // "system", "user", "assistant", "tool"
        std::string content;
    };
    TurnHandle ChatStream(const std::vector<ChatMessage>& messages,
                          const OllamaOptions& options,
                          TokenCallback on_token,
                          DoneCallback on_done,
                          ErrorCallback on_error);

    // Cancel a turn by its request_id (best effort)
    void CancelTurn(uint64_t request_id);

    // Configuration
    void SetBaseUrl(const std::string& url);
    void SetTimeoutSeconds(int seconds) { m_timeout_seconds = seconds; }
    void SetDefaultOptions(const OllamaOptions& opts) { m_default_options = opts; }

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;

    std::string m_base_url;
    int m_timeout_seconds = 120;
    OllamaOptions m_default_options;

    std::atomic<uint64_t> m_next_request_id{1};
    std::mutex m_active_turns_mutex;
    std::unordered_map<uint64_t, TurnHandle> m_active_turns;
};

} // namespace RawrXD