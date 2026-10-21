// =============================================================================
// ollama_client.h — WinHTTP-based Ollama API Client (Header)
// =============================================================================
// Speaks Ollama's DOCUMENTED local HTTP API:
//
//   GET  /api/version   server version
//   GET  /api/tags      installed models (name, digest, size, family, params)
//   POST /api/show      model metadata (template, parameters, capabilities)
//   GET  /api/ps        models currently resident (incl. VRAM)
//   POST /api/chat      chat completion (streaming NDJSON)
//   POST /api/generate  raw completion (streaming NDJSON)
//   POST /api/embeddings
//
// No external HTTP dependency: WinHTTP on Windows. No authentication is used
// because the local server does not require it.
//
// Contract notes that the previous revision violated:
//   * Request bodies are built with nlohmann/json, so a message containing a
//     quote, a backslash or a newline cannot corrupt the JSON payload.
//   * `options` values are JSON NUMBERS. Ollama rejects string-valued options
//     with HTTP 500 ("invalid option type").
//   * Streaming is real: the NDJSON stream is consumed incrementally and each
//     object is delivered as it arrives, instead of buffering a non-streaming
//     request and replaying it.
//   * The endpoint is taken from the configured base URL, not hard-coded.
//   * HTTP status codes are inspected; a non-2xx reply becomes an error with
//     the server's own message rather than an empty string.
// =============================================================================
#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <functional>
#include <map>
#include <atomic>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace RawrXD {
namespace Backend {

// ---------------------------------------------------------------------------
// Ollama model info
// ---------------------------------------------------------------------------
struct OllamaModel {
    std::string name;
    std::string modified_at;
    uint64_t    size = 0;
    std::string digest;
    std::string format;           // e.g. "gguf"
    std::string family;           // e.g. "llama"
    std::string parameter_size;   // e.g. "7B"
    std::string quantization_level;
    uint64_t    context_length = 0;

    // Cloud models are served by ollama.com, not by the local runtime. They
    // require a signed-in Ollama account with remaining quota, and they need
    // internet. A cloud model is NOT local inference and must never be
    // reported as such.
    std::string remote_host;      // e.g. "https://ollama.com" when cloud
    std::string remote_model;     // the model name on the remote host
    std::vector<std::string> capabilities;  // completion, tools, thinking, vision

    bool IsCloud() const { return !remote_host.empty(); }
};

// ---------------------------------------------------------------------------
// Ollama generate request
// ---------------------------------------------------------------------------
struct OllamaGenerateRequest {
    std::string  model;
    std::string  prompt;
    bool         stream = false;
    // Numeric option values (temperature, num_ctx, num_predict, ...).
    // These MUST serialize as JSON numbers; Ollama rejects string options.
    json         options = json::object();
    std::vector<std::string> stop;
};

// ---------------------------------------------------------------------------
// Ollama chat request
// ---------------------------------------------------------------------------
struct OllamaChatMessage {
    std::string role;             // "system" | "user" | "assistant" | "tool"
    std::string content;
    std::string tool_call_id;     // optional, for role="tool" turns
    json        tool_calls = json();  // optional, assistant-side tool calls
};

struct OllamaChatRequest {
    std::string                 model;
    std::vector<OllamaChatMessage> messages;
    bool                        stream = false;
    json                        tools;     // OpenAI-format tool definitions
    json                        options = json::object();
    std::vector<std::string>    stop;
};

// ---------------------------------------------------------------------------
// Ollama response (unified for generate + chat)
// ---------------------------------------------------------------------------
struct OllamaResponse {
    std::string  model;
    std::string  response;        // Completion text (generate mode)
    std::string  message;         // Chat message content (chat mode)
    bool         done = false;
    std::string  done_reason;
    std::string  error;           // Non-empty when the server reported a failure
    /// @brief Thinking text from a reasoning model. Ollama returns it
    /// separately from `message`; it is never part of the answer.
    std::string  thinking;

    // Tool calls (chat mode, parsed from message)
    json         tool_calls;

    // Performance metrics
    uint64_t     total_duration      = 0;
    uint64_t     load_duration       = 0;
    uint64_t     prompt_eval_count   = 0;
    uint64_t     prompt_eval_duration = 0;
    uint64_t     eval_count          = 0;
    uint64_t     eval_duration       = 0;

    static OllamaResponse Ok(const std::string& text, uint64_t ptok = 0, uint64_t ctok = 0);
    static OllamaResponse Error(const std::string& msg);
};

// ---------------------------------------------------------------------------
// POST /api/show — model metadata
// ---------------------------------------------------------------------------
struct OllamaShowResult {
    bool        ok = false;
    std::string error;
    std::string license;
    std::string modelfile;
    std::string parameters;
    std::string template_text;
    std::string system;
    json        details = json::object();
    json        model_info = json::object();
    json        capabilities = json::object();
    std::vector<std::string> modified_at;
};

// ---------------------------------------------------------------------------
// GET /api/ps — models currently resident in memory
// ---------------------------------------------------------------------------
struct OllamaRunningModel {
    std::string name;
    std::string model;
    uint64_t    size = 0;
    uint64_t    vram = 0;
    std::string digest;
    std::string family;
    std::string parameter_size;
    std::string quantization_level;
    double      expires_in_seconds = 0.0;
};

// ---------------------------------------------------------------------------
// Streaming and error callbacks
// ---------------------------------------------------------------------------
using StreamCallback     = std::function<void(const OllamaResponse&)>;
using ErrorCallback      = std::function<void(const std::string&)>;
using CompletionCallback = std::function<void(const OllamaResponse&)>;

// ---------------------------------------------------------------------------
// OllamaClient — WinHTTP-based HTTP client for the Ollama API
// ---------------------------------------------------------------------------
class OllamaClient {
public:
    explicit OllamaClient(const std::string& base_url = "http://127.0.0.1:11434");
    ~OllamaClient();

    void setBaseUrl(const std::string& url);
    const std::string& getBaseUrl() const { return m_base_url; }

    // ---- Connection ----
    bool testConnection();
    std::string getVersion();
    bool isRunning();

    // ---- Model discovery ----
    std::vector<OllamaModel> listModels();
    bool showModel(const std::string& model, OllamaShowResult& out);
    std::vector<OllamaRunningModel> listRunning();

    /// @brief Release a resident model (keep_alive = 0). Used between
    /// benchmark runs so each measurement starts from a clean state instead
    /// of sharing GPU memory with the previous model.
    bool unloadModel(const std::string& model);

    // ---- Generate (completion) ----
    OllamaResponse generateSync(const OllamaGenerateRequest& request);
    bool generate(const OllamaGenerateRequest& request,
                  StreamCallback on_chunk,
                  ErrorCallback on_error,
                  CompletionCallback on_complete);

    // ---- Chat (with tool calling) ----
    OllamaResponse chatSync(const OllamaChatRequest& request);
    bool chat(const OllamaChatRequest& request,
              StreamCallback on_chunk,
              ErrorCallback on_error,
              CompletionCallback on_complete);

    // ---- Embeddings ----
    std::vector<float> embeddings(const std::string& model, const std::string& prompt);

    // ---- Configuration ----
    void setTimeoutSeconds(int seconds) { m_timeout_seconds = seconds; }

    // ---- Cancellation ----
    // Aborts an in-flight streaming request. The streaming loop polls this
    // flag between reads, so a cancelled request stops consuming the socket.
    void cancel();
    bool wasCancelled() const { return m_cancelled.load(); }
    void clearCancel() { m_cancelled.store(false); }

    // ---- Diagnostics ----
    const std::string& lastError() const { return m_last_error; }

private:
    std::string m_base_url;
    int         m_timeout_seconds;
    std::atomic<bool> m_cancelled{false};
    mutable std::string m_last_error;

    // JSON builders
    std::string createGenerateRequestJson(const OllamaGenerateRequest& req) const;
    std::string createChatRequestJson(const OllamaChatRequest& req) const;

    // Response parsing
    OllamaResponse parseResponse(const std::string& json_str) const;
    std::vector<OllamaModel> parseModels(const std::string& json_str) const;

    // HTTP helpers (platform-specific)
    /// @brief Perform a single request/response exchange. Returns the body on
    /// success, or an empty string with lastError() set on failure.
    std::string httpRequest(const std::string& method, const std::string& endpoint,
                            const std::string* body);
    std::string makeGetRequest(const std::string& endpoint);
    std::string makePostRequest(const std::string& endpoint, const std::string& json_body);
    bool makeStreamingPostRequest(const std::string& endpoint,
                                  const std::string& json_body,
                                  StreamCallback on_chunk,
                                  ErrorCallback on_error,
                                  CompletionCallback on_complete);
};

} // namespace Backend
} // namespace RawrXD
