// =============================================================================
// ollama_client.h — WinHTTP-based Ollama API Client (Header)
// =============================================================================
// Companion header for ollama_client.cpp. Provides type definitions for the
// Ollama HTTP client used by OllamaBackend and the shared backend layer.
// No external HTTP dependencies — uses WinHTTP on Windows.
// =============================================================================
#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <functional>
#include <map>
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
};

// ---------------------------------------------------------------------------
// Ollama generate request
// ---------------------------------------------------------------------------
struct OllamaGenerateRequest {
    std::string  model;
    std::string  prompt;
    bool         stream = false;
    std::map<std::string, std::string> options;  // e.g. {"temperature", "0.2"}, {"num_ctx", "4096"}
    std::vector<std::string> stop;
};

// ---------------------------------------------------------------------------
// Ollama chat request
// ---------------------------------------------------------------------------
struct OllamaChatMessage {
    std::string role;
    std::string content;
    std::string tool_call_id;
    json tool_calls;
};

struct OllamaChatRequest {
    std::string                 model;
    std::vector<OllamaChatMessage> messages;
    bool                        stream = false;
    json                        tools;     // OpenAI-format tool definitions
    std::map<std::string, std::string> options;
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
    static OllamaResponse Error(const std::string& msg);};

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

    // ---- Connection ----
    bool testConnection();
    std::string getVersion();
    bool isRunning();

    // ---- Model discovery ----
    std::vector<OllamaModel> listModels();

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

private:
    std::string m_base_url;
    int         m_timeout_seconds;

    // JSON builders
    std::string createGenerateRequestJson(const OllamaGenerateRequest& req);
    std::string createChatRequestJson(const OllamaChatRequest& req);

    // Response parsing
    OllamaResponse parseResponse(const std::string& json_str);
    std::vector<OllamaModel> parseModels(const std::string& json_str);

    // HTTP helpers (platform-specific)
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
