// =============================================================================
// InferenceBackend.h — Unified Inference Backend Abstraction
// =============================================================================
// Shared interface contract for all inference backends (Deep2 native, Ollama HTTP).
// Enables the agent/orchestrator/IDE to operate against a single abstraction
// regardless of whether the model is served via:
//   - Deep2 native GPU/CPU compute (127.0.0.1:11436 internal bridge)
//   - Ollama local HTTP API (127.0.0.1:11434)
//   - Future cloud backends (explicit opt-in only, never silent)
//
// Design goals:
//   1. No paid API / cloud fallback without explicit user opt-in
//   2. Full feature parity: chat, tool-calling, streaming, cancellation
//   3. No silent splicing of output from two different models during failover
//   4. Shared session format (conversation history survives backend switches)
//   5. No exceptions — all errors via InferenceResult pattern
// =============================================================================
#pragma once

#include <string>
#include <vector>
#include <functional>
#include <cstdint>
#include <chrono>
#include <optional>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace RawrXD {
namespace Agent {

// ---------------------------------------------------------------------------
// Backend identifier
// ---------------------------------------------------------------------------
enum class BackendKind : uint8_t {
    Unknown = 0,
    Deep2   = 1,   // Deep2 native GGUF compute (GPU/CPU)
    Ollama  = 2,   // Ollama HTTP API
};

inline const char* BackendName(BackendKind k) {
    switch (k) {
        case BackendKind::Deep2:  return "deep2";
        case BackendKind::Ollama: return "ollama";
        default:                  return "unknown";
    }
}

// ---------------------------------------------------------------------------
// Backend health status
// ---------------------------------------------------------------------------
struct BackendHealth {
    bool        available      = false;
    bool        healthy        = true;
    int         error_count    = 0;
    double      avg_latency_ms = 0.0;
    std::string model_name;
    std::string endpoint;
    std::string last_error;
    std::chrono::steady_clock::time_point last_check{};
};

// ---------------------------------------------------------------------------
// Backend capability flags
// ---------------------------------------------------------------------------
enum class BackendCapability : uint8_t {
    Chat,            // Chat/completion via /api/chat or /api/generate
    ToolCalling,     // Structured tool-call output parsing
    Streaming,       // Token-by-token streaming
    FIM,             // Fill-in-middle prompt format (ghost text)
    Embeddings,      // Embedding vectors
    Cancellation,    // In-flight request cancellation
    ModelDiscovery,  // List available models
    StructuredOutput, // JSON schema-constrained generation
};

// ---------------------------------------------------------------------------
// Chat message (shared session format across all backends)
// ---------------------------------------------------------------------------
struct ChatMessage {
    std::string role;       // "system", "user", "assistant", "tool"
    std::string content;
    std::string tool_call_id;
    json        tool_calls; // Assistant: array of {id, type:"function", function:{name,arguments}}
};

// ---------------------------------------------------------------------------
// Streaming callbacks
// ---------------------------------------------------------------------------
using TokenCallback    = std::function<void(const std::string& token)>;
using ToolCallCallback = std::function<void(const std::string& tool_name, const json& args)>;
using DoneCallback     = std::function<void(const std::string& full_response,
                                             uint64_t prompt_tokens,
                                             uint64_t completion_tokens,
                                             double tokens_per_sec)>;
using ErrorCallback    = std::function<void(const std::string& error)>;

// ---------------------------------------------------------------------------
// Inference result (no exceptions)
// ---------------------------------------------------------------------------
struct InferenceResult {
    bool        success = false;
    std::string response;           // Full response text
    std::string error_message;

    // Tool call fields
    bool                                         has_tool_calls = false;
    std::vector<std::pair<std::string, json>>    tool_calls;     // [(name, args)]
    // The ids the server gave the calls, in the same order. A tool result
    // has to name the call it answers, and the assistant turn has to be
    // echoed with its calls: a model that cannot see its own call cannot
    // tell which result belongs to it.
    std::vector<std::string>                     tool_call_ids;

    // Perf metrics
    uint64_t prompt_tokens    = 0;
    uint64_t completion_tokens = 0;
    double   tokens_per_sec   = 0.0;
    double   total_duration_ms = 0.0;

    // The server's own generation accounting.
    //
    // tokens_per_sec above is wall clock, and it includes the model load and
    // the prompt evaluation. The inference throughput is the server's own
    // number: eval_count * 1e9 / eval_duration, where eval_duration is the
    // time the server spent generating and nothing else.
    uint64_t eval_duration_ns = 0;
    uint64_t load_duration_ns = 0;
    double   inference_tps     = 0.0;   // eval_count * 1e9 / eval_duration
    double   ttft_ms           = 0.0;   // time to the first streamed token

    static InferenceResult Ok(const std::string& resp,
                              uint64_t ptok = 0, uint64_t ctok = 0,
                              double tps = 0.0, double ms = 0.0) {
        InferenceResult r;
        r.success = true;
        r.response = resp;
        r.prompt_tokens = ptok;
        r.completion_tokens = ctok;
        r.tokens_per_sec = tps;
        r.total_duration_ms = ms;
        return r;
    }

    static InferenceResult Error(const std::string& msg) {
        InferenceResult r;
        r.success = false;
        r.error_message = msg;
        return r;
    }
};

// ---------------------------------------------------------------------------
// Backend configuration
// ---------------------------------------------------------------------------
struct BackendConfig {
    BackendKind kind            = BackendKind::Deep2;
    std::string endpoint;         // e.g. "http://127.0.0.1:11434" or "native"
    std::string model;            // Model name/tag
    float       temperature       = 0.2f;
    float       top_p             = 0.9f;
    int         max_tokens       = 4096;
    int         fim_max_tokens   = 256;   // Short for ghost text / FIM
    int         num_ctx          = 8192;
    int         timeout_ms        = 120000;
    bool        use_gpu          = true;
    int         num_gpu          = 99;
    json        extra_options;    // Backend-specific options
};

// ---------------------------------------------------------------------------
// InferenceBackend — Abstract interface
// ---------------------------------------------------------------------------
class InferenceBackend {
public:
    virtual ~InferenceBackend() = default;

    // ---- Lifecycle ----
    virtual bool Initialize(const BackendConfig& config) = 0;
    virtual void Shutdown() = 0;
    virtual bool IsInitialized() const = 0;

    // ---- Configuration ----
    virtual BackendKind GetKind() const = 0;
    virtual BackendConfig GetConfig() const = 0;
    virtual void SetConfig(const BackendConfig& config) = 0;

    // ---- Health ----
    virtual BackendHealth GetHealth() const = 0;
    virtual bool CheckHealth() = 0;

    // ---- Capabilities ----
    virtual bool Supports(BackendCapability cap) const = 0;

    // ---- Model discovery ----
    virtual std::vector<std::string> ListModels() = 0;
    virtual bool LoadModel(const std::string& model_name) = 0;

    // ---- Chat (agentic, with tool calling) ----
    virtual InferenceResult ChatSync(const std::vector<ChatMessage>& messages,
                                     const json& tools = json::array()) = 0;

    virtual bool ChatStream(const std::vector<ChatMessage>& messages,
                            const json& tools,
                            TokenCallback     on_token,
                            ToolCallCallback  on_tool_call,
                            DoneCallback      on_done,
                            ErrorCallback     on_error) = 0;

    // ---- FIM (ghost text completions) ----
    virtual InferenceResult FIMSync(const std::string& prefix,
                                    const std::string& suffix,
                                    const std::string& filename = "") = 0;

    virtual bool FIMStream(const std::string& prefix,
                           const std::string& suffix,
                           const std::string& filename,
                           TokenCallback  on_token,
                           DoneCallback   on_done,
                           ErrorCallback  on_error) = 0;

    // ---- Cancellation ----
    virtual void Cancel() = 0;
    virtual bool IsStreaming() const = 0;

    // ---- Stats ----
    virtual uint64_t GetTotalRequests() const = 0;
    virtual double   GetAvgTokensPerSec() const = 0;

    // ---- The accounting of the last generation ----
    //
    // The completion callbacks carry a rate, but not the server's own
    // generation accounting. A backend that talks to a server that reports
    // its own counters fills this in, so that the caller can report the
    // inference throughput separately from the wall-clock throughput.
    struct StreamMetrics {
        uint64_t prompt_tokens     = 0;
        uint64_t completion_tokens = 0;
        uint64_t eval_duration_ns  = 0;   // the time spent generating
        uint64_t load_duration_ns  = 0;   // the time spent loading the model
        double   ttft_ms           = 0.0;
        double   inference_tps     = 0.0; // eval_count * 1e9 / eval_duration
    };
    virtual StreamMetrics LastStreamMetrics() const { return StreamMetrics{}; }
};

// ---------------------------------------------------------------------------
// Backend factory
// ---------------------------------------------------------------------------
class InferenceBackendFactory {
public:
    static std::unique_ptr<InferenceBackend> Create(BackendKind kind);
    static std::unique_ptr<InferenceBackend> CreateFromConfig(const BackendConfig& config);
    static std::vector<BackendKind> AvailableBackends();
};

} // namespace Agent
} // namespace RawrXD
