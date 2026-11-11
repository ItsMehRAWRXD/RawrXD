// =============================================================================
// OllamaBackend.cpp — Ollama HTTP Backend Adapter Implementation
// =============================================================================
#include "OllamaBackend.h"
#include <chrono>
#include <sstream>
#include <algorithm>

namespace RawrXD {
namespace Agent {

OllamaBackend::OllamaBackend() = default;
OllamaBackend::~OllamaBackend() { Shutdown(); }

BackendConfig OllamaBackend::DefaultConfig() const {
    BackendConfig cfg;
    cfg.kind          = BackendKind::Ollama;
    cfg.endpoint      = "http://127.0.0.1:11434";
    cfg.model         = "qwen2.5-coder:32b";
    cfg.temperature   = 0.2f;
    cfg.top_p         = 0.9f;
    cfg.max_tokens    = 4096;
    cfg.num_ctx       = 8192;
    cfg.timeout_ms    = 120000;
    cfg.use_gpu       = true;
    cfg.num_gpu       = 99;
    return cfg;
}

bool OllamaBackend::Initialize(const BackendConfig& config) {
    if (m_initialized.load()) return true;

    m_config = config;
    if (m_config.endpoint.empty()) {
        m_config.endpoint = "http://127.0.0.1:11434";
    }
    if (m_config.model.empty()) {
        m_config.model = "qwen2.5-coder:32b";
    }

    m_client = std::make_unique<Backend::OllamaClient>(m_config.endpoint);
    m_client->setTimeoutSeconds(m_config.timeout_ms / 1000);

    // Test connection
    if (!m_client->testConnection()) {
        m_config = DefaultConfig();
        m_client = std::make_unique<Backend::OllamaClient>(m_config.endpoint);
        m_client->setTimeoutSeconds(m_config.timeout_ms / 1000);
        if (!m_client->testConnection()) {
            RecordFailure("Ollama backend: cannot connect to " + m_config.endpoint);
            return false;
        }
    }

    m_initialized.store(true);
    return true;
}

void OllamaBackend::Shutdown() {
    m_cancelRequested.store(true);
    m_streaming.store(false);
    m_initialized.store(false);
    m_client.reset();
}

bool OllamaBackend::IsInitialized() const {
    return m_initialized.load();
}

BackendConfig OllamaBackend::GetConfig() const {
    return m_config;
}

void OllamaBackend::SetConfig(const BackendConfig& config) {
    m_config = config;
    // A different model may well support native tool calling.
    m_nativeToolsUnsupported.store(false);
    if (m_client) {
        m_client->setBaseUrl(m_config.endpoint);
        m_client->setTimeoutSeconds(m_config.timeout_ms / 1000);
    }
}

BackendHealth OllamaBackend::GetHealth() const {
    BackendHealth health;
    health.endpoint  = m_config.endpoint;
    health.model_name = m_config.model;
    health.last_check = std::chrono::steady_clock::now();

    if (!m_initialized.load()) {
        health.available = false;
        health.healthy   = false;
        health.last_error = "Backend not initialized";
        return health;
    }

    if (m_client) {
        health.available = m_client->isRunning();
        health.healthy   = m_consecutiveErrors < 3;
        if (!m_recentErrors.empty()) {
            health.last_error = m_recentErrors.back();
        }
    }

    return health;
}

bool OllamaBackend::CheckHealth() {
    if (!m_client) return false;
    bool ok = m_client->testConnection();
    if (!ok) {
        RecordFailure("Ollama backend health check failed: " + m_config.endpoint);
    }
    return ok;
}

bool OllamaBackend::Supports(BackendCapability cap) const {
    switch (cap) {
        case BackendCapability::Chat:
        case BackendCapability::ToolCalling:
        case BackendCapability::Streaming:
        case BackendCapability::FIM:
        case BackendCapability::Cancellation:
        case BackendCapability::ModelDiscovery:
        case BackendCapability::Embeddings:
            return true;
        case BackendCapability::StructuredOutput:
            // Ollama supports JSON format via options
            return true;
        default:
            return false;
    }
}

std::vector<std::string> OllamaBackend::ListModels() {
    if (!m_client) return {};
    auto models = m_client->listModels();
    std::vector<std::string> names;
    names.reserve(models.size());
    for (const auto& m : models) {
        names.push_back(m.name);
    }
    return names;
}

std::vector<Backend::OllamaModel> OllamaBackend::ListModelsDetailed() {
    if (!m_client) return {};
    return m_client->listModels();
}

bool OllamaBackend::ShowModel(const std::string& model_name,
                              Backend::OllamaShowResult& out) {
    if (!m_client) {
        out.ok = false;
        out.error = "Ollama backend not initialized";
        return false;
    }
    return m_client->showModel(model_name, out);
}

std::vector<Backend::OllamaRunningModel> OllamaBackend::ListRunning() {
    if (!m_client) return {};
    return m_client->listRunning();
}

bool OllamaBackend::IsCloudModel(const std::string& model_name) {
    if (!m_client) return false;
    for (const auto& m : m_client->listModels()) {
        if (m.name == model_name) return m.IsCloud();
    }
    // An exact match is the only reliable signal; a prefix match could be a
    // local model that merely starts with the same characters.
    return false;
}

bool OllamaBackend::LoadModel(const std::string& model_name) {
    if (!m_client) return false;
    // Ollama auto-loads models on first request; just verify it exists
    auto models = m_client->listModels();
    for (const auto& m : models) {
        if (m.name == model_name || m.name.find(model_name) != std::string::npos) {
            m_config.model = m.name;
            return true;
        }
    }
    // Model may not be loaded yet; Ollama will pull it on first generate
    m_config.model = model_name;
    return true;
}

void OllamaBackend::ConvertMessages(
    const std::vector<ChatMessage>& messages,
    std::vector<Backend::OllamaChatMessage>& out) const {
    out.clear();
    out.reserve(messages.size());
    for (const auto& msg : messages) {
        Backend::OllamaChatMessage omsg;
        omsg.role    = msg.role;
        omsg.content = msg.content;
        omsg.tool_call_id = msg.tool_call_id;
        // Only forward tool calls the provider can represent; an empty
        // array would make Ollama reject the request.
        if (msg.tool_calls.is_array() && !msg.tool_calls.empty()) {
            omsg.tool_calls = msg.tool_calls;
        }
        out.push_back(omsg);
    }
}

std::string OllamaBackend::ConvertToolsToJson(const json& tools) const {
    // tools is already OpenAI-format; pass through as JSON
    if (tools.is_array()) {
        return tools.dump();
    }
    return "[]";
}

void OllamaBackend::ParseToolCallsFromResponse(
    const std::string& response,
    InferenceResult& result) const {
    try {
        json j = json::parse(response);
        if (j.contains("tools")) {
            result.has_tool_calls = true;
            for (const auto& tool : j["tools"]) {
                std::string name = tool.value("name", "");
                json args = tool.value("arguments", json::object());
                result.tool_calls.emplace_back(name, args);
            }
        }
    } catch (const json::exception&) {
        // No tool calls in response text
    }
}

InferenceResult OllamaBackend::ChatSync(
    const std::vector<ChatMessage>& messages,
    const json& tools) {
    if (!m_client || !m_initialized.load()) {
        return InferenceResult::Error("Ollama backend not initialized");
    }

    m_cancelRequested.store(false);
    if (m_client) m_client->clearCancel();

    Backend::OllamaChatRequest req;
    req.model  = m_config.model;
    req.stream = false;
    ConvertMessages(messages, req.messages);

    // Build options
    req.options["temperature"] = m_config.temperature;
    req.options["top_p"] = m_config.top_p;
    req.options["num_ctx"] = m_config.num_ctx;
    if (m_config.max_tokens > 0) {
        req.options["num_predict"] = m_config.max_tokens;
    }
    if (!tools.is_null()) {
        req.tools = tools;
    }

    auto t0 = std::chrono::steady_clock::now();
    Backend::OllamaResponse resp;

    try {
        resp = m_client->chatSync(req);
        // Not every served model implements native tool calling, and Ollama
        // answers such a request with HTTP 400 ("does not support tools").
        // The agent contract in the prompt is the fallback: retry once with
        // the tool schemas removed and remember the limitation, so the agent
        // engine keeps working with models that only speak the JSON contract.
        if (resp.error.find("does not support tools") != std::string::npos) {
            m_nativeToolsUnsupported.store(true);
            req.tools = json();
            resp = m_client->chatSync(req);
        }
    } catch (const std::exception& e) {
        RecordFailure("Ollama chatSync exception: " + std::string(e.what()));
        return InferenceResult::Error(e.what());
    }

    auto t1 = std::chrono::steady_clock::now();
    double elapsed_ms = std::chrono::duration<double, std::milli>(t1 - t0).count();

    m_totalRequests.fetch_add(1);

    // Chat replies carry the text in `message.content`; `response` is only
    // populated by /api/generate. Checking `response` alone would reject
    // every successful chat completion.
    std::string text = !resp.message.empty() ? resp.message : resp.response;
    if (!resp.error.empty()) {
        RecordFailure("Ollama chatSync failed: " + resp.error);
        return InferenceResult::Error(resp.error);
    }
    // A tool call is a complete reply even when the content is empty: a
    // model asked to call a function answers with tool_calls and no text.
    const bool hasToolCalls = resp.tool_calls.is_array() && !resp.tool_calls.empty();
    if (!resp.done || (text.empty() && !hasToolCalls)) {
        const std::string err = resp.done_reason == "error"
            ? (resp.error.empty() ? "Ollama reported an error" : resp.error)
            : "Ollama returned an empty completion";
        RecordFailure("Ollama chatSync failed: " + err);
        return InferenceResult::Error(err);
    }

    InferenceResult result = InferenceResult::Ok(text);
    result.tool_calls.clear();

    // Parse tool calls if present. Ollama returns them in OpenAI shape:
    // {"id": "...", "function": {"name": "...", "arguments": {...}}}
    if (resp.tool_calls.is_array() && !resp.tool_calls.empty()) {
        result.has_tool_calls = true;
        for (const auto& tc : resp.tool_calls) {
            std::string name = tc.value("name", tc.value("function", json::object()).value("name", ""));
            json args = tc.value("arguments", tc.value("function", json::object()).value("arguments", json::object()));
            if (args.is_string()) {
                // Ollama sometimes returns args as a JSON string
                try {
                    args = json::parse(args.get<std::string>());
                } catch (...) {}
            }
            if (!args.is_object()) args = json::object();
            result.tool_calls.emplace_back(name, args);
        }
    }

    uint64_t ptok = resp.prompt_eval_count;
    uint64_t ctok = resp.eval_count;
    double tps = (elapsed_ms > 0 && ctok > 0)
        ? (ctok / (elapsed_ms / 1000.0)) : 0.0;

    RecordSuccess(tps, ptok, ctok);

    result.prompt_tokens = ptok;
    result.completion_tokens = ctok;
    result.tokens_per_sec = tps;
    result.total_duration_ms = elapsed_ms;

    return result;
}

bool OllamaBackend::ChatStream(
    const std::vector<ChatMessage>& messages,
    const json& tools,
    TokenCallback     on_token,
    ToolCallCallback  on_tool_call,
    DoneCallback      on_done,
    ErrorCallback     on_error) {
    if (!m_client || !m_initialized.load()) {
        if (on_error) on_error("Ollama backend not initialized");
        return false;
    }

    m_cancelRequested.store(false);
    if (m_client) m_client->clearCancel();
    m_streaming.store(true);

    Backend::OllamaChatRequest req;
    req.model  = m_config.model;
    req.stream = true;
    ConvertMessages(messages, req.messages);

    req.options["temperature"] = m_config.temperature;
    req.options["top_p"] = m_config.top_p;
    req.options["num_ctx"] = m_config.num_ctx;
    if (m_config.max_tokens > 0) {
        req.options["num_predict"] = m_config.max_tokens;
    }
    if (!tools.is_null() && !m_nativeToolsUnsupported.load()) {
        req.tools = tools;
    }

    auto t0 = std::chrono::steady_clock::now();
    std::string full_response;
    uint64_t ptok = 0, ctok = 0;
    bool stream_failed = false;
    std::string fail_reason;

    auto on_chunk = [&](const Backend::OllamaResponse& chunk) {
        if (m_cancelRequested.load()) {
            return;
        }

        // Streamed chat responses come as SSE-like JSON lines
        // Reasoning is a separate channel from the answer.
        if (!chunk.thinking.empty() && m_thinking_sink) {
            m_thinking_sink(chunk.thinking);
        }
        if (!chunk.message.empty()) {
            full_response += chunk.message;
        }
        if (!chunk.response.empty()) {
            full_response += chunk.response;
            if (on_token) on_token(chunk.response);
        }

        ptok = chunk.prompt_eval_count;
        ctok = chunk.eval_count;

        // Check for tool calls in streaming mode
        if (!chunk.tool_calls.is_null() && on_tool_call) {
            for (const auto& tc : chunk.tool_calls) {
                std::string name = tc.value("name",
                    tc.value("function", json::object()).value("name", ""));
                json args = tc.value("arguments",
                    tc.value("function", json::object()).value("arguments", json::object()));
                if (args.is_string()) {
                    try { args = json::parse(args.get<std::string>()); } catch (...) {}
                }
                on_tool_call(name, args);
            }
        }

        if (chunk.done) {
            auto t1 = std::chrono::steady_clock::now();
            double elapsed_ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
            double tps = (elapsed_ms > 0 && ctok > 0)
                ? (ctok / (elapsed_ms / 1000.0)) : 0.0;

            m_totalRequests.fetch_add(1);

            if (!chunk.error.empty() || chunk.done_reason == "error") {
                stream_failed = true;
                fail_reason = chunk.error.empty()
                    ? (chunk.response.empty() ? "Ollama streaming failed" : chunk.response)
                    : chunk.error;
                RecordFailure("Ollama ChatStream failed: " + fail_reason);
                if (on_error) on_error(fail_reason);
            } else {
                RecordSuccess(tps, ptok, ctok);
                if (on_done) on_done(full_response, ptok, ctok, tps);
            }
        }
    };

    auto on_err = [&](const std::string& err) {
        stream_failed = true;
        fail_reason = err;
        RecordFailure("Ollama ChatStream error: " + err);
        if (on_error) on_error(err);
    };

    auto on_complete = [&](const Backend::OllamaResponse& resp) {
        // Already handled in on_chunk when done=true. No-op.
    };

    bool ok = m_client->chat(req, on_chunk, on_err, on_complete);
    m_streaming.store(false);

    return ok && !stream_failed;
}

InferenceResult OllamaBackend::FIMSync(
    const std::string& prefix,
    const std::string& suffix,
    const std::string& filename) {
    if (!m_client || !m_initialized.load()) {
        return InferenceResult::Error("Ollama backend not initialized");
    }

    m_cancelRequested.store(false);
    if (m_client) m_client->clearCancel();

    // Build FIM prompt: <|fim_prefix|>{prefix}<|fim_suffix|>{suffix}<|fim_middle|>
    std::string fim_prompt = "<|fim_prefix|>" + prefix + "<|fim_suffix|>" + suffix + "<|fim_middle|>";

    Backend::OllamaGenerateRequest req;
    req.model  = m_config.model;
    req.prompt = fim_prompt;
    req.stream = false;
    req.options["temperature"] = m_config.temperature;
    req.options["num_ctx"] = m_config.num_ctx;
    req.options["num_predict"] = (m_config.fim_max_tokens > 0 ? m_config.fim_max_tokens : 256);

    auto t0 = std::chrono::steady_clock::now();
    Backend::OllamaResponse resp;

    try {
        resp = m_client->generateSync(req);
    } catch (const std::exception& e) {
        RecordFailure("Ollama FIMSync exception: " + std::string(e.what()));
        return InferenceResult::Error(e.what());
    }

    auto t1 = std::chrono::steady_clock::now();
    double elapsed_ms = std::chrono::duration<double, std::milli>(t1 - t0).count();

    m_totalRequests.fetch_add(1);

    if (!resp.done || resp.response.empty()) {
        RecordFailure("Ollama FIMSync failed");
        return InferenceResult::Error("FIM generation failed");
    }

    uint64_t ptok = resp.prompt_eval_count;
    uint64_t ctok = resp.eval_count;
    double tps = (elapsed_ms > 0 && ctok > 0)
        ? (ctok / (elapsed_ms / 1000.0)) : 0.0;

    RecordSuccess(tps, ptok, ctok);

    // Strip FIM control tokens from response
    std::string cleaned = resp.response;
    size_t pos;
    while ((pos = cleaned.find("<|fim_middle|>")) != std::string::npos) {
        cleaned.erase(pos, 17);
    }
    while ((pos = cleaned.find("<|fim_begin|>")) != std::string::npos) {
        cleaned.erase(pos, 15);
    }
    while ((pos = cleaned.find("<|fim_end|>")) != std::string::npos) {
        cleaned.erase(pos, 12);
    }

    return InferenceResult::Ok(cleaned, ptok, ctok, tps, elapsed_ms);
}

bool OllamaBackend::FIMStream(
    const std::string& prefix,
    const std::string& suffix,
    const std::string& filename,
    TokenCallback  on_token,
    DoneCallback   on_done,
    ErrorCallback  on_error) {
    if (!m_client || !m_initialized.load()) {
        if (on_error) on_error("Ollama backend not initialized");
        return false;
    }

    m_cancelRequested.store(false);
    if (m_client) m_client->clearCancel();
    m_streaming.store(true);

    std::string fim_prompt = "<|fim_prefix|>" + prefix + "<|fim_suffix|>" + suffix + "<|fim_middle|>";

    Backend::OllamaGenerateRequest req;
    req.model  = m_config.model;
    req.prompt = fim_prompt;
    req.stream = true;
    req.options["temperature"] = m_config.temperature;
    req.options["num_ctx"] = m_config.num_ctx;
    req.options["num_predict"] = (m_config.fim_max_tokens > 0 ? m_config.fim_max_tokens : 256);

    auto t0 = std::chrono::steady_clock::now();
    std::string full_response;
    uint64_t ptok = 0, ctok = 0;
    bool stream_failed = false;
    std::string fail_reason;

    auto on_chunk = [&](const Backend::OllamaResponse& chunk) {
        if (m_cancelRequested.load()) return;

        if (!chunk.response.empty()) {
            full_response += chunk.response;
            if (on_token) on_token(chunk.response);
        }

        ptok = chunk.prompt_eval_count;
        ctok = chunk.eval_count;

        if (chunk.done) {
            auto t1 = std::chrono::steady_clock::now();
            double elapsed_ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
            double tps = (elapsed_ms > 0 && ctok > 0)
                ? (ctok / (elapsed_ms / 1000.0)) : 0.0;

            m_totalRequests.fetch_add(1);

            if (!chunk.error.empty() || chunk.done_reason == "error" || full_response.empty()) {
                stream_failed = true;
                fail_reason = chunk.error.empty() ? "FIM streaming failed" : chunk.error;
                RecordFailure("Ollama FIMStream failed");
                if (on_error) on_error(fail_reason);
            } else {
                RecordSuccess(tps, ptok, ctok);
                // Strip FIM control tokens
                size_t pos;
                while ((pos = full_response.find("<|fim_middle|>")) != std::string::npos) {
                    full_response.erase(pos, 17);
                }
                while ((pos = full_response.find("<|fim_begin|>")) != std::string::npos) {
                    full_response.erase(pos, 15);
                }
                while ((pos = full_response.find("<|fim_end|>")) != std::string::npos) {
                    full_response.erase(pos, 12);
                }
                if (on_done) on_done(full_response, ptok, ctok, tps);
            }
        }
    };

    auto on_err = [&](const std::string& err) {
        stream_failed = true;
        fail_reason = err;
        RecordFailure("Ollama FIMStream error: " + err);
        if (on_error) on_error(err);
    };

    auto on_complete = [&](const Backend::OllamaResponse&) { /* handled in on_chunk */ };

    bool ok = m_client->generate(req, on_chunk, on_err, on_complete);
    m_streaming.store(false);

    return ok && !stream_failed;
}

void OllamaBackend::Cancel() {
    m_cancelRequested.store(true);
    // Abort the in-flight HTTP read so the streaming loop stops consuming the
    // socket instead of running to completion in the background.
    if (m_client) m_client->cancel();
    m_streaming.store(false);
}

bool OllamaBackend::IsStreaming() const {
    return m_streaming.load();
}

uint64_t OllamaBackend::GetTotalRequests() const {
    return m_totalRequests.load();
}

double OllamaBackend::GetAvgTokensPerSec() const {
    return m_accumulatedTps.load() / std::max<uint64_t>(m_totalRequests.load(), 1);
}

bool OllamaBackend::ShouldEmitError(const std::string& msg) {
    std::lock_guard<std::mutex> lock(m_stats_mtx);
    m_recentErrors.push_back(msg);
    if (m_recentErrors.size() > 10) {
        m_recentErrors.pop_front();
    }
    m_consecutiveErrors++;
    return true;
}

void OllamaBackend::RecordSuccess(double tps, uint64_t ptok, uint64_t ctok) {
    m_consecutiveErrors = 0;
    m_totalTokens.fetch_add(ptok + ctok);
    double current_avg = m_accumulatedTps.load();
    uint64_t total_req = m_totalRequests.load();
    m_accumulatedTps.store(((current_avg * total_req) + tps) / (total_req + 1));
}

void OllamaBackend::RecordFailure(const std::string& error) {
    ShouldEmitError(error);
}

} // namespace Agent
} // namespace RawrXD
