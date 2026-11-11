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
        omsg.tool_calls = msg.tool_calls;
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
    auto parseArguments = [](const json& value) -> json {
        if (value.is_object() || value.is_array()) return value;
        if (value.is_string()) {
            try {
                return json::parse(value.get<std::string>());
            } catch (...) {
            }
        }
        return json::object();
    };

    auto addCall = [&](const std::string& name, const json& args) {
        if (name.empty()) return;
        result.tool_calls.emplace_back(name, parseArguments(args));
    };

    try {
        json j = json::parse(response);
        if (j.is_object() && j.contains("tool_calls") && j["tool_calls"].is_array()) {
            for (const auto& tool : j["tool_calls"]) {
                const json function = tool.value("function", json::object());
                const std::string name = tool.value("name", function.value("name", ""));
                const json args = tool.contains("arguments")
                    ? tool["arguments"]
                    : function.value("arguments", json::object());
                addCall(name, args);
            }
        } else if (j.is_object() && j.contains("name") && j["name"].is_string()) {
            // Small local models frequently emit the tool envelope as plain
            // JSON content instead of using Ollama's native tool_calls field.
            const json args = j.contains("arguments") ? j["arguments"]
                : (j.contains("parameters") ? j["parameters"]
                    : (j.contains("args") ? j["args"] : json::object()));
            addCall(j["name"].get<std::string>(), args);
        } else if (j.is_object() && j.contains("tool") && j["tool"].is_string()) {
            const json args = j.contains("arguments") ? j["arguments"]
                : (j.contains("parameters") ? j["parameters"] : json::object());
            addCall(j["tool"].get<std::string>(), args);
        }
        if (!result.tool_calls.empty()) {
            result.has_tool_calls = true;
        }
    } catch (const json::exception&) {
        // Plain natural-language responses do not carry a structured tool
        // envelope; leave them as final assistant text.
    }
}

InferenceResult OllamaBackend::ChatSync(
    const std::vector<ChatMessage>& messages,
    const json& tools) {
    if (!m_client || !m_initialized.load()) {
        return InferenceResult::Error("Ollama backend not initialized");
    }

    m_cancelRequested.store(false);

    Backend::OllamaChatRequest req;
    req.model  = m_config.model;
    req.stream = false;
    ConvertMessages(messages, req.messages);

    // Build options
    req.options["temperature"] = std::to_string(m_config.temperature);
    req.options["top_p"] = std::to_string(m_config.top_p);
    req.options["num_ctx"] = std::to_string(m_config.num_ctx);
    if (m_config.max_tokens > 0) {
        req.options["num_predict"] = std::to_string(m_config.max_tokens);
    }
    if (!tools.is_null()) {
        req.tools = tools;
    }

    auto t0 = std::chrono::steady_clock::now();
    Backend::OllamaResponse resp;

    try {
        resp = m_client->chatSync(req);
    } catch (const std::exception& e) {
        RecordFailure("Ollama chatSync exception: " + std::string(e.what()));
        return InferenceResult::Error(e.what());
    }

    auto t1 = std::chrono::steady_clock::now();
    double elapsed_ms = std::chrono::duration<double, std::milli>(t1 - t0).count();

    m_totalRequests.fetch_add(1);

    // /api/chat returns content in message.content, while /api/generate uses
    // response. Validate the unified text after selecting the correct field.
    std::string text = !resp.message.empty() ? resp.message : resp.response;
    const bool has_tool_calls = !resp.tool_calls.is_null() &&
                                resp.tool_calls.is_array() &&
                                !resp.tool_calls.empty();
    if (!resp.done || (text.empty() && !has_tool_calls)) {
        std::string err = resp.done_reason == "error"
            ? (!resp.response.empty() ? resp.response : resp.message)
            : "Ollama returned no chat content";
        RecordFailure("Ollama chatSync failed: " + err);
        return InferenceResult::Error(err);
    }

    // Extract response text (chat mode uses .message, generate mode uses .response)
    InferenceResult result = InferenceResult::Ok(text);
    result.tool_calls.clear();

    // Parse tool calls if present
    if (!resp.tool_calls.is_null()) {
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
            result.tool_calls.emplace_back(name, args);
        }
    }
    if (result.tool_calls.empty()) {
        ParseToolCallsFromResponse(text, result);
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
    m_streaming.store(true);

    Backend::OllamaChatRequest req;
    req.model  = m_config.model;
    req.stream = true;
    ConvertMessages(messages, req.messages);

    req.options["temperature"] = std::to_string(m_config.temperature);
    req.options["top_p"] = std::to_string(m_config.top_p);
    req.options["num_ctx"] = std::to_string(m_config.num_ctx);
    if (m_config.max_tokens > 0) {
        req.options["num_predict"] = std::to_string(m_config.max_tokens);
    }
    if (!tools.is_null()) {
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
        if (!chunk.message.empty()) {
            full_response += chunk.message;
            if (on_token) on_token(chunk.message);
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

            if (chunk.done_reason == "error" || chunk.response.empty()) {
                stream_failed = true;
                fail_reason = !chunk.response.empty() ? chunk.response : "Streaming failed";
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

    // Build FIM prompt: <|fim_prefix|>{prefix}<|fim_suffix|>{suffix}<|fim_middle|>
    std::string fim_prompt = "<|fim_prefix|>" + prefix + "<|fim_suffix|>" + suffix + "<|fim_middle|>";

    Backend::OllamaGenerateRequest req;
    req.model  = m_config.model;
    req.prompt = fim_prompt;
    req.stream = false;
    req.options["temperature"] = std::to_string(m_config.temperature);
    req.options["num_ctx"] = std::to_string(m_config.num_ctx);
    req.options["num_predict"] = std::to_string(m_config.fim_max_tokens > 0 ? m_config.fim_max_tokens : 256);

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
    m_streaming.store(true);

    std::string fim_prompt = "<|fim_prefix|>" + prefix + "<|fim_suffix|>" + suffix + "<|fim_middle|>";

    Backend::OllamaGenerateRequest req;
    req.model  = m_config.model;
    req.prompt = fim_prompt;
    req.stream = true;
    req.options["temperature"] = std::to_string(m_config.temperature);
    req.options["num_ctx"] = std::to_string(m_config.num_ctx);
    req.options["num_predict"] = std::to_string(m_config.fim_max_tokens > 0 ? m_config.fim_max_tokens : 256);

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

            if (chunk.done_reason == "error" || full_response.empty()) {
                stream_failed = true;
                fail_reason = "FIM streaming failed";
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
    // Note: Ollama HTTP doesn't support per-request cancellation.
    // The cancel flag prevents new tokens from being delivered to callbacks.
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
