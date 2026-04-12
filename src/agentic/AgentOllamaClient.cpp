#include "AgentOllamaClient.h"
#include "BackendOrchestrator.h"
#include "hotpatch/Engine.hpp"

#include <chrono>
#include <cctype>
#include <future>
#include <iostream>
#include <thread>

using RawrXD::Agent::AgentOllamaClient;
using RawrXD::Agent::InferenceResult;
using RawrXD::Agent::OllamaHealth;

namespace {
constexpr int kMaxRetries = 3;
constexpr int kRetryBaseDelayMs = 100;

extern "C" unsigned int rawr_cpu_has_avx2();

std::string trimAsciiCopy(const std::string& value)
{
    size_t begin = 0;
    while (begin < value.size() && std::isspace(static_cast<unsigned char>(value[begin]))) {
        ++begin;
    }

    size_t end = value.size();
    while (end > begin && std::isspace(static_cast<unsigned char>(value[end - 1]))) {
        --end;
    }

    return value.substr(begin, end - begin);
}

std::string toLowerAsciiCopy(std::string value)
{
    for (char& ch : value) {
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    }
    return value;
}

bool startsWithBackendError(const std::string& text, std::string* outDetail = nullptr)
{
    const std::string trimmed = trimAsciiCopy(text);
    constexpr const char* kPrefix = "[BackendError]";
    const size_t prefixLen = std::strlen(kPrefix);
    if (trimmed.size() < prefixLen || trimmed.compare(0, prefixLen, kPrefix) != 0) {
        return false;
    }

    if (outDetail) {
        *outDetail = trimAsciiCopy(trimmed.substr(prefixLen));
    }
    return true;
}

std::string formatBackendError(const char* stage, const std::string& detail)
{
    const std::string trimmed = trimAsciiCopy(detail);
    if (trimmed.empty()) {
        return std::string("[BackendError] stage=") + stage + " detail=empty_error_payload";
    }

    const std::string lowered = toLowerAsciiCopy(trimmed);
    if (lowered == "na" || lowered == "n/a" || lowered == "nan" || lowered == "null" || lowered == "none" ||
        lowered == "-") {
        return std::string("[BackendError] stage=") + stage + " detail=non_actionable_error_payload(" + trimmed + ")";
    }

    return std::string("[BackendError] stage=") + stage + " detail=" + trimmed;
}

int parseContextMetadataInt(const nlohmann::json& metadata, const char* key)
{
    if (!metadata.contains(key)) {
        return 0;
    }
    if (metadata[key].is_number_integer()) {
        return metadata[key].get<int>();
    }
    if (metadata[key].is_number()) {
        return static_cast<int>(metadata[key].get<double>());
    }
    return 0;
}

void logBackendContextObservation(const nlohmann::json& metadata, int requestedContext)
{
    if (requestedContext <= 0) {
        return;
    }

    int effective = parseContextMetadataInt(metadata, "effective_ctx");
    if (effective <= 0) {
        effective = parseContextMetadataInt(metadata, "num_ctx");
    }
    if (effective <= 0) {
        effective = parseContextMetadataInt(metadata, "n_ctx");
    }
    if (effective <= 0) {
        return;
    }

    if (effective < requestedContext) {
        const int64_t requestedBytes = RawrXD::ContextLimits::estimateKVBytes(requestedContext);
        const int64_t effectiveBytes = RawrXD::ContextLimits::estimateKVBytes(effective);
        const double requestedPerToken = requestedContext > 0
                                             ? static_cast<double>(requestedBytes) / static_cast<double>(requestedContext)
                                             : 0.0;
        const double effectivePerToken = effective > 0
                                             ? static_cast<double>(effectiveBytes) / static_cast<double>(effective)
                                             : 0.0;
        std::cerr << "[AgentOllamaClient] Backend context clamp detected requested="
                  << requestedContext
                  << " effective=" << effective
                  << " requested_kv_bytes=" << requestedBytes
                  << " effective_kv_bytes=" << effectiveBytes
                  << " requested_kv_per_token=" << requestedPerToken
                  << " effective_kv_per_token=" << effectivePerToken << "\n";
    }
}
}

AgentOllamaClient::AgentOllamaClient(const OllamaConfig& config)
    : m_config(config) {
    if (!RawrXD::BackendOrchestrator::Instance().IsInitialized()) {
        RawrXD::BackendOrchestrator::Instance().Initialize();
    }

    const RawrXD::ContextDecision ctxDecision =
        RawrXD::ResolveContextDecision(m_config.num_ctx > 0 ? m_config.num_ctx : RawrXD::ContextLimits::DEFAULT);
    m_config.num_ctx = ctxDecision.effective;
    std::cerr << "[AgentOllamaClient] Context decision requested=" << ctxDecision.requested
              << " env=" << (ctxDecision.env_override_applied ? ctxDecision.env_override_value : 0)
              << " system_max=" << ctxDecision.system_safe_max
              << " kv_max=" << ctxDecision.kv_safe_max
              << " effective=" << ctxDecision.effective
              << " kv_bytes=" << ctxDecision.estimated_kv_bytes
              << " kv_per_token=" << ctxDecision.kv_bytes_per_token
              << " vram_budget=" << ctxDecision.vram_budget_bytes
              << " kv_budget=" << ctxDecision.kv_budget_bytes
              << " pressure_ratio=" << ctxDecision.pressure_ratio
              << " pressure=" << (ctxDecision.pressure_detected ? 1 : 0)
              << " adapted=" << (ctxDecision.adapted ? 1 : 0) << "\n";

    RawrXD::Agentic::Hotpatch::Engine::instance().setModelTemperature(m_config.temperature);

    (void)rawr_cpu_has_avx2();
}

AgentOllamaClient::~AgentOllamaClient() {
    CancelStream();
}

std::string AgentOllamaClient::BuildPromptFromMessages(const std::vector<ChatMessage>& messages,
                                                       const nlohmann::json& tools) const {
    std::string prompt;
    bool systemAlreadyMentionsTools = false;

    for (const auto& msg : messages) {
        if (msg.role == "system") {
            prompt += "System: " + msg.content + "\n\n";
            systemAlreadyMentionsTools = (msg.content.find("Available Tools:") != std::string::npos) ||
                                        (msg.content.find("Tool Call Protocol:") != std::string::npos);
            break;
        }
    }

    for (const auto& msg : messages) {
        if (msg.role == "user") {
            prompt += "User: " + msg.content + "\n";
        } else if (msg.role == "assistant") {
            prompt += "Assistant: " + msg.content + "\n";
        } else if (msg.role == "tool") {
            prompt += "Tool result: " + msg.content + "\n";
        }
    }

    if (!systemAlreadyMentionsTools && !tools.empty() && tools.is_array()) {
        prompt += "\nTool Call Protocol:\n";
        prompt += "- Emit JSON only: {\"tool_call\": {\"name\": \"tool_name\", \"arguments\": {...}}}\n";
        prompt += "- Available tool names: ";
        bool first = true;
        for (const auto& tool : tools) {
            if (tool.contains("function") && tool["function"].is_object()) {
                const auto& func = tool["function"];
                const std::string name = func.value("name", std::string());
                if (name.empty()) {
                    continue;
                }
                if (!first) {
                    prompt += ", ";
                }
                first = false;
                prompt += name;
            }
        }
        prompt += "\n";
    }

    prompt += "Assistant: ";
    return prompt;
}

void AgentOllamaClient::ParseToolCallsFromResponse(const std::string& response,
                                                   InferenceResult& result) const {
    const std::string toolPrefix = "TOOL_CALL:";
    const size_t prefixPos = response.find(toolPrefix);
    if (prefixPos != std::string::npos) {
        const size_t prefixedJsonStart = response.find('{', prefixPos + toolPrefix.size());
        const size_t prefixedJsonEnd = response.rfind('}');
        if (prefixedJsonStart != std::string::npos && prefixedJsonEnd != std::string::npos && prefixedJsonEnd >= prefixedJsonStart) {
            try {
                nlohmann::json tc = nlohmann::json::parse(response.substr(prefixedJsonStart, prefixedJsonEnd - prefixedJsonStart + 1));
                const std::string name = tc.value("name", std::string());
                nlohmann::json args = tc.value("arguments", nlohmann::json::object());
                if (!name.empty()) {
                    result.has_tool_calls = true;
                    result.tool_calls.emplace_back(name, args);
                    result.response = response.substr(0, prefixPos);
                    return;
                }
            } catch (...) {
            }
        }
    }

    size_t json_start = response.find("{");
    if (json_start == std::string::npos) {
        return;
    }

    size_t json_end = response.rfind("}");
    if (json_end == std::string::npos || json_end < json_start) {
        return;
    }

    std::string json_str = response.substr(json_start, json_end - json_start + 1);
    try {
        nlohmann::json j = nlohmann::json::parse(json_str);
        if (j.contains("tool_call") && j["tool_call"].is_object()) {
            const auto& tc = j["tool_call"];
            std::string name = tc.value("name", "");
            nlohmann::json args = tc.value("arguments", nlohmann::json::object());
            if (!name.empty()) {
                result.has_tool_calls = true;
                result.tool_calls.emplace_back(name, args);
                result.response = response.substr(0, json_start);
                return;
            }
        }

        if (j.contains("tool_calls") && j["tool_calls"].is_array()) {
            for (const auto& entry : j["tool_calls"]) {
                if (!entry.is_object()) {
                    continue;
                }

                std::string name = entry.value("tool", std::string());
                nlohmann::json args = entry.value("arguments", nlohmann::json::object());
                if (name.empty() && entry.contains("function") && entry["function"].is_object()) {
                    const auto& function = entry["function"];
                    name = function.value("name", std::string());
                    if (function.contains("arguments")) {
                        args = function["arguments"];
                        if (args.is_string()) {
                            args = nlohmann::json::parse(args.get<std::string>(), nullptr, false);
                            if (args.is_discarded()) {
                                args = nlohmann::json::object();
                            }
                        }
                    }
                }

                if (!name.empty()) {
                    result.has_tool_calls = true;
                    result.tool_calls.emplace_back(name, args.is_object() ? args : nlohmann::json::object());
                }
            }
            if (result.has_tool_calls) {
                result.response = response.substr(0, json_start);
            }
        }
    } catch (...) {
    }
}

bool AgentOllamaClient::TestConnection() {
    return TestConnectionWithStats().ok;
}

OllamaHealth AgentOllamaClient::TestConnectionWithStats() {
    OllamaHealth h;
    auto t0 = std::chrono::steady_clock::now();

    auto& bo = RawrXD::BackendOrchestrator::Instance();
    h.ok = bo.IsInitialized() && !bo.GetLoadedModelTags().empty();
    h.model_count = static_cast<int>(bo.GetLoadedModelTags().size());

    auto t1 = std::chrono::steady_clock::now();
    h.latency_ms = static_cast<int>(
        std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count());
    h.version = "RawrXD-v14.7.3";

    return h;
}

std::string AgentOllamaClient::GetVersion() {
    return "RawrXD-v14.7.3";
}

std::vector<std::string> AgentOllamaClient::ListModels() {
    return RawrXD::BackendOrchestrator::Instance().GetLoadedModelTags();
}

InferenceResult AgentOllamaClient::ChatSync(const std::vector<ChatMessage>& messages,
                                            const nlohmann::json& tools) {
    std::string prompt = BuildPromptFromMessages(messages, tools);

    RawrXD::InferRequest req;
    req.id = m_nextRequestId++;
    req.prompt = prompt;
    req.max_tokens = m_config.max_tokens;
    req.tenant_id = "agentic";

    std::promise<std::string> completion_promise;
    std::promise<std::string> metadata_promise;

    req.complete_cb = [&](const std::string& completion, const std::string& metadata) {
        completion_promise.set_value(completion);
        metadata_promise.set_value(metadata);
    };

    auto start_time = std::chrono::steady_clock::now();
    auto& bo = RawrXD::BackendOrchestrator::Instance();
    uint64_t req_id = bo.Enqueue(req);

    std::future<std::string> completion_future = completion_promise.get_future();
    if (completion_future.wait_for(std::chrono::seconds(120)) != std::future_status::ready) {
        bo.Cancel(req_id);
        return InferenceResult::error("Inference timeout");
    }

    InferenceResult result;
    result.success = true;
    result.has_tool_calls = false;
    result.response = completion_future.get();
    std::string backendDetail;
    if (startsWithBackendError(result.response, &backendDetail)) {
        return InferenceResult::error(formatBackendError("chat_sync", backendDetail));
    }
    if (trimAsciiCopy(result.response).empty()) {
        return InferenceResult::error("[BackendError] stage=chat_sync detail=empty_completion_payload");
    }
    result.prompt_tokens = 0;
    result.completion_tokens = 0;
    result.tokens_per_sec = 0.0;

    try {
        std::string metadata = metadata_promise.get_future().get();
        nlohmann::json j = nlohmann::json::parse(metadata, nullptr, false);
        if (j.is_object()) {
            logBackendContextObservation(j, m_config.num_ctx);
            if (j.contains("prompt_eval_count")) {
                result.prompt_tokens = j["prompt_eval_count"].get<uint64_t>();
            }
            if (j.contains("eval_count")) {
                result.completion_tokens = j["eval_count"].get<uint64_t>();
            }
            if (j.contains("eval_duration") && result.completion_tokens > 0) {
                uint64_t eval_ns = j["eval_duration"].get<uint64_t>();
                result.tokens_per_sec = static_cast<double>(result.completion_tokens) /
                                        (static_cast<double>(eval_ns) / 1e9);
            }
        }
    } catch (...) {
    }

    auto end_time = std::chrono::steady_clock::now();
    result.total_duration_ms = static_cast<double>(
        std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count());

    ParseToolCallsFromResponse(result.response, result);

    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_totalDurationMs += result.total_duration_ms;
    }
    m_totalRequests.fetch_add(1, std::memory_order_relaxed);
    m_totalTokens.fetch_add(result.completion_tokens, std::memory_order_relaxed);

    return result;
}

bool AgentOllamaClient::ChatStream(const std::vector<ChatMessage>& messages,
                                   const nlohmann::json& tools,
                                   TokenCallback on_token,
                                   ToolCallCallback on_tool_call,
                                   DoneCallback on_done,
                                   ErrorCallback on_error) {
    (void)on_error;

    std::string prompt = BuildPromptFromMessages(messages, tools);

    RawrXD::InferRequest req;
    req.id = m_nextRequestId++;
    req.prompt = prompt;
    req.max_tokens = m_config.max_tokens;
    req.tenant_id = "agentic";

    m_streaming.store(true);
    m_cancelRequested.store(false);
    m_totalRequests.fetch_add(1, std::memory_order_relaxed);

    auto start_time = std::chrono::steady_clock::now();

    auto full_response = std::make_shared<std::string>();
    auto prompt_tokens = std::make_shared<uint64_t>(0);
    auto completion_tokens = std::make_shared<uint64_t>(0);
    auto tps = std::make_shared<double>(0.0);

    req.stream_cb = [this, on_token, full_response](const std::string& token) {
        if (m_cancelRequested.load()) {
            return;
        }
        full_response->append(token);
        if (on_token) {
            on_token(token);
        }
    };

    req.complete_cb = [=](const std::string& completion, const std::string& metadata) {
        std::string backendDetail;
        if (startsWithBackendError(completion, &backendDetail)) {
            m_streaming.store(false);
            if (on_error) {
                on_error(formatBackendError("chat_stream", backendDetail));
            }
            return;
        }
        if (trimAsciiCopy(completion).empty()) {
            m_streaming.store(false);
            if (on_error) {
                on_error("[BackendError] stage=chat_stream detail=empty_completion_payload");
            }
            return;
        }

        *full_response = completion;

        try {
            nlohmann::json j = nlohmann::json::parse(metadata, nullptr, false);
            if (j.is_object()) {
                logBackendContextObservation(j, m_config.num_ctx);
                if (j.contains("prompt_eval_count")) {
                    *prompt_tokens = j["prompt_eval_count"].get<uint64_t>();
                }
                if (j.contains("eval_count")) {
                    *completion_tokens = j["eval_count"].get<uint64_t>();
                }
                if (j.contains("eval_duration") && *completion_tokens > 0) {
                    uint64_t eval_ns = j["eval_duration"].get<uint64_t>();
                    *tps = static_cast<double>(*completion_tokens) /
                           (static_cast<double>(eval_ns) / 1e9);
                }
            }
        } catch (...) {
        }

        InferenceResult parsed;
        parsed.success = true;
        parsed.has_tool_calls = false;
        parsed.response = completion;
        ParseToolCallsFromResponse(completion, parsed);

        if (on_tool_call) {
            for (const auto& tool_call : parsed.tool_calls) {
                on_tool_call(tool_call.first, tool_call.second);
            }
        }

        auto end_time = std::chrono::steady_clock::now();
        double elapsed_ms = static_cast<double>(
            std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count());

        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_totalDurationMs += elapsed_ms;
        }
        m_totalTokens.fetch_add(*completion_tokens, std::memory_order_relaxed);
        m_streaming.store(false);

        if (on_done) {
            on_done(completion, *prompt_tokens, *completion_tokens, *tps);
        }
    };

    RawrXD::BackendOrchestrator::Instance().Enqueue(req);
    return true;
}

InferenceResult AgentOllamaClient::FIMSync(const std::string& prefix,
                                           const std::string& suffix,
                                           const std::string& filename) {
    (void)filename;

    std::string prompt = prefix + "<FILL>" + suffix;

    RawrXD::InferRequest req;
    req.id = m_nextRequestId++;
    req.prompt = prompt;
    req.max_tokens = m_config.fim_max_tokens;
    req.tenant_id = "agentic";

    auto completion_promise = std::make_shared<std::promise<std::string>>();

    req.complete_cb = [completion_promise](const std::string& completion, const std::string& metadata) {
        (void)metadata;
        completion_promise->set_value(completion);
    };

    auto& bo = RawrXD::BackendOrchestrator::Instance();
    uint64_t req_id = bo.Enqueue(req);

    std::future<std::string> completion_future = completion_promise->get_future();
    if (completion_future.wait_for(std::chrono::seconds(60)) != std::future_status::ready) {
        bo.Cancel(req_id);
        return InferenceResult::error("FIM timeout");
    }

    std::string response = completion_future.get();
    std::string backendDetail;
    if (startsWithBackendError(response, &backendDetail)) {
        return InferenceResult::error(formatBackendError("fim_sync", backendDetail));
    }
    if (trimAsciiCopy(response).empty()) {
        return InferenceResult::error("[BackendError] stage=fim_sync detail=empty_completion_payload");
    }

    size_t fill_pos = response.find("<FILL>");
    if (fill_pos != std::string::npos) {
        std::string fill = response.substr(fill_pos + 6);
        if (!suffix.empty() && fill.size() >= suffix.size() &&
            fill.compare(fill.size() - suffix.size(), suffix.size(), suffix) == 0) {
            fill.resize(fill.size() - suffix.size());
        }
        return InferenceResult::ok(fill);
    }

    return InferenceResult::ok(response);
}

bool AgentOllamaClient::FIMStream(const std::string& prefix,
                                  const std::string& suffix,
                                  const std::string& filename,
                                  TokenCallback on_token,
                                  DoneCallback on_done,
                                  ErrorCallback on_error) {
    (void)filename;
    (void)on_error;

    std::string prompt = prefix + "<FILL>" + suffix;

    RawrXD::InferRequest req;
    req.id = m_nextRequestId++;
    req.prompt = prompt;
    req.max_tokens = m_config.fim_max_tokens;
    req.tenant_id = "agentic";

    m_streaming.store(true);
    m_cancelRequested.store(false);
    m_totalRequests.fetch_add(1, std::memory_order_relaxed);

    auto start_time = std::chrono::steady_clock::now();
    auto completion_tokens = std::make_shared<uint64_t>(0);
    auto tps = std::make_shared<double>(0.0);

    req.stream_cb = [this, on_token](const std::string& token) {
        if (m_cancelRequested.load()) {
            return;
        }
        if (on_token) {
            on_token(token);
        }
    };

    req.complete_cb = [=](const std::string& completion, const std::string& metadata) {
        std::string backendDetail;
        if (startsWithBackendError(completion, &backendDetail)) {
            m_streaming.store(false);
            if (on_error) {
                on_error(formatBackendError("fim_stream", backendDetail));
            }
            return;
        }
        if (trimAsciiCopy(completion).empty()) {
            m_streaming.store(false);
            if (on_error) {
                on_error("[BackendError] stage=fim_stream detail=empty_completion_payload");
            }
            return;
        }

        try {
            nlohmann::json j = nlohmann::json::parse(metadata, nullptr, false);
            if (j.is_object()) {
                logBackendContextObservation(j, m_config.num_ctx);
                if (j.contains("eval_count")) {
                    *completion_tokens = j["eval_count"].get<uint64_t>();
                }
                if (j.contains("eval_duration") && *completion_tokens > 0) {
                    uint64_t eval_ns = j["eval_duration"].get<uint64_t>();
                    *tps = static_cast<double>(*completion_tokens) /
                           (static_cast<double>(eval_ns) / 1e9);
                }
            }
        } catch (...) {
        }

        auto end_time = std::chrono::steady_clock::now();
        double elapsed_ms = static_cast<double>(
            std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count());

        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_totalDurationMs += elapsed_ms;
        }
        m_totalTokens.fetch_add(*completion_tokens, std::memory_order_relaxed);
        m_streaming.store(false);

        if (on_done) {
            on_done(completion, 0, *completion_tokens, *tps);
        }
    };

    RawrXD::BackendOrchestrator::Instance().Enqueue(req);
    return true;
}

void AgentOllamaClient::CancelStream() {
    m_cancelRequested.store(true);
}

bool AgentOllamaClient::WarmupConnection() {
    auto t0 = std::chrono::steady_clock::now();
    for (int attempt = 0; attempt < kMaxRetries; ++attempt) {
        if (TestConnection()) {
            auto t1 = std::chrono::steady_clock::now();
            double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
            std::cerr << "[AgentOllamaClient] Native warmup succeeded in " << ms
                      << "ms (attempt " << (attempt + 1) << ")\n";
            return true;
        }
        if (attempt < kMaxRetries - 1) {
            std::this_thread::sleep_for(
                std::chrono::milliseconds(kRetryBaseDelayMs * (1 << attempt)));
        }
    }
    std::cerr << "[AgentOllamaClient] Native warmup failed after " << kMaxRetries
              << " attempts\n";
    return false;
}

bool AgentOllamaClient::CheckModelHealth(const std::string& modelName) {
    auto models = ListModels();
    for (const auto& m : models) {
        if (m == modelName || m.find(modelName) != std::string::npos) {
            return true;
        }
    }
    return false;
}

bool AgentOllamaClient::ShouldEmitError(const std::string& msg) {
    std::lock_guard<std::mutex> lock(m_mutex);

    while (m_recentErrors.size() > 10) {
        m_recentErrors.pop_front();
    }

    for (const auto& recent : m_recentErrors) {
        if (recent == msg) {
            return false;
        }
    }

    m_recentErrors.push_back(msg);
    m_consecutiveErrors++;
    return m_consecutiveErrors <= 10;
}

void AgentOllamaClient::SetConfig(const OllamaConfig& config) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_config = config;
    const RawrXD::ContextDecision ctxDecision =
        RawrXD::ResolveContextDecision(m_config.num_ctx > 0 ? m_config.num_ctx : RawrXD::ContextLimits::DEFAULT);
    m_config.num_ctx = ctxDecision.effective;
    std::cerr << "[AgentOllamaClient] SetConfig context requested=" << ctxDecision.requested
              << " env=" << (ctxDecision.env_override_applied ? ctxDecision.env_override_value : 0)
              << " system_max=" << ctxDecision.system_safe_max
              << " kv_max=" << ctxDecision.kv_safe_max
              << " effective=" << ctxDecision.effective
              << " kv_bytes=" << ctxDecision.estimated_kv_bytes
              << " kv_per_token=" << ctxDecision.kv_bytes_per_token
              << " vram_budget=" << ctxDecision.vram_budget_bytes
              << " kv_budget=" << ctxDecision.kv_budget_bytes
              << " pressure_ratio=" << ctxDecision.pressure_ratio
              << " pressure=" << (ctxDecision.pressure_detected ? 1 : 0)
              << " adapted=" << (ctxDecision.adapted ? 1 : 0) << "\n";
    RawrXD::Agentic::Hotpatch::Engine::instance().setModelTemperature(m_config.temperature);
}

double AgentOllamaClient::GetAvgTokensPerSec() const {
    uint64_t tokens = m_totalTokens.load(std::memory_order_relaxed);
    if (tokens == 0 || m_totalDurationMs <= 0.0) {
        return 0.0;
    }
    return static_cast<double>(tokens) / (m_totalDurationMs / 1000.0);
}

AgentOllamaClient::MetricsSnapshot AgentOllamaClient::GetMetricsSnapshot() const {
    MetricsSnapshot snap;
    snap.totalRequests = m_totalRequests.load(std::memory_order_relaxed);
    snap.totalTokens = m_totalTokens.load(std::memory_order_relaxed);
    snap.avgTokensPerSec = GetAvgTokensPerSec();
    snap.isStreaming = m_streaming.load(std::memory_order_relaxed);
    snap.consecutiveErrors = m_consecutiveErrors;
    snap.chatModel = m_config.chat_model;
    snap.fimModel = m_config.fim_model;
    snap.host = m_config.host;
    snap.port = m_config.port;
    return snap;
}

InferenceResult AgentOllamaClient::ChatSyncWithRetry(const std::vector<ChatMessage>& messages,
                                                     const nlohmann::json& tools,
                                                     int maxRetries) {
    for (int attempt = 0; attempt < maxRetries; ++attempt) {
        InferenceResult result = ChatSync(messages, tools);
        if (result.success) {
            m_consecutiveErrors = 0;
            return result;
        }

        if (result.error_message.find("model not found") != std::string::npos ||
            result.error_message.find("invalid") != std::string::npos) {
            return result;
        }

        if (attempt < maxRetries - 1) {
            int delayMs = kRetryBaseDelayMs * (1 << attempt);
            std::this_thread::sleep_for(std::chrono::milliseconds(delayMs));
        }
    }

    return InferenceResult::error("ChatSync failed after retries");
}