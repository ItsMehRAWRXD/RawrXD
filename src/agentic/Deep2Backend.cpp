// =============================================================================
// Deep2Backend.cpp — Deep2 Native Inference Backend Implementation
// =============================================================================
#include "Deep2Backend.h"
#include <chrono>
#include <sstream>
#include <algorithm>

#ifdef _WIN32
#include <windows.h>
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")
#else
#include <curl/curl.h>
#endif

namespace RawrXD {
namespace Agent {

Deep2Backend::Deep2Backend() = default;
Deep2Backend::~Deep2Backend() { Shutdown(); }

BackendConfig Deep2Backend::DefaultConfig() const {
    BackendConfig cfg;
    cfg.kind          = BackendKind::Deep2;
    cfg.endpoint      = "http://127.0.0.1:11436";
    cfg.model         = "deep2-native";
    cfg.temperature   = 0.2f;
    cfg.top_p         = 0.9f;
    cfg.max_tokens    = 4096;
    cfg.num_ctx       = 32768;
    cfg.timeout_ms    = 120000;
    cfg.use_gpu       = true;
    cfg.num_gpu       = 99;
    return cfg;
}

bool Deep2Backend::Initialize(const BackendConfig& config) {
    if (m_initialized.load()) return true;

    m_config = config;
    if (m_config.endpoint.empty()) {
        m_config = DefaultConfig();
    }

    m_initialized.store(true);
    if (CheckHealth()) return true;
    m_initialized.store(false);
    return false;
}

void Deep2Backend::Shutdown() {
    m_cancelRequested.store(true);
    m_streaming.store(false);
    m_initialized.store(false);
}

bool Deep2Backend::IsInitialized() const {
    return m_initialized.load();
}

BackendConfig Deep2Backend::GetConfig() const {
    return m_config;
}

void Deep2Backend::SetConfig(const BackendConfig& config) {
    m_config = config;
    if (m_config.endpoint.empty()) {
        m_config.endpoint = "http://127.0.0.1:11436";
    }
}

BackendHealth Deep2Backend::GetHealth() const {
    BackendHealth health;
    health.endpoint   = m_config.endpoint;
    health.model_name = m_config.model;
    health.last_check = std::chrono::steady_clock::now();

    if (!m_initialized.load()) {
        health.available = false;
        health.healthy   = false;
        health.last_error = "Backend not initialized";
        return health;
    }

    health.available = (m_consecutiveErrors < 3);
    health.healthy   = (m_consecutiveErrors < 3);
    if (!m_recentErrors.empty()) {
        health.last_error = m_recentErrors.back();
    }
    return health;
}

bool Deep2Backend::CheckHealth() {
    if (!m_initialized.load()) return false;

    std::string resp = makeGetRequest("/health");
    if (resp.empty()) {
        RecordFailure("Deep2 backend health check failed: " + m_config.endpoint);
        return false;
    }

    try {
        json j = json::parse(resp);
        bool ok = j.value("status", std::string()) == "ok" ||
                  j.value("healthy", false) == true;
        if (ok) {
            m_consecutiveErrors = 0;
        } else {
            RecordFailure("Deep2 health returned unhealthy: " + resp.substr(0, 128));
        }
        return ok;
    } catch (const json::exception&) {
        RecordFailure("Deep2 health returned invalid JSON");
        return false;
    }
}

bool Deep2Backend::Supports(BackendCapability cap) const {
    switch (cap) {
        case BackendCapability::Chat:
        case BackendCapability::ToolCalling:
        case BackendCapability::Streaming:
        case BackendCapability::FIM:
        case BackendCapability::Cancellation:
        case BackendCapability::ModelDiscovery:
        case BackendCapability::StructuredOutput:
            return true;
        case BackendCapability::Embeddings:
            // Deep2 supports embeddings via /api/embeddings
            return true;
        default:
            return false;
    }
}

std::vector<std::string> Deep2Backend::ListModels() {
    std::string resp = makeGetRequest("/v1/models");
    std::vector<std::string> models;
    if (resp.empty()) return models;

    try {
        json j = json::parse(resp);
        const json* entries = nullptr;
        if (j.contains("data") && j["data"].is_array()) {
            entries = &j["data"]; // OpenAI-compatible /v1/models
        } else if (j.contains("models") && j["models"].is_array()) {
            entries = &j["models"]; // Native Deep2 model listing
        }
        if (entries) {
            for (const auto& m : *entries) {
                if (!m.is_object()) continue;
                const std::string id = m.value("id", m.value("name", std::string()));
                if (!id.empty()) models.push_back(id);
            }
        }
    } catch (const json::exception&) {}

    return models;
}

bool Deep2Backend::LoadModel(const std::string& model_name) {
    // Deep2 loads models server-side; send a load request
    json load_req;
    load_req["model"] = model_name;
    std::string resp = makePostRequest("/api/models/load", load_req.dump());
    if (resp.empty()) return false;

    m_config.model = model_name;
    return true;
}

json Deep2Backend::BuildOpenAiMessages(
    const std::vector<ChatMessage>& messages) const {
    json arr = json::array();
    for (const auto& msg : messages) {
        json m;
        m["role"] = msg.role;
        m["content"] = msg.content;
        if (msg.role == "assistant" && !msg.tool_calls.is_null()) {
            m["tool_calls"] = msg.tool_calls;
        }
        if (msg.role == "tool" && !msg.tool_call_id.empty()) {
            m["tool_call_id"] = msg.tool_call_id;
        }
        // Tool responses may already be in content
        arr.push_back(m);
    }
    return arr;
}

InferenceResult Deep2Backend::ChatSync(
    const std::vector<ChatMessage>& messages,
    const json& tools) {
    if (!m_initialized.load()) {
        return InferenceResult::Error("Deep2 backend not initialized");
    }

    m_cancelRequested.store(false);

    json req;
    req["model"]    = m_config.model;
    req["messages"]  = BuildOpenAiMessages(messages);
    req["stream"]    = false;
    req["temperature"] = m_config.temperature;
    req["top_p"]       = m_config.top_p;
    if (m_config.max_tokens > 0) req["max_tokens"] = m_config.max_tokens;
    if (!tools.is_null()) req["tools"] = tools;

    auto t0 = std::chrono::steady_clock::now();
    std::string resp = makePostRequest("/v1/chat/completions", req.dump());

    auto t1 = std::chrono::steady_clock::now();
    double elapsed_ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
    m_totalRequests.fetch_add(1);

    if (resp.empty()) {
        RecordFailure("Deep2 ChatSync: empty response");
        return InferenceResult::Error("Deep2 server returned empty response");
    }

    try {
        json j = json::parse(resp);

        std::string text;
        uint64_t ptok = 0, ctok = 0;

        if (j.contains("choices") && !j["choices"].empty()) {
            const auto& choice = j["choices"][0];
            if (choice.contains("message")) {
                const auto& msg = choice["message"];
                text = msg.value("content", std::string());
                // Parse tool_calls
                if (msg.contains("tool_calls")) {
                    // Store raw tool_calls for caller to parse
                }
            } else if (choice.contains("text")) {
                text = choice["text"].get<std::string>();
            }
        }

        if (j.contains("usage")) {
            const auto& usage = j["usage"];
            ptok = usage.value("prompt_tokens", uint64_t(0));
            ctok = usage.value("completion_tokens", uint64_t(0));
        }

        double tps = (elapsed_ms > 0 && ctok > 0)
            ? (ctok / (elapsed_ms / 1000.0)) : 0.0;
        RecordSuccess(tps, ptok, ctok);

        InferenceResult result = InferenceResult::Ok(text);
        result.prompt_tokens = ptok;
        result.completion_tokens = ctok;
        result.tokens_per_sec = tps;
        result.total_duration_ms = elapsed_ms;
        return result;

    } catch (const json::exception& e) {
        RecordFailure("Deep2 ChatSync JSON error: " + std::string(e.what()));
        return InferenceResult::Error("Failed to parse Deep2 response: " + std::string(e.what()));
    }
}

bool Deep2Backend::ChatStream(
    const std::vector<ChatMessage>& messages,
    const json& tools,
    TokenCallback     on_token,
    ToolCallCallback  on_tool_call,
    DoneCallback      on_done,
    ErrorCallback     on_error) {
    if (!m_initialized.load()) {
        if (on_error) on_error("Deep2 backend not initialized");
        return false;
    }

    m_cancelRequested.store(false);
    m_streaming.store(true);

    json req;
    req["model"]    = m_config.model;
    req["messages"]  = BuildOpenAiMessages(messages);
    req["stream"]    = true;
    req["temperature"] = m_config.temperature;
    req["top_p"]       = m_config.top_p;
    if (m_config.max_tokens > 0) req["max_tokens"] = m_config.max_tokens;
    if (!tools.is_null()) req["tools"] = tools;

    auto t0 = std::chrono::steady_clock::now();
    std::string full_response;
    uint64_t ptok = 0, ctok = 0;
    bool stream_failed = false;
    bool has_tool_calls = false;
    json accumulated_tool_calls = json::array();

    auto on_chunk = [&](const std::string& chunk_data) -> bool {
        if (m_cancelRequested.load()) return false;

        // Parse SSE-style lines: "data: {...}\n\n"
        if (chunk_data.rfind("data: ", 0) == 0 || chunk_data.rfind("data:", 0) == 0) {
            std::string data = chunk_data.substr(chunk_data.find(':') + 1);
            // Trim leading space
            data.erase(0, data.find_first_not_of(" \t\r\n"));

            if (data == "[DONE]" || data == "[done]") {
                auto t1 = std::chrono::steady_clock::now();
                double elapsed_ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
                double tps = (elapsed_ms > 0 && ctok > 0)
                    ? (ctok / (elapsed_ms / 1000.0)) : 0.0;

                m_totalRequests.fetch_add(1);
                RecordSuccess(tps, ptok, ctok);

                if (on_done) on_done(full_response, ptok, ctok, tps);
                return true;
            }

            try {
                json delta = json::parse(data);

                if (delta.contains("choices") && !delta["choices"].empty()) {
                    const auto& choice = delta["choices"][0];

                    // Content delta
                    if (choice.contains("delta") && choice["delta"].contains("content")) {
                        std::string content = choice["delta"]["content"].get<std::string>();
                        full_response += content;
                        if (on_token) on_token(content);
                    }

                    // Tool call delta (accumulation)
                    if (choice.contains("delta") && choice["delta"].contains("tool_calls")) {
                        has_tool_calls = true;
                        const auto& tc_delta = choice["delta"]["tool_calls"];
                        // Merge tool calls
                        for (const auto& tc_d : tc_delta) {
                            int idx = tc_d.value("index", 0);
                            // Grow the accumulator to hold index idx (json arrays
                            // grow on assignment, so pad with nulls first).
                            while (accumulated_tool_calls.size() <= static_cast<size_t>(idx)) {
                                accumulated_tool_calls.push_back(json());
                            }
                            if (tc_d.contains("function")) {
                                const auto& fn = tc_d["function"];
                                if (fn.contains("name")) {
                                    accumulated_tool_calls[idx]["function"]["name"] = fn["name"];
                                }
                                if (fn.contains("arguments")) {
                                    std::string args = fn["arguments"].get<std::string>();
                                    if (!accumulated_tool_calls[idx].contains("function")) {
                                        accumulated_tool_calls[idx]["function"] = json::object();
                                    }
                                    accumulated_tool_calls[idx]["function"]["arguments"] =
                                        accumulated_tool_calls[idx]["function"].value("arguments", "") + args;
                                }
                            }
                        }
                    }

                    // Usage (may arrive at end)
                    if (choice.contains("usage")) {
                        const auto& usage = choice["usage"];
                        ptok = usage.value("prompt_tokens", uint64_t(0));
                        ctok = usage.value("completion_tokens", uint64_t(0));
                    }
                }
            } catch (const json::exception&) {
                // Ignore parse errors for individual chunks
            }
        }

        return true;
    };

    auto on_err = [&](const std::string& err) {
        stream_failed = true;
        RecordFailure("Deep2 ChatStream error: " + err);
        if (on_error) on_error(err);
    };

    // Tool deltas are delivered only after a successful completed stream.
    auto deliver_tool_calls = [&]() {
        if (!has_tool_calls || !on_tool_call) return;
        for (const auto& tc : accumulated_tool_calls) {
            if (!tc.is_object() || !tc.contains("function") ||
                !tc["function"].is_object()) continue;
            const auto& fn = tc["function"];
            const std::string name = fn.value("name", std::string());
            if (name.empty()) continue;
            json args = fn.value("arguments", json::object());
            if (args.is_string()) {
                try { args = json::parse(args.get<std::string>()); }
                catch (const json::exception&) { continue; }
            }
            if (!args.is_object()) continue;
            on_tool_call(name, args);
        }
    };

    std::string resp = makePostRequestStreaming("/v1/chat/completions", req.dump(), on_chunk);

    m_streaming.store(false);

    if (resp.empty() && !stream_failed) {
        stream_failed = true;
        on_err("Deep2 ChatStream: empty response");
    }

    if (!stream_failed && !m_cancelRequested.load()) deliver_tool_calls();
    return !stream_failed && !m_cancelRequested.load();
}

InferenceResult Deep2Backend::FIMSync(
    const std::string& prefix,
    const std::string& suffix,
    const std::string& filename) {
    if (!m_initialized.load()) {
        return InferenceResult::Error("Deep2 backend not initialized");
    }

    // Deep2 supports FIM via the /api/inference endpoint
    json req;
    req["prompt"] = "<|fim_prefix|>" + prefix + "<|fim_suffix|>" + suffix + "<|fim_middle|>";
    req["model"]  = m_config.model;
    req["stream"] = false;
    req["temperature"] = m_config.temperature;
    req["max_tokens"]  = 256;  // Short for ghost text

    std::string resp = makePostRequest("/api/inference", req.dump());

    if (resp.empty()) {
        RecordFailure("Deep2 FIMSync: empty response");
        return InferenceResult::Error("Deep2 server returned empty response");
    }

    try {
        json j = json::parse(resp);
        std::string text = j.value("generated_text", j.value("response", std::string()));
        RecordSuccess(0, 0, 0);
        return InferenceResult::Ok(text);
    } catch (const json::exception& e) {
        return InferenceResult::Error("Failed to parse Deep2 FIM response: " + std::string(e.what()));
    }
}

bool Deep2Backend::FIMStream(
    const std::string& prefix,
    const std::string& suffix,
    const std::string& filename,
    TokenCallback  on_token,
    DoneCallback   on_done,
    ErrorCallback  on_error) {
    if (!m_initialized.load()) {
        if (on_error) on_error("Deep2 backend not initialized");
        return false;
    }

    m_cancelRequested.store(false);
    m_streaming.store(true);

    json req;
    req["prompt"] = "<|fim_prefix|>" + prefix + "<|fim_suffix|>" + suffix + "<|fim_middle|>";
    req["model"]  = m_config.model;
    req["stream"] = true;
    req["temperature"] = m_config.temperature;
    req["max_tokens"]  = 256;

    auto t0 = std::chrono::steady_clock::now();
    std::string full_response;
    uint64_t ptok = 0, ctok = 0;
    bool stream_failed = false;

    auto on_chunk = [&](const std::string& chunk_data) -> bool {
        if (m_cancelRequested.load()) return false;

        if (chunk_data.rfind("data: ", 0) == 0 || chunk_data.rfind("data:", 0) == 0) {
            std::string data = chunk_data.substr(chunk_data.find(':') + 1);
            data.erase(0, data.find_first_not_of(" \t\r\n"));

            if (data == "[DONE]" || data == "[done]") {
                auto t1 = std::chrono::steady_clock::now();
                double elapsed_ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
                double tps = (elapsed_ms > 0 && ctok > 0)
                    ? (ctok / (elapsed_ms / 1000.0)) : 0.0;
                m_totalRequests.fetch_add(1);
                RecordSuccess(tps, ptok, ctok);
                if (on_done) on_done(full_response, ptok, ctok, tps);
                return true;
            }

            try {
                json j = json::parse(data);
                if (j.contains("choices") && !j["choices"].empty()) {
                    const auto& choice = j["choices"][0];
                    if (choice.contains("delta") && choice["delta"].contains("content")) {
                        std::string content = choice["delta"]["content"].get<std::string>();
                        full_response += content;
                        if (on_token) on_token(content);
                    }
                }
            } catch (const json::exception&) {}
        }
        return true;
    };

    auto on_err = [&](const std::string& err) {
        stream_failed = true;
        RecordFailure("Deep2 FIMStream error: " + err);
        if (on_error) on_error(err);
    };

    std::string resp = makePostRequestStreaming("/v1/chat/completions", req.dump(), on_chunk);
    m_streaming.store(false);

    if (resp.empty() && !stream_failed) {
        if (on_error) on_error("Deep2 FIMStream: empty response");
        return false;
    }

    return !stream_failed;
}

void Deep2Backend::Cancel() {
    m_cancelRequested.store(true);
    m_streaming.store(false);
}

bool Deep2Backend::IsStreaming() const {
    return m_streaming.load();
}

uint64_t Deep2Backend::GetTotalRequests() const {
    return m_totalRequests.load();
}

double Deep2Backend::GetAvgTokensPerSec() const {
    uint64_t total_req = m_totalRequests.load();
    if (total_req == 0) return 0.0;
    return m_accumulatedTps.load() / total_req;
}

bool Deep2Backend::ShouldEmitError(const std::string& msg) {
    std::lock_guard<std::mutex> lock(m_stats_mtx);
    m_recentErrors.push_back(msg);
    if (m_recentErrors.size() > 10) {
        m_recentErrors.pop_front();
    }
    m_consecutiveErrors++;
    return true;
}

void Deep2Backend::RecordSuccess(double tps, uint64_t ptok, uint64_t ctok) {
    m_consecutiveErrors = 0;
    m_totalTokens.fetch_add(ptok + ctok);
    double current_avg = m_accumulatedTps.load();
    uint64_t total_req = m_totalRequests.load();
    m_accumulatedTps.store(((current_avg * total_req) + tps) / (total_req + 1));
}

void Deep2Backend::RecordFailure(const std::string& error) {
    ShouldEmitError(error);
}

// =============================================================================
// WinHTTP implementation
// =============================================================================
#ifdef _WIN32

std::string Deep2Backend::makeGetRequest(const std::string& endpoint) {
    // Parse endpoint from config
    std::string host = "127.0.0.1";
    int port = 11436;
    size_t pos = m_config.endpoint.find("://");
    if (pos != std::string::npos) {
        std::string addr = m_config.endpoint.substr(pos + 3);
        size_t colon = addr.find(':');
        if (colon != std::string::npos) {
            host = addr.substr(0, colon);
            port = std::stoi(addr.substr(colon + 1));
        } else {
            host = addr;
        }
    }

    HINTERNET hSession = WinHttpOpen(L"Deep2Backend/1.0",
                                     WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                     WINHTTP_NO_PROXY_NAME,
                                     WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return "";

    std::wstring whost(host.begin(), host.end());
    HINTERNET hConnect = WinHttpConnect(hSession, whost.c_str(), port, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return "";
    }

    std::wstring wendpoint(endpoint.begin(), endpoint.end());
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", wendpoint.c_str(),
                                            NULL, WINHTTP_NO_REFERER,
                                            WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return "";
    }

    BOOL bResults = WinHttpSendRequest(hRequest,
                                       WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                       WINHTTP_NO_REQUEST_DATA, 0, 0, 0);

    std::string response;
    if (bResults) {
        bResults = WinHttpReceiveResponse(hRequest, NULL);
        if (bResults) {
            DWORD dwSize = 0;
            DWORD dwDownloaded = 0;
            do {
                dwSize = 0;
                if (WinHttpQueryDataAvailable(hRequest, &dwSize)) {
                    char* pszOutBuffer = new char[dwSize + 1];
                    ZeroMemory(pszOutBuffer, dwSize + 1);
                    if (WinHttpReadData(hRequest, (LPVOID)pszOutBuffer, dwSize, &dwDownloaded)) {
                        response.append(pszOutBuffer, dwDownloaded);
                    }
                    delete[] pszOutBuffer;
                }
            } while (dwSize > 0);
        }
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return response;
}

std::string Deep2Backend::makePostRequest(const std::string& endpoint, const std::string& json_body) {
    // Parse endpoint from config
    std::string host = "127.0.0.1";
    int port = 11436;
    size_t pos = m_config.endpoint.find("://");
    if (pos != std::string::npos) {
        std::string addr = m_config.endpoint.substr(pos + 3);
        size_t colon = addr.find(':');
        if (colon != std::string::npos) {
            host = addr.substr(0, colon);
            port = std::stoi(addr.substr(colon + 1));
        } else {
            host = addr;
        }
    }

    HINTERNET hSession = WinHttpOpen(L"Deep2Backend/1.0",
                                     WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                     WINHTTP_NO_PROXY_NAME,
                                     WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return "";

    std::wstring whost(host.begin(), host.end());
    HINTERNET hConnect = WinHttpConnect(hSession, whost.c_str(), port, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return "";
    }

    std::wstring wendpoint(endpoint.begin(), endpoint.end());
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", wendpoint.c_str(),
                                            NULL, WINHTTP_NO_REFERER,
                                            WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return "";
    }

    std::wstring headers = L"Content-Type: application/json\r\n";

    BOOL bResults = WinHttpSendRequest(hRequest,
                                       headers.c_str(), -1,
                                       (LPVOID)json_body.c_str(), json_body.length(),
                                       json_body.length(), 0);

    std::string response;
    if (bResults) {
        bResults = WinHttpReceiveResponse(hRequest, NULL);
        if (bResults) {
            DWORD dwSize = 0;
            DWORD dwDownloaded = 0;
            do {
                dwSize = 0;
                if (WinHttpQueryDataAvailable(hRequest, &dwSize)) {
                    char* pszOutBuffer = new char[dwSize + 1];
                    ZeroMemory(pszOutBuffer, dwSize + 1);
                    if (WinHttpReadData(hRequest, (LPVOID)pszOutBuffer, dwSize, &dwDownloaded)) {
                        response.append(pszOutBuffer, dwDownloaded);
                    }
                    delete[] pszOutBuffer;
                }
            } while (dwSize > 0);
        }
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return response;
}

std::string Deep2Backend::makePostRequestStreaming(
    const std::string& endpoint,
    const std::string& json_body,
    std::function<bool(const std::string& chunk)> onChunk) {
    // Parse endpoint from config
    std::string host = "127.0.0.1";
    int port = 11436;
    size_t pos = m_config.endpoint.find("://");
    if (pos != std::string::npos) {
        std::string addr = m_config.endpoint.substr(pos + 3);
        size_t colon = addr.find(':');
        if (colon != std::string::npos) {
            host = addr.substr(0, colon);
            port = std::stoi(addr.substr(colon + 1));
        } else {
            host = addr;
        }
    }

    HINTERNET hSession = WinHttpOpen(L"Deep2Backend/1.0",
                                     WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                     WINHTTP_NO_PROXY_NAME,
                                     WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return "";

    std::wstring whost(host.begin(), host.end());
    HINTERNET hConnect = WinHttpConnect(hSession, whost.c_str(), port, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return "";
    }

    std::wstring wendpoint(endpoint.begin(), endpoint.end());
    // Streaming uses the same WinHTTP open call as the sync path; chunked
    // responses are handled incrementally in the receive loop below.
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", wendpoint.c_str(),
                                            NULL, WINHTTP_NO_REFERER,
                                            WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return "";
    }

    std::wstring headers = L"Content-Type: application/json\r\n";

    BOOL bResults = WinHttpSendRequest(hRequest,
                                       headers.c_str(), -1,
                                       (LPVOID)json_body.c_str(), json_body.length(),
                                       json_body.length(), 0);

    std::string response;
    if (bResults) {
        bResults = WinHttpReceiveResponse(hRequest, NULL);
        if (bResults) {
            DWORD dwSize = 0;
            DWORD dwDownloaded = 0;
            std::string buffer;
            do {
                dwSize = 0;
                if (WinHttpQueryDataAvailable(hRequest, &dwSize)) {
                    char* pszOutBuffer = new char[dwSize + 1];
                    ZeroMemory(pszOutBuffer, dwSize + 1);
                    if (WinHttpReadData(hRequest, (LPVOID)pszOutBuffer, dwSize, &dwDownloaded)) {
                        buffer.append(pszOutBuffer, dwDownloaded);

                        // Process SSE lines
                        size_t start = 0;
                        size_t nl;
                        while ((nl = buffer.find('\n', start)) != std::string::npos) {
                            std::string line = buffer.substr(start, nl - start);
                            start = nl + 1;
                            if (line.empty() || line == "\r") continue;
                            if (!onChunk(line)) {
                                // Cancelled
                                break;
                            }
                        }
                        if (start < buffer.length()) {
                            buffer = buffer.substr(start);
                        } else {
                            buffer.clear();
                        }
                    }
                    delete[] pszOutBuffer;
                }
            } while (dwSize > 0 && !m_cancelRequested.load());
        }
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return response;
}

#else  // Non-Windows — fall back to empty (not supported in this environment)

std::string Deep2Backend::makeGetRequest(const std::string&) { return ""; }
std::string Deep2Backend::makePostRequest(const std::string&, const std::string&) { return ""; }
std::string Deep2Backend::makePostRequestStreaming(
    const std::string&, const std::string&,
    std::function<bool(const std::string&)>) { return ""; }

#endif

} // namespace Agent
} // namespace RawrXD
