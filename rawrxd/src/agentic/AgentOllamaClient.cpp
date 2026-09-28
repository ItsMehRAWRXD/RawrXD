// ============================================================================
// AgentOllamaClient.cpp — Real Ollama HTTP client for the agent subsystem
// Implements the contract declared in AgentOllamaClient.h:
//   TestConnection / ListModels / ChatSync — all synchronous, no exceptions
//   escaping the public surface (fail-closed error semantics).
//
// Ollama wire protocol used by callers (ProbeWithOllama in
// model_bruteforce_engine.cpp):
//   GET  /api/tags                 → {"models":[{"name":"tag"}...]}
//   POST /api/chat  {model, messages, stream:false, options{...}}
//     → {"message":{"content":...},"eval_count":N,"prompt_eval_count":N}
// All I/O is bounded by config_.timeoutMs (fail-closed). This client IS the
// Ollama path; callers opt in explicitly, so OLLAMA_USED accounting stays
// honest wherever it is checked.
// ============================================================================

#include "../agentic/AgentOllamaClient.h"

#include <nlohmann/json.hpp>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winhttp.h>

#include <sstream>
#include <algorithm>

#pragma comment(lib, "winhttp.lib")

namespace RawrXD {
namespace Agent {

namespace {

struct HttpResult {
    bool        ok = false;
    long        status = 0;
    std::string body;
    std::string error;
};

HttpResult HttpCall(const std::string& host, int port,
                    const std::string& method, const std::string& path,
                    const std::string& bodyJson, int timeoutMs) {
    HttpResult r;
    HINTERNET session = nullptr, connect = nullptr, request = nullptr;
    try {
        std::wstring whost(host.begin(), host.end());
        std::wstring wpath(path.begin(), path.end());
        std::wstring wmethod(method.begin(), method.end());

        session = WinHttpOpen(L"RawrXD-AgentOllamaClient/1.0",
                              WINHTTP_ACCESS_TYPE_NO_PROXY,
                              WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!session) { r.error = "WinHttpOpen failed"; return r; }

        int t = timeoutMs > 0 ? timeoutMs : 30000;
        WinHttpSetOption(session, WINHTTP_OPTION_CONNECT_TIMEOUT, &t, sizeof(t));
        WinHttpSetOption(session, WINHTTP_OPTION_SEND_TIMEOUT,     &t, sizeof(t));
        WinHttpSetOption(session, WINHTTP_OPTION_RECEIVE_TIMEOUT,  &t, sizeof(t));

        connect = WinHttpConnect(session, whost.c_str(), (INTERNET_PORT)port, 0);
        if (!connect) { r.error = "WinHttpConnect failed"; return r; }

        request = WinHttpOpenRequest(connect, wmethod.c_str(), wpath.c_str(),
                                     nullptr, WINHTTP_NO_REFERER,
                                     WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
        if (!request) { r.error = "WinHttpOpenRequest failed"; return r; }

        if (!bodyJson.empty()) {
            std::wstring hdr = L"Content-Type: application/json\r\n";
            WinHttpAddRequestHeaders(request, hdr.c_str(), (DWORD)-1,
                                     WINHTTP_ADDREQ_FLAG_ADD);
        }

        const BOOL sent = WinHttpSendRequest(
            request,
            WINHTTP_NO_ADDITIONAL_HEADERS, 0,
            bodyJson.empty() ? WINHTTP_NO_REQUEST_DATA : (LPVOID)bodyJson.c_str(),
            (DWORD)bodyJson.size(), (DWORD)bodyJson.size(), 0);
        if (!sent) { r.error = "WinHttpSendRequest failed"; return r; }

        if (!WinHttpReceiveResponse(request, nullptr)) {
            r.error = "WinHttpReceiveResponse failed";
            return r;
        }

        DWORD status = 0, size = sizeof(status);
        WinHttpQueryHeaders(request,
                            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX,
                            &status, &size, WINHTTP_NO_HEADER_INDEX);
        r.status = (long)status;

        std::string out;
        DWORD avail = 0;
        for (;;) {
            if (!WinHttpQueryDataAvailable(request, &avail)) break;
            if (avail == 0) break;
            std::vector<char> buf(avail);
            DWORD read = 0;
            if (!WinHttpReadData(request, buf.data(), avail, &read)) break;
            if (read == 0) break;
            out.append(buf.data(), read);
        }
        r.body = out;
        r.ok = (r.status >= 200 && r.status < 300);
        return r;
    } catch (...) {
        r.error = "HttpCall exception";
        return r;
    }
}

inline void CloseHandles(HINTERNET s, HINTERNET c, HINTERNET q) {
    if (q) WinHttpCloseHandle(q);
    if (c) WinHttpCloseHandle(c);
    if (s) WinHttpCloseHandle(s);
}

} // namespace

AgentOllamaClient::AgentOllamaClient(const OllamaConfig& config)
    : config_(config) {}

AgentOllamaClient::~AgentOllamaClient() {
    if (m_streaming) CancelStream();
}

void AgentOllamaClient::CancelStream() {
    m_streaming = false;
}

bool AgentOllamaClient::TestConnection() {
    HINTERNET session = nullptr, connect = nullptr, request = nullptr;
    bool connected = false;
    try {
        std::wstring whost(config_.host.begin(), config_.host.end());
        session = WinHttpOpen(L"RawrXD-AgentOllamaClient/1.0",
                              WINHTTP_ACCESS_TYPE_NO_PROXY,
                              WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!session) goto done;
        int t = config_.timeoutMs > 0 ? config_.timeoutMs : 30000;
        WinHttpSetOption(session, WINHTTP_OPTION_CONNECT_TIMEOUT, &t, sizeof(t));
        connect = WinHttpConnect(session, whost.c_str(),
                                 (INTERNET_PORT)config_.port, 0);
        if (!connect) goto done;
        request = WinHttpOpenRequest(connect, L"GET", L"/api/tags",
                                     nullptr, WINHTTP_NO_REFERER,
                                     WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
        if (!request) goto done;
        if (!WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) goto done;
        if (!WinHttpReceiveResponse(request, nullptr)) goto done;
        DWORD status = 0, size = sizeof(status);
        if (WinHttpQueryHeaders(request,
                WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                WINHTTP_HEADER_NAME_BY_INDEX, &status, &size,
                WINHTTP_NO_HEADER_INDEX)) {
            connected = (status >= 200 && status < 300);
        }
    } catch (...) {
        connected = false;
    }
done:
    if (request)  WinHttpCloseHandle(request);
    if (connect)  WinHttpCloseHandle(connect);
    if (session)  WinHttpCloseHandle(session);
    m_connected = connected;
    return connected;
}

std::vector<std::string> AgentOllamaClient::ListModels() {
    std::vector<std::string> models;
    HttpResult r = HttpCall(config_.host, config_.port, "GET", "/api/tags",
                            "", config_.timeoutMs);
    if (!r.ok) return models;
    try {
        auto j = nlohmann::json::parse(r.body, nullptr, false);
        if (j.is_discarded() || !j.contains("models") || !j["models"].is_array())
            return models;
        for (const auto& m : j["models"]) {
            if (m.contains("name") && m["name"].is_string())
                models.push_back(m["name"].get<std::string>());
            else if (m.contains("model") && m["model"].is_string())
                models.push_back(m["model"].get<std::string>());
        }
    } catch (...) {
        // Fail-closed: empty list on any parse problem.
    }
    return models;
}

InferenceResult AgentOllamaClient::ChatSync(
    const std::vector<ChatMessage>& messages, const nlohmann::json& options) {

    InferenceResult out;
    try {
        nlohmann::json req;
        req["model"]    = options.value("model", config_.defaultModel);
        req["messages"] = nlohmann::json::array();
        for (const auto& m : messages) {
            nlohmann::json mj;
            mj["role"]    = m.role;
            mj["content"] = m.content;
            if (!m.name.empty()) mj["name"] = m.name;
            req["messages"].push_back(mj);
        }
        req["stream"] = false;  // ChatSync is synchronous by contract.

        nlohmann::json opts;
        if (options.contains("temperature"))
            opts["temperature"] = options["temperature"];
        if (options.contains("max_tokens"))
            opts["num_predict"] = options["max_tokens"];  // Ollama option name.
        if (options.contains("top_p")) opts["top_p"] = options["top_p"];
        if (options.contains("top_k")) opts["top_k"] = options["top_k"];
        if (!opts.empty()) req["options"] = opts;

        HttpResult r = HttpCall(config_.host, config_.port, "POST",
                                "/api/chat", req.dump(), config_.timeoutMs);
        if (!r.ok) {
            out.error = "Ollama HTTP " + std::to_string(r.status) +
                        (r.error.empty() ? "" : (": " + r.error));
            return out;
        }

        auto j = nlohmann::json::parse(r.body, nullptr, false);
        if (j.is_discarded()) { out.error = "Ollama: unparseable response"; return out; }

        if (j.contains("message") && j["message"].contains("content") &&
            j["message"]["content"].is_string()) {
            out.content = j["message"]["content"].get<std::string>();
        } else if (j.contains("error") && j["error"].is_string()) {
            out.error = j["error"].get<std::string>();
            return out;
        } else {
            out.error = "Ollama: missing message.content";
            return out;
        }

        if (j.contains("eval_count") && j["eval_count"].is_number())
            out.tokensGenerated = j["eval_count"].get<uint64_t>();
        if (j.contains("prompt_eval_count") && j["prompt_eval_count"].is_number())
            out.tokensPrompt = j["prompt_eval_count"].get<uint64_t>();

        out.success = true;
        return out;
    } catch (const std::exception& e) {
        out.error = std::string("Ollama exception: ") + e.what();
        return out;
    } catch (...) {
        out.error = "Ollama unknown exception";
        return out;
    }
}

} // namespace Agent
} // namespace RawrXD
