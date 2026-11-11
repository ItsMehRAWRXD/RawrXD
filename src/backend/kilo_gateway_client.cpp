// =============================================================================
// kilo_gateway_client.cpp — Kilo Gateway Client implementation
// =============================================================================
#include "backend/kilo_gateway_client.h"

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <sstream>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")
#endif

namespace RawrXD {
namespace Backend {

namespace {

struct Endpoint {
    std::wstring host;
    int  port = 443;
    bool secure = true;
    // The Kilo base URL carries a path prefix ("/api/v1"). Unlike the Ollama
    // base, it must be preserved: the request path is appended to it.
    std::wstring base_path;
};

Endpoint ParseEndpoint(const std::string& base) {
    Endpoint ep;
    std::string url = base;
    if (url.empty()) return ep;
    const size_t scheme = url.find("://");
    if (scheme != std::string::npos) {
        ep.secure = (url.substr(0, scheme) == "https");
        url = url.substr(scheme + 3);
    }
    const size_t slash = url.find('/');
    if (slash != std::string::npos) {
        // One temporary: iterators from two different temporaries would be
        // undefined behaviour.
        const std::string prefix = url.substr(slash);
        ep.base_path = std::wstring(prefix.begin(), prefix.end());
        url = url.substr(0, slash);
    }
    const size_t colon = url.find(':');
    if (colon != std::string::npos) {
        const int parsed = std::atoi(url.substr(colon + 1).c_str());
        if (parsed > 0 && parsed < 65536) ep.port = parsed;
        url = url.substr(0, colon);
    }
    if (!url.empty()) ep.host = std::wstring(url.begin(), url.end());
    return ep;
}

std::wstring Widen(const std::string& s) {
    if (s.empty()) return {};
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()),
                                       nullptr, 0);
    if (n <= 0) return std::wstring(s.begin(), s.end());
    std::wstring out(static_cast<size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), out.data(), n);
    return out;
}

std::string ExtractError(const std::string& body) {
    try {
        const json j = json::parse(body);
        if (j.is_object()) {
            if (j.contains("error")) {
                if (j["error"].is_string()) return j["error"].get<std::string>();
                if (j["error"].is_object() && j["error"].contains("message")) {
                    return j["error"]["message"].get<std::string>();
                }
            }
            if (j.contains("message") && j["message"].is_string()) {
                return j["message"].get<std::string>();
            }
        }
    } catch (const std::exception&) {
        // Not JSON.
    }
    return {};
}

} // namespace

KiloGatewayClient::KiloGatewayClient(const std::string& base_url)
    : m_base_url(base_url.empty() ? "https://ai-gateway.kilo.ai/api/v1" : base_url) {
    const char* env = std::getenv("KILO_API_KEY");
    if (env && env[0] != '\0') m_api_key = env;
}

KiloGatewayClient::~KiloGatewayClient() = default;

bool KiloGatewayClient::hasApiKey() const {
    return !m_api_key.empty();
}

std::string KiloGatewayClient::DefaultModel() {
    const char* env = std::getenv("KILO_MODEL");
    if (env && env[0] != '\0') return env;
    return "kilo-auto/free";
}

// ---------------------------------------------------------------------------
// HTTP transport
// ---------------------------------------------------------------------------
#ifdef _WIN32
bool KiloGatewayClient::httpRequest(const std::string& method, const std::string& path,
                                    const std::string* body, std::string& out_body,
                                    std::string& out_error) {
    out_body.clear();
    out_error.clear();

    const Endpoint ep = ParseEndpoint(m_base_url);
    HINTERNET hSession = WinHttpOpen(L"RawrXD/1.0",
                                     WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                     WINHTTP_NO_PROXY_NAME,
                                     WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        out_error = "WinHttpOpen failed";
        return false;
    }
    HINTERNET hConnect = WinHttpConnect(hSession, ep.host.c_str(),
                                        static_cast<INTERNET_PORT>(ep.port), 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        out_error = "cannot connect to " + m_base_url;
        return false;
    }
    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect, Widen(method).c_str(), (ep.base_path + Widen(path)).c_str(), NULL,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
        ep.secure ? WINHTTP_FLAG_SECURE : 0);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        out_error = "WinHttpOpenRequest failed";
        return false;
    }

    const int timeout_ms = std::max(1, m_timeout_seconds) * 1000;
    WinHttpSetTimeouts(hRequest, 10000, 15000, 30000, timeout_ms);

    // The bearer token is sent in the header only. It is never written to
    // stdout, stderr, a receipt or an error message.
    std::wstring headers = L"Accept: application/json\r\n";
    if (!m_api_key.empty()) {
        headers += L"Authorization: Bearer " + Widen(m_api_key) + L"\r\n";
    }
    if (body) headers += L"Content-Type: application/json\r\n";

    bool ok = false;
    if (body) {
        ok = WinHttpSendRequest(hRequest, headers.c_str(), -1,
                                const_cast<char*>(body->data()),
                                static_cast<DWORD>(body->size()),
                                static_cast<DWORD>(body->size()), 0) != FALSE;
    } else {
        ok = WinHttpSendRequest(hRequest, headers.c_str(), -1,
                                WINHTTP_NO_REQUEST_DATA, 0, 0, 0) != FALSE;
    }

    DWORD status = 0;
    if (!ok) {
        out_error = "WinHttpSendRequest failed";
    } else if (!WinHttpReceiveResponse(hRequest, nullptr)) {
        out_error = "WinHttpReceiveResponse failed";
    } else {
        DWORD size = sizeof(status);
        DWORD index = 0;
        WinHttpQueryHeaders(hRequest,
                            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &status, &size, &index);
        for (;;) {
            DWORD avail = 0;
            if (!WinHttpQueryDataAvailable(hRequest, &avail) || avail == 0) break;
            std::vector<char> buf(avail);
            DWORD got = 0;
            if (!WinHttpReadData(hRequest, buf.data(), avail, &got) || got == 0) break;
            out_body.append(buf.data(), got);
        }
        if (status >= 400) {
            const std::string serverError = ExtractError(out_body);
            out_error = serverError.empty()
                ? ("gateway returned HTTP " + std::to_string(status))
                : ("gateway returned HTTP " + std::to_string(status) + ": " + serverError);
        } else if (status == 0) {
            out_error = "no HTTP status from gateway";
        } else {
            out_error.clear();
        }
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return out_error.empty();
}
#else
bool KiloGatewayClient::httpRequest(const std::string&, const std::string&,
                                    const std::string*, std::string&,
                                    std::string& out_error) {
    out_error = "Kilo Gateway transport requires WinHTTP (Windows only)";
    return false;
}
#endif

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------
bool KiloGatewayClient::testConnection() {
    if (!hasApiKey()) {
        m_last_error = "no API key: set KILO_API_KEY (or pass one explicitly)";
        return false;
    }
    std::string body, error;
    if (!httpRequest("GET", "/models", nullptr, body, error)) {
        m_last_error = error;
        return false;
    }
    m_last_error.clear();
    return true;
}

std::vector<KiloModel> KiloGatewayClient::listModels() {
    std::vector<KiloModel> out;
    if (!hasApiKey()) {
        m_last_error = "no API key: set KILO_API_KEY (or pass one explicitly)";
        return out;
    }
    std::string body, error;
    if (!httpRequest("GET", "/models", nullptr, body, error)) {
        m_last_error = error;
        return out;
    }
    m_last_error.clear();
    try {
        const json j = json::parse(body);
        const json* arr = nullptr;
        if (j.is_array()) {
            arr = &j;
        } else if (j.contains("data") && j["data"].is_array()) {
            arr = &j["data"];
        } else if (j.contains("models") && j["models"].is_array()) {
            arr = &j["models"];
        }
        if (!arr) return out;
        for (const auto& m : *arr) {
            KiloModel km;
            km.id = m.value("id", m.value("name", std::string()));
            km.name = m.value("name", km.id);
            km.description = m.value("description", std::string());
            // The gateway reports prices as STRINGS ("0.00000015"). A model is
            // free when both prices are zero, or when the id carries the
            // ":free" suffix, or when the explicit flag says so.
            auto priceIsZero = [](const json& pricing, const char* key) -> bool {
                if (!pricing.contains(key)) return true;
                const json& v = pricing[key];
                if (v.is_number()) return v.get<double>() == 0.0;
                if (v.is_string()) {
                    try { return std::stod(v.get<std::string>()) == 0.0; }
                    catch (...) { return true; }
                }
                return true;
            };
            if (m.contains("pricing") && m["pricing"].is_object()) {
                const auto& p = m["pricing"];
                km.is_free = priceIsZero(p, "prompt") && priceIsZero(p, "completion");
            }
            if (m.contains("isFree") && m["isFree"].is_boolean()) {
                km.is_free = m["isFree"].get<bool>();
            }
            if (m.contains("is_free") && m["is_free"].is_boolean()) {
                km.is_free = m["is_free"].get<bool>();
            }
            if (km.id.size() > 5 &&
                km.id.compare(km.id.size() - 5, 5, ":free") == 0) {
                km.is_free = true;
            }
            out.push_back(km);
        }
    } catch (const std::exception& e) {
        m_last_error = std::string("invalid catalog payload: ") + e.what();
    }
    return out;
}

KiloResponse KiloGatewayClient::chatSync(
    const std::vector<std::pair<std::string, std::string>>& messages,
    const std::string& model, int max_tokens) {
    KiloResponse result;
    if (!hasApiKey()) {
        result.error = "no API key: set KILO_API_KEY (or pass one explicitly)";
        return result;
    }
    json body;
    body["model"] = model.empty() ? DefaultModel() : model;
    json msgs = json::array();
    for (const auto& m : messages) {
        msgs.push_back(json{{"role", m.first}, {"content", m.second}});
    }
    body["messages"] = std::move(msgs);
    body["stream"] = false;
    if (max_tokens > 0) body["max_tokens"] = max_tokens;

    const auto t0 = std::chrono::steady_clock::now();
    std::string response, error;
    const std::string payload = body.dump();
    if (!httpRequest("POST", "/chat/completions", &payload, response, error)) {
        result.error = error;
        result.total_duration_ms =
            std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
        return result;
    }
    result.total_duration_ms =
        std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
    m_last_error.clear();

    try {
        const json j = json::parse(response);
        if (j.contains("choices") && j["choices"].is_array() && !j["choices"].empty()) {
            const auto& choice = j["choices"][0];
            if (choice.contains("message") && choice["message"].is_object()) {
                const auto& msg = choice["message"];
                result.content = msg.value("content", std::string());
                // Reasoning arrives under one of several names depending on
                // the upstream provider. It never belongs in `content`.
                if (msg.contains("reasoning") && msg["reasoning"].is_string()) {
                    result.reasoning = msg["reasoning"].get<std::string>();
                } else if (msg.contains("reasoning_content") &&
                           msg["reasoning_content"].is_string()) {
                    result.reasoning = msg["reasoning_content"].get<std::string>();
                }
            } else if (choice.contains("text")) {
                result.content = choice.value("text", std::string());
            }
            result.finish_reason = choice.value("finish_reason", std::string());
        }
        if (j.contains("usage") && j["usage"].is_object()) {
            result.prompt_tokens = j["usage"].value("prompt_tokens", uint64_t(0));
            result.completion_tokens = j["usage"].value("completion_tokens", uint64_t(0));
            if (j["usage"].contains("completion_tokens_details") &&
                j["usage"]["completion_tokens_details"].is_object()) {
                result.reasoning_tokens =
                    j["usage"]["completion_tokens_details"].value("reasoning_tokens", uint64_t(0));
            }
        }
        result.success = true;
    } catch (const std::exception& e) {
        result.error = std::string("invalid completion payload: ") + e.what();
    }
    return result;
}

bool KiloGatewayClient::chatStream(
    const std::vector<std::pair<std::string, std::string>>& messages,
    const std::string& model, int max_tokens,
    KiloTokenCallback on_token, KiloDoneCallback on_done, KiloErrorCallback on_error,
    KiloReasoningCallback on_reasoning) {
    if (!hasApiKey()) {
        const std::string err = "no API key: set KILO_API_KEY (or pass one explicitly)";
        m_last_error = err;
        if (on_error) on_error(err);
        return false;
    }

    json body;
    body["model"] = model.empty() ? DefaultModel() : model;
    json msgs = json::array();
    for (const auto& m : messages) {
        msgs.push_back(json{{"role", m.first}, {"content", m.second}});
    }
    body["messages"] = std::move(msgs);
    body["stream"] = true;
    if (max_tokens > 0) body["max_tokens"] = max_tokens;
    const std::string payload = body.dump();

#ifdef _WIN32
    const Endpoint ep = ParseEndpoint(m_base_url);
    HINTERNET hSession = WinHttpOpen(L"RawrXD/1.0",
                                     WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                     WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        m_last_error = "WinHttpOpen failed";
        if (on_error) on_error(m_last_error);
        return false;
    }
    HINTERNET hConnect = WinHttpConnect(hSession, ep.host.c_str(),
                                        static_cast<INTERNET_PORT>(ep.port), 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        m_last_error = "cannot connect to " + m_base_url;
        if (on_error) on_error(m_last_error);
        return false;
    }
    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect, L"POST", (ep.base_path + L"/chat/completions").c_str(), NULL,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
        ep.secure ? WINHTTP_FLAG_SECURE : 0);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        m_last_error = "WinHttpOpenRequest failed";
        if (on_error) on_error(m_last_error);
        return false;
    }

    const int timeout_ms = std::max(1, m_timeout_seconds) * 1000;
    WinHttpSetTimeouts(hRequest, 10000, 15000, 30000, timeout_ms);

    std::wstring headers = L"Authorization: Bearer " + Widen(m_api_key) + L"\r\n";
    headers += L"Content-Type: application/json\r\n";
    headers += L"Accept: text/event-stream\r\n";

    const auto t0 = std::chrono::steady_clock::now();
    if (!WinHttpSendRequest(hRequest, headers.c_str(), -1,
                            const_cast<char*>(payload.data()),
                            static_cast<DWORD>(payload.size()),
                            static_cast<DWORD>(payload.size()), 0) ||
        !WinHttpReceiveResponse(hRequest, nullptr)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        m_last_error = "gateway request failed";
        if (on_error) on_error(m_last_error);
        return false;
    }

    DWORD status = 0;
    {
        DWORD size = sizeof(status), index = 0;
        WinHttpQueryHeaders(hRequest,
                            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &status, &size, &index);
    }
    if (status >= 400) {
        std::string errBody;
        for (;;) {
            DWORD avail = 0;
            if (!WinHttpQueryDataAvailable(hRequest, &avail) || avail == 0) break;
            std::vector<char> buf(avail);
            DWORD got = 0;
            if (!WinHttpReadData(hRequest, buf.data(), avail, &got) || got == 0) break;
            errBody.append(buf.data(), got);
        }
        const std::string serverError = ExtractError(errBody);
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        m_last_error = serverError.empty()
            ? ("gateway returned HTTP " + std::to_string(status))
            : ("gateway returned HTTP " + std::to_string(status) + ": " + serverError);
        if (on_error) on_error(m_last_error);
        return false;
    }

    // Server-sent events: "data: {json}" lines, terminated by "data: [DONE]".
    std::string pending;
    std::string full;
    std::string reasoning;
    uint64_t ptok = 0, ctok = 0, rtok = 0;
    bool done = false;

    auto handleEvent = [&](const std::string& rawLine) {
        std::string line = rawLine;
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.rfind("data:", 0) != 0) return;   // comments, event: lines
        std::string data = line.substr(5);
        while (!data.empty() && (data.front() == ' ')) data.erase(data.begin());
        if (data.empty()) return;
        if (data == "[DONE]") { done = true; return; }
        try {
            const json j = json::parse(data);
            if (j.contains("choices") && j["choices"].is_array() && !j["choices"].empty()) {
                const auto& choice = j["choices"][0];
                std::string delta;
                std::string think;
                if (choice.contains("delta") && choice["delta"].is_object()) {
                    const auto& d = choice["delta"];
                    delta = d.value("content", std::string());
                    // Reasoning is a separate channel: a reasoning model emits
                    // a long thinking stream before the answer, and mixing the
                    // two would corrupt the answer.
                    if (d.contains("reasoning") && d["reasoning"].is_string()) {
                        think = d["reasoning"].get<std::string>();
                    } else if (d.contains("reasoning_content") &&
                               d["reasoning_content"].is_string()) {
                        think = d["reasoning_content"].get<std::string>();
                    }
                } else if (choice.contains("text")) {
                    delta = choice.value("text", std::string());
                }
                if (!think.empty()) {
                    reasoning += think;
                    if (on_reasoning) on_reasoning(think);
                }
                if (!delta.empty()) {
                    full += delta;
                    if (on_token) on_token(delta);
                }
            }
            if (j.contains("usage") && j["usage"].is_object()) {
                ptok = j["usage"].value("prompt_tokens", ptok);
                ctok = j["usage"].value("completion_tokens", ctok);
                if (j["usage"].contains("completion_tokens_details") &&
                    j["usage"]["completion_tokens_details"].is_object()) {
                    rtok = j["usage"]["completion_tokens_details"].value("reasoning_tokens", rtok);
                }
            }
        } catch (const std::exception&) {
            // A malformed event is skipped rather than aborting the stream.
        }
    };

    for (;;) {
        if (m_cancelled.load()) {
            m_last_error = "cancelled";
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            if (on_error) on_error(m_last_error);
            return false;
        }
        DWORD avail = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &avail)) {
            const DWORD err = GetLastError();
            if (err == ERROR_WINHTTP_TIMEOUT) continue;
            m_last_error = "WinHttpQueryDataAvailable failed";
            break;
        }
        if (avail == 0) break;
        std::vector<char> buf(avail);
        DWORD got = 0;
        if (!WinHttpReadData(hRequest, buf.data(), avail, &got) || got == 0) break;
        pending.append(buf.data(), got);

        size_t pos = 0;
        for (;;) {
            const size_t nl = pending.find('\n', pos);
            if (nl == std::string::npos) break;
            handleEvent(pending.substr(pos, nl - pos));
            pos = nl + 1;
        }
        if (pos) pending.erase(0, pos);
        if (done) break;
    }
    if (!pending.empty() && !m_cancelled.load()) handleEvent(pending);

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    if (m_cancelled.load()) return false;
    const double elapsed_ms = std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - t0).count();
    const double tps = (elapsed_ms > 0 && ctok > 0)
        ? (static_cast<double>(ctok) / (elapsed_ms / 1000.0)) : 0.0;
    if (on_done) on_done(full, ptok, ctok, tps);
    return true;
#else
    (void)messages; (void)model; (void)max_tokens;
    (void)on_token; (void)on_done;
    m_last_error = "Kilo Gateway transport requires WinHTTP (Windows only)";
    if (on_error) on_error(m_last_error);
    return false;
#endif
}

} // namespace Backend
} // namespace RawrXD
