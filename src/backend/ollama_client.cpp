// =============================================================================
// ollama_client.cpp — WinHTTP-based Ollama API Client (Implementation)
// =============================================================================
// Speaks Ollama's documented local HTTP API. See ollama_client.h for the
// contract this implementation upholds (escaped JSON bodies, numeric options,
// real NDJSON streaming, endpoint-driven routing, status-code checking).
// =============================================================================
#include "backend/ollama_client.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")
#endif

using json = nlohmann::json;

namespace RawrXD {
namespace Backend {

namespace {

// ---------------------------------------------------------------------------
// Endpoint parsing: "http://host:port" -> host/port/secure
// ---------------------------------------------------------------------------
struct Endpoint {
    std::wstring host = L"127.0.0.1";
    int  port   = 11434;
    bool secure = false;
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
    if (slash != std::string::npos) url = url.substr(0, slash);
    const size_t at = url.find('@');
    if (at != std::string::npos) url = url.substr(at + 1);

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

std::string Narrow(const std::wstring& s) {
    if (s.empty()) return {};
    const int n = WideCharToMultiByte(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()),
                                       nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string out(static_cast<size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), out.data(), n,
                        nullptr, nullptr);
    return out;
}

// Extract the server's own error message from a response body, if present.
std::string ExtractErrorField(const std::string& body) {
    try {
        const json j = json::parse(body);
        if (j.is_object() && j.contains("error") && j["error"].is_string()) {
            return j["error"].get<std::string>();
        }
    } catch (const std::exception&) {
        // Not JSON: fall through to the raw body.
    }
    return {};
}

} // namespace

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------
OllamaClient::OllamaClient(const std::string& base_url)
    : m_base_url(base_url.empty() ? "http://127.0.0.1:11434" : base_url),
      m_timeout_seconds(300) {
}

OllamaClient::~OllamaClient() = default;

void OllamaClient::setBaseUrl(const std::string& url) {
    if (!url.empty()) m_base_url = url;
}

void OllamaClient::cancel() {
    m_cancelled.store(true);
}

// ---------------------------------------------------------------------------
// Connection
// ---------------------------------------------------------------------------
bool OllamaClient::testConnection() {
    return !getVersion().empty();
}

std::string OllamaClient::getVersion() {
    const std::string response = makeGetRequest("/api/version");
    try {
        const json j = json::parse(response);
        return j.value("version", std::string());
    } catch (const json::exception&) {
        return "";
    }
}

bool OllamaClient::isRunning() {
    return testConnection();
}

// ---------------------------------------------------------------------------
// Model discovery
// ---------------------------------------------------------------------------
std::vector<OllamaModel> OllamaClient::listModels() {
    const std::string response = makeGetRequest("/api/tags");
    return parseModels(response);
}

bool OllamaClient::showModel(const std::string& model, OllamaShowResult& out) {
    out = OllamaShowResult();
    if (model.empty()) {
        out.error = "empty model name";
        return false;
    }
    const std::string body = json({{"model", model}}).dump();
    const std::string response = makePostRequest("/api/show", body);
    if (response.empty()) {
        out.error = m_last_error.empty() ? "no response from /api/show" : m_last_error;
        return false;
    }
    try {
        const json j = json::parse(response);
        if (j.contains("error")) {
            out.error = j["error"].is_string() ? j["error"].get<std::string>()
                                               : j["error"].dump();
            return false;
        }
        out.ok = true;
        out.license = j.value("license", std::string());
        out.modelfile = j.value("modelfile", std::string());
        out.parameters = j.value("parameters", std::string());
        out.template_text = j.value("template", std::string());
        out.system = j.value("system", std::string());
        if (j.contains("details")) out.details = j["details"];
        if (j.contains("model_info")) out.model_info = j["model_info"];
        if (j.contains("capabilities")) out.capabilities = j["capabilities"];
        if (j.contains("modified_at") && j["modified_at"].is_array()) {
            for (const auto& t : j["modified_at"]) {
                if (t.is_string()) out.modified_at.push_back(t.get<std::string>());
            }
        }
        return true;
    } catch (const json::exception& e) {
        out.error = std::string("invalid /api/show payload: ") + e.what();
        return false;
    }
}

bool OllamaClient::unloadModel(const std::string& model) {
    if (model.empty()) return false;
    // keep_alive = 0 tells the server to release the model immediately.
    const std::string body = json({{"model", model}, {"keep_alive", 0}}).dump();
    const std::string response = makePostRequest("/api/generate", body);
    return !m_last_error.empty() ? false : true;
}

std::vector<OllamaRunningModel> OllamaClient::listRunning() {
    std::vector<OllamaRunningModel> out;
    const std::string response = makeGetRequest("/api/ps");
    if (response.empty()) return out;
    try {
        const json j = json::parse(response);
        if (!j.contains("models") || !j["models"].is_array()) return out;
        for (const auto& m : j["models"]) {
            OllamaRunningModel r;
            r.name = m.value("name", std::string());
            r.model = m.value("model", std::string());
            r.size = m.value("size", uint64_t(0));
            r.vram = m.value("size_vram", uint64_t(0));
            r.digest = m.value("digest", std::string());
            if (m.contains("details")) {
                const auto& d = m["details"];
                r.family = d.value("family", std::string());
                r.parameter_size = d.value("parameter_size", std::string());
                r.quantization_level = d.value("quantization_level", std::string());
            }
            if (m.contains("expires_at")) {
                // "expires_at" is an RFC3339 timestamp; report the remaining
                // seconds relative to now when it can be parsed.
                const std::string expires = m["expires_at"].is_string()
                                                ? m["expires_at"].get<std::string>() : "";
                if (!expires.empty()) {
                    // Minimal RFC3339 -> epoch seconds conversion (UTC only).
                    int y = 0, mo = 0, d = 0, h = 0, mi = 0, se = 0;
                    if (std::sscanf(expires.c_str(), "%4d-%2d-%2dT%2d:%2d:%2d",
                                    &y, &mo, &d, &h, &mi, &se) == 6) {
                        // Days from civil (Howard Hinnant's algorithm).
                        auto days_from_civil = [](int yy, unsigned mm, unsigned dd) -> long long {
                            yy -= mm <= 2;
                            const int era = (yy >= 0 ? yy : yy - 399) / 400;
                            const unsigned yoe = static_cast<unsigned>(yy - era * 400);
                            const unsigned doy = (153 * (mm + (mm > 2 ? -3 : 9)) + 2) / 5 + dd - 1;
                            const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
                            return static_cast<long long>(era) * 146097 +
                                   static_cast<long long>(doe) - 719468;
                        };
                        const long long epoch = days_from_civil(y, static_cast<unsigned>(mo),
                                                              static_cast<unsigned>(d)) * 86400LL +
                                                h * 3600LL + mi * 60LL + se;
                        const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                            std::chrono::system_clock::now().time_since_epoch()).count();
                        r.expires_in_seconds = static_cast<double>(epoch - now);
                    }
                }
            }
            out.push_back(r);
        }
    } catch (const json::exception&) {
        return out;
    }
    return out;
}

// ---------------------------------------------------------------------------
// Generate
// ---------------------------------------------------------------------------
OllamaResponse OllamaClient::generateSync(const OllamaGenerateRequest& request) {
    OllamaGenerateRequest sync_req = request;
    sync_req.stream = false;
    const std::string body = createGenerateRequestJson(sync_req);
    const std::string response = makePostRequest("/api/generate", body);
    return parseResponse(response);
}

OllamaResponse OllamaClient::chatSync(const OllamaChatRequest& request) {
    OllamaChatRequest sync_req = request;
    sync_req.stream = false;
    const std::string body = createChatRequestJson(sync_req);
    const std::string response = makePostRequest("/api/chat", body);
    return parseResponse(response);
}

bool OllamaClient::generate(const OllamaGenerateRequest& request,
                            StreamCallback on_chunk,
                            ErrorCallback on_error,
                            CompletionCallback on_complete) {
    const std::string body = createGenerateRequestJson(request);
    return makeStreamingPostRequest("/api/generate", body, on_chunk, on_error, on_complete);
}

bool OllamaClient::chat(const OllamaChatRequest& request,
                        StreamCallback on_chunk,
                        ErrorCallback on_error,
                        CompletionCallback on_complete) {
    const std::string body = createChatRequestJson(request);
    return makeStreamingPostRequest("/api/chat", body, on_chunk, on_error, on_complete);
}

// ---------------------------------------------------------------------------
// Embeddings
// ---------------------------------------------------------------------------
std::vector<float> OllamaClient::embeddings(const std::string& model,
                                            const std::string& prompt) {
    std::vector<float> result;
    const std::string body = json({{"model", model}, {"prompt", prompt}}).dump();
    const std::string response = makePostRequest("/api/embeddings", body);
    if (response.empty()) return result;
    try {
        const json j = json::parse(response);
        if (j.contains("embedding") && j["embedding"].is_array()) {
            for (const auto& v : j["embedding"]) {
                if (v.is_number()) result.push_back(v.get<float>());
            }
        } else if (j.contains("embeddings") && j["embeddings"].is_array()) {
            for (const auto& row : j["embeddings"]) {
                if (!row.is_array()) continue;
                for (const auto& v : row) {
                    if (v.is_number()) result.push_back(v.get<float>());
                }
            }
        }
    } catch (const json::exception&) {
        return {};
    }
    return result;
}

// ---------------------------------------------------------------------------
// JSON builders — nlohmann guarantees correct escaping of every string.
// ---------------------------------------------------------------------------
std::string OllamaClient::createGenerateRequestJson(const OllamaGenerateRequest& req) const {
    json j;
    j["model"] = req.model;
    j["prompt"] = req.prompt;
    j["stream"] = req.stream;
    if (req.options.is_object() && !req.options.empty()) j["options"] = req.options;
    if (!req.stop.empty()) j["stop"] = req.stop;
    return j.dump();
}

std::string OllamaClient::createChatRequestJson(const OllamaChatRequest& req) const {
    json j;
    j["model"] = req.model;
    json msgs = json::array();
    for (const auto& m : req.messages) {
        json o;
        o["role"] = m.role;
        o["content"] = m.content;
        if (!m.tool_call_id.empty()) o["tool_call_id"] = m.tool_call_id;
        if (!m.tool_calls.is_null()) o["tool_calls"] = m.tool_calls;
        msgs.push_back(std::move(o));
    }
    j["messages"] = std::move(msgs);
    j["stream"] = req.stream;
    if (req.tools.is_array() && !req.tools.empty()) j["tools"] = req.tools;
    if (req.options.is_object() && !req.options.empty()) j["options"] = req.options;
    if (!req.stop.empty()) j["stop"] = req.stop;
    return j.dump();
}

// ---------------------------------------------------------------------------
// Response parsing
// ---------------------------------------------------------------------------
OllamaResponse OllamaClient::parseResponse(const std::string& json_str) const {
    OllamaResponse resp;
    if (json_str.empty()) {
        resp.error = m_last_error.empty() ? "empty response body" : m_last_error;
        resp.done = true;
        resp.done_reason = "error";
        return resp;
    }
    try {
        const json j = json::parse(json_str);

        resp.model = j.value("model", std::string());
        resp.response = j.value("response", std::string());
        resp.done = j.value("done", false);
        resp.done_reason = j.value("done_reason", std::string());

        if (j.contains("message")) {
            const auto& msg = j["message"];
            if (msg.is_object()) {
                resp.message = msg.value("content", std::string());
                // Reasoning models report their thinking in a separate field.
                // It must not be merged into the answer.
                if (msg.contains("thinking") && msg["thinking"].is_string()) {
                    resp.thinking = msg["thinking"].get<std::string>();
                }
                if (msg.contains("tool_calls")) resp.tool_calls = msg["tool_calls"];
            }
        }
        if (j.contains("error") && j["error"].is_string()) {
            resp.error = j["error"].get<std::string>();
            resp.done = true;
            if (resp.done_reason.empty()) resp.done_reason = "error";
        }

        resp.total_duration = j.value("total_duration", uint64_t(0));
        resp.prompt_eval_count = j.value("prompt_eval_count", uint64_t(0));
        resp.eval_count = j.value("eval_count", uint64_t(0));
        resp.load_duration = j.value("load_duration", uint64_t(0));
        resp.prompt_eval_duration = j.value("prompt_eval_duration", uint64_t(0));
        resp.eval_duration = j.value("eval_duration", uint64_t(0));
    } catch (const json::exception& e) {
        resp.error = std::string("invalid JSON payload: ") + e.what();
        resp.done = true;
        resp.done_reason = "error";
    }
    return resp;
}

std::vector<OllamaModel> OllamaClient::parseModels(const std::string& json_str) const {
    std::vector<OllamaModel> models;
    if (json_str.empty()) return models;
    try {
        const json j = json::parse(json_str);
        if (j.contains("models") && j["models"].is_array()) {
            for (const auto& mj : j["models"]) {
                OllamaModel model;
                model.name = mj.value("name", std::string());
                model.modified_at = mj.value("modified_at", std::string());
                model.size = mj.value("size", uint64_t(0));
                model.digest = mj.value("digest", std::string());
                model.remote_host = mj.value("remote_host", std::string());
                model.remote_model = mj.value("remote_model", std::string());
                if (mj.contains("capabilities") && mj["capabilities"].is_array()) {
                    for (const auto& c : mj["capabilities"]) {
                        if (c.is_string()) model.capabilities.push_back(c.get<std::string>());
                    }
                }
                if (mj.contains("details")) {
                    const auto& details = mj["details"];
                    model.format = details.value("format", std::string());
                    model.family = details.value("family", std::string());
                    model.parameter_size = details.value("parameter_size", std::string());
                    model.quantization_level = details.value("quantization_level", std::string());
                    model.context_length = details.value("context_length", uint64_t(0));
                }
                models.push_back(model);
            }
        }
    } catch (const json::exception&) {
        return models;
    }
    return models;
}

// ---------------------------------------------------------------------------
// HTTP transport
// ---------------------------------------------------------------------------
#ifdef _WIN32

namespace {

DWORD QueryStatusCode(HINTERNET request) {
    DWORD status = 0;
    DWORD size = sizeof(status);
    DWORD index = 0;
    if (!WinHttpQueryHeaders(request,
                             WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                             WINHTTP_HEADER_NAME_BY_INDEX,
                             &status, &size, &index)) {
        return 0;
    }
    return status;
}

} // namespace

std::string OllamaClient::makeGetRequest(const std::string& endpoint) {
    return httpRequest("GET", endpoint, nullptr);
}

std::string OllamaClient::makePostRequest(const std::string& endpoint,
                                          const std::string& json_body) {
    return httpRequest("POST", endpoint, &json_body);
}

std::string OllamaClient::httpRequest(const std::string& method,
                                       const std::string& endpoint,
                                       const std::string* body) {
    const Endpoint ep = ParseEndpoint(m_base_url);
    const std::wstring wmethod = Widen(method);
    const std::wstring wpath = Widen(endpoint);

    HINTERNET hSession = WinHttpOpen(L"RawrXD/1.0",
                                     WINHTTP_ACCESS_TYPE_NO_PROXY,
                                     WINHTTP_NO_PROXY_NAME,
                                     WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        m_last_error = "WinHttpOpen failed";
        return "";
    }

    HINTERNET hConnect = WinHttpConnect(hSession, ep.host.c_str(),
                                        static_cast<INTERNET_PORT>(ep.port), 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        m_last_error = "cannot connect to Ollama at " + m_base_url;
        return "";
    }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, wmethod.c_str(), wpath.c_str(),
                                             NULL, WINHTTP_NO_REFERER,
                                             WINHTTP_DEFAULT_ACCEPT_TYPES,
                                             ep.secure ? WINHTTP_FLAG_SECURE : 0);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        m_last_error = "WinHttpOpenRequest failed";
        return "";
    }

    const int timeout_ms = std::max(1, m_timeout_seconds) * 1000;
    WinHttpSetTimeouts(hRequest, 5000, 5000, 30000, timeout_ms);

    std::wstring headers = L"Accept: application/json\r\n";
    if (body) headers += L"Content-Type: application/json\r\n";

    bool sent = false;
    if (body) {
        sent = WinHttpSendRequest(hRequest, headers.c_str(), -1,
                                   const_cast<char*>(body->data()),
                                   static_cast<DWORD>(body->size()),
                                   static_cast<DWORD>(body->size()), 0) != FALSE;
    } else {
        sent = WinHttpSendRequest(hRequest, headers.c_str(), -1,
                                   WINHTTP_NO_REQUEST_DATA, 0, 0, 0) != FALSE;
    }

    std::string response;
    if (!sent) {
        m_last_error = "WinHttpSendRequest failed";
    } else if (!WinHttpReceiveResponse(hRequest, nullptr)) {
        m_last_error = "WinHttpReceiveResponse failed";
    } else {
        const DWORD status = QueryStatusCode(hRequest);
        for (;;) {
            DWORD avail = 0;
            if (!WinHttpQueryDataAvailable(hRequest, &avail)) break;
            if (avail == 0) break;
            std::vector<char> buf(avail);
            DWORD got = 0;
            if (!WinHttpReadData(hRequest, buf.data(), avail, &got) || got == 0) break;
            response.append(buf.data(), got);
        }
        if (status >= 400) {
            const std::string serverError = ExtractErrorField(response);
            m_last_error = serverError.empty()
                ? ("Ollama returned HTTP " + std::to_string(status))
                : ("Ollama returned HTTP " + std::to_string(status) + ": " + serverError);
            return "";
        }
        if (status == 0) {
            m_last_error = "no HTTP status from Ollama";
            return "";
        }
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return response;
}

bool OllamaClient::makeStreamingPostRequest(const std::string& endpoint,
                                            const std::string& json_body,
                                            StreamCallback on_chunk,
                                            ErrorCallback on_error,
                                            CompletionCallback on_complete) {
    const Endpoint ep = ParseEndpoint(m_base_url);
    const std::wstring wmethod = L"POST";
    const std::wstring wpath = Widen(endpoint);

    HINTERNET hSession = WinHttpOpen(L"RawrXD/1.0",
                                     WINHTTP_ACCESS_TYPE_NO_PROXY,
                                     WINHTTP_NO_PROXY_NAME,
                                     WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        m_last_error = "WinHttpOpen failed";
        if (on_error) on_error(m_last_error);
        return false;
    }

    HINTERNET hConnect = WinHttpConnect(hSession, ep.host.c_str(), static_cast<INTERNET_PORT>(ep.port), 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        m_last_error = "cannot connect to Ollama at " + m_base_url;
        if (on_error) on_error(m_last_error);
        return false;
    }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, wmethod.c_str(), wpath.c_str(),
                                             NULL, WINHTTP_NO_REFERER,
                                             WINHTTP_DEFAULT_ACCEPT_TYPES,
                                             ep.secure ? WINHTTP_FLAG_SECURE : 0);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        m_last_error = "WinHttpOpenRequest failed";
        if (on_error) on_error(m_last_error);
        return false;
    }

    // The initial response must be allowed the FULL timeout: a cold model can
    // take a long time before the first byte. The short poll timeout used
    // during the streaming phase is installed afterwards, once the response
    // headers have arrived.
    const int timeout_ms = std::max(1, m_timeout_seconds) * 1000;
    WinHttpSetTimeouts(hRequest, 5000, 5000, 30000, timeout_ms);

    const std::wstring headers = L"Content-Type: application/json\r\nAccept: application/x-ndjson\r\n";

    bool ok = false;
    std::string error_text;

    if (!WinHttpSendRequest(hRequest, headers.c_str(), -1,
                            const_cast<char*>(json_body.data()),
                            static_cast<DWORD>(json_body.size()),
                            static_cast<DWORD>(json_body.size()), 0)) {
        error_text = "WinHttpSendRequest failed";
    } else if (!WinHttpReceiveResponse(hRequest, nullptr)) {
        error_text = "WinHttpReceiveResponse failed";
    } else {
        const DWORD status = QueryStatusCode(hRequest);
        if (status >= 400) {
            // Read the error body so the caller sees the server's message.
            std::string errBody;
            for (;;) {
                DWORD avail = 0;
                if (!WinHttpQueryDataAvailable(hRequest, &avail) || avail == 0) break;
                std::vector<char> buf(avail);
                DWORD got = 0;
                if (!WinHttpReadData(hRequest, buf.data(), avail, &got) || got == 0) break;
                errBody.append(buf.data(), got);
            }
            const std::string serverError = ExtractErrorField(errBody);
            error_text = serverError.empty()
                ? ("Ollama returned HTTP " + std::to_string(status))
                : ("Ollama returned HTTP " + std::to_string(status) + ": " + serverError);
        } else {
            ok = true;
            // From here on, poll in short slices so a cancellation is noticed
            // within about a second instead of at the end of the generation.
            WinHttpSetTimeouts(hRequest, 5000, 5000, 30000, 1000);
        }
    }

    if (!ok) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        m_last_error = error_text;
        if (on_error) on_error(error_text);
        return false;
    }

    // ---- Consume the NDJSON stream incrementally ----
    std::string pending;
    std::string full_text;
    uint64_t ptok = 0, ctok = 0;
    bool saw_done = false;
    bool stream_error = false;
    std::string stream_error_text;
    const auto idle_deadline = std::chrono::steady_clock::now() +
                               std::chrono::seconds(std::max(1, m_timeout_seconds));

    auto handle_line = [&](const std::string& raw_line) {
        std::string line = raw_line;
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) return;
        OllamaResponse resp = parseResponse(line);
        if (!resp.error.empty()) {
            stream_error = true;
            stream_error_text = resp.error;
            return;
        }
        if (!resp.message.empty()) full_text += resp.message;
        if (!resp.response.empty()) full_text += resp.response;
        if (resp.prompt_eval_count) ptok = resp.prompt_eval_count;
        if (resp.eval_count) ctok = resp.eval_count;
        if (on_chunk) on_chunk(resp);
        if (resp.done) saw_done = true;
    };

    for (;;) {
        if (m_cancelled.load()) {
            stream_error = true;
            stream_error_text = "cancelled";
            break;
        }

        DWORD avail = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &avail)) {
            const DWORD err = GetLastError();
            if (err == ERROR_WINHTTP_TIMEOUT) {
                if (std::chrono::steady_clock::now() > idle_deadline) {
                    stream_error = true;
                    stream_error_text = "Ollama stream idle timeout";
                    break;
                }
                continue;
            }
            stream_error = true;
            stream_error_text = "WinHttpQueryDataAvailable failed (" + std::to_string(err) + ")";
            break;
        }
        if (avail == 0) break;   // end of body

        std::vector<char> buf(avail);
        DWORD got = 0;
        if (!WinHttpReadData(hRequest, buf.data(), avail, &got)) {
            const DWORD err = GetLastError();
            if (err == ERROR_WINHTTP_TIMEOUT) continue;
            stream_error = true;
            stream_error_text = "WinHttpReadData failed (" + std::to_string(err) + ")";
            break;
        }
        if (got == 0) break;
        pending.append(buf.data(), got);

        size_t pos = 0;
        for (;;) {
            if (m_cancelled.load()) {
                stream_error = true;
                stream_error_text = "cancelled";
                break;
            }
            const size_t nl = pending.find('\n', pos);
            if (nl == std::string::npos) break;
            handle_line(pending.substr(pos, nl - pos));
            pos = nl + 1;
        }
        if (pos) pending.erase(0, pos);
        if (stream_error) break;
    }

    if (!pending.empty() && !stream_error) handle_line(pending);

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    if (stream_error) {
        m_last_error = stream_error_text;
        if (on_error) on_error(stream_error_text);
        return false;
    }

    OllamaResponse final;
    final.model = m_base_url;
    final.done = true;
    final.done_reason = saw_done ? "stop" : "eof";
    final.prompt_eval_count = ptok;
    final.eval_count = ctok;
    final.response = full_text;
    final.message = full_text;
    if (on_complete) on_complete(final);
    return true;
}

#else
// Non-Windows builds are not part of the certified path; the Ollama provider
// is Windows-only (WinHTTP). Report the limitation honestly instead of
// silently pretending a request succeeded.
std::string OllamaClient::makeGetRequest(const std::string&) {
    m_last_error = "Ollama HTTP transport requires WinHTTP (Windows only)";
    return "";
}

std::string OllamaClient::makePostRequest(const std::string&, const std::string&) {
    m_last_error = "Ollama HTTP transport requires WinHTTP (Windows only)";
    return "";
}

std::string OllamaClient::httpRequest(const std::string&, const std::string&,
                                       const std::string*) {
    m_last_error = "Ollama HTTP transport requires WinHTTP (Windows only)";
    return "";
}

bool OllamaClient::makeStreamingPostRequest(const std::string&,
                                            const std::string&,
                                            StreamCallback,
                                            ErrorCallback on_error,
                                            CompletionCallback) {
    m_last_error = "Ollama HTTP transport requires WinHTTP (Windows only)";
    if (on_error) on_error(m_last_error);
    return false;
}
#endif

// ---------------------------------------------------------------------------
// Response factories
// ---------------------------------------------------------------------------
OllamaResponse OllamaResponse::Ok(const std::string& text, uint64_t ptok, uint64_t ctok) {
    OllamaResponse r;
    r.model = "ollama";
    r.response = text;
    r.message = text;
    r.done = true;
    r.done_reason = "stop";
    r.prompt_eval_count = ptok;
    r.eval_count = ctok;
    return r;
}

OllamaResponse OllamaResponse::Error(const std::string& msg) {
    OllamaResponse r;
    r.done = true;
    r.done_reason = "error";
    r.error = msg;
    r.response = "[ERROR] " + msg;
    return r;
}

} // namespace Backend
} // namespace RawrXD
