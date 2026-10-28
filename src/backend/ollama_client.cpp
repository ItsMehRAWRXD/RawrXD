#include "backend/ollama_client.h"
#include <sstream>
#include <stdexcept>
#include <iostream>
#include <algorithm>
#include <fstream>
#include <cstdlib>
#include <nlohmann/json.hpp>

#ifdef _WIN32
#include <windows.h>
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")
#else
#include <curl/curl.h>
#endif

using json = nlohmann::json;

namespace RawrXD {
namespace Backend {

namespace {
void TraceOllamaExchange(const char* endpoint,
                         const std::string& request,
                         const std::string& response) {
    const char* path = std::getenv("RAWRXD_OLLAMA_TRACE_PATH");
    if (!path || !*path) return;
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) return;
    out << "ENDPOINT " << endpoint << "\nREQUEST\n" << request
        << "\nRESPONSE\n" << response << "\n";
}
}

OllamaClient::OllamaClient(const std::string& base_url)
    : m_base_url(base_url), m_timeout_seconds(300) {
}

OllamaClient::~OllamaClient() {
}

void OllamaClient::setBaseUrl(const std::string& url) {
    m_base_url = url;
}

bool OllamaClient::testConnection() {
    try {
        std::string version = getVersion();
        return !version.empty();
    } catch (...) {
        return false;
    }
}

std::string OllamaClient::getVersion() {
    std::string response = makeGetRequest("/api/version");
    if (response.find_first_not_of(" \t\r\n") == std::string::npos) {
        return {};
    }
    
    // Production-ready JSON parsing
    try {
        json j = json::parse(response);
        return j.value("version", std::string());
    } catch (const json::exception& e) {
        std::cerr << "JSON parsing error in getVersion: " << e.what() << std::endl;
        return "";
    }
}

bool OllamaClient::isRunning() {
    return testConnection();
}

std::vector<OllamaModel> OllamaClient::listModels() {
    std::string response = makeGetRequest("/api/tags");
    return parseModels(response);
}

OllamaResponse OllamaClient::generateSync(const OllamaGenerateRequest& request) {
    OllamaGenerateRequest sync_req = request;
    sync_req.stream = false;
    
    std::string json = createGenerateRequestJson(sync_req);
    std::string response = makePostRequest("/api/generate", json);
    
    return parseResponse(response);
}

OllamaResponse OllamaClient::chatSync(const OllamaChatRequest& request) {
    if (std::getenv("RAWRXD_CLI_DISPATCH_TRACE")) {
        std::fprintf(stderr, "[rawr-ollama-client-trace] chatSync:request model=%s messages=%zu\n",
                     request.model.c_str(), request.messages.size());
        std::fflush(stderr);
    }
    OllamaChatRequest sync_req = request;
    sync_req.stream = false;
    
    std::string json = createChatRequestJson(sync_req);
    std::string response = makePostRequest("/api/chat", json);
    if (std::getenv("RAWRXD_CLI_DISPATCH_TRACE")) {
        std::fprintf(stderr, "[rawr-ollama-client-trace] chatSync:response bytes=%zu\n", response.size());
        std::fflush(stderr);
    }
    
    return parseResponse(response);
}

bool OllamaClient::generate(const OllamaGenerateRequest& request,
                           StreamCallback on_chunk,
                           ErrorCallback on_error,
                           CompletionCallback on_complete) {
    std::string json = createGenerateRequestJson(request);
    return makeStreamingPostRequest("/api/generate", json, on_chunk, on_error, on_complete);
}

bool OllamaClient::chat(const OllamaChatRequest& request,
                       StreamCallback on_chunk,
                       ErrorCallback on_error,
                       CompletionCallback on_complete) {
    std::string json = createChatRequestJson(request);
    return makeStreamingPostRequest("/api/chat", json, on_chunk, on_error, on_complete);
}

std::vector<float> OllamaClient::embeddings(const std::string& model, const std::string& prompt) {
    const json payload = {{"model", model}, {"prompt", prompt}};
    std::string response = makePostRequest("/api/embeddings", payload.dump());
    
    // Parse embeddings array from JSON
    std::vector<float> result;
    // Simple parser for array of numbers
    size_t pos = response.find("[");
    if (pos != std::string::npos) {
        size_t end = response.find("]", pos);
        std::string array_str = response.substr(pos + 1, end - pos - 1);
        
        std::istringstream iss(array_str);
        std::string token;
        while (std::getline(iss, token, ',')) {
            try {
                result.push_back(std::stof(token));
            } catch (...) {}
        }
    }
    
    return result;
}

// JSON creation helpers
namespace {

// Request options are kept as strings in the public compatibility structs, but
// Ollama expects numbers and booleans as JSON values.  Parse the scalar when it
// is unambiguously numeric; retain other values as strings rather than emitting
// invalid JSON or silently changing their meaning.
json OllamaOptionValue(const std::string& value) {
    if (value == "true") return true;
    if (value == "false") return false;

    try {
        size_t consumed = 0;
        const long long integer = std::stoll(value, &consumed);
        if (consumed == value.size()) return integer;
    } catch (...) {
    }

    try {
        size_t consumed = 0;
        const double real = std::stod(value, &consumed);
        if (consumed == value.size()) return real;
    } catch (...) {
    }

    return value;
}

} // namespace

std::string OllamaClient::createGenerateRequestJson(const OllamaGenerateRequest& req) {
    json payload = {
        {"model", req.model},
        {"prompt", req.prompt},
        {"stream", req.stream},
        {"think", false}
    };
    if (!req.options.empty()) {
        payload["options"] = json::object();
        for (const auto& [key, value] : req.options) {
            payload["options"][key] = OllamaOptionValue(value);
        }
    }
    if (!req.stop.empty()) payload["stop"] = req.stop;
    return payload.dump();
}

std::string OllamaClient::createChatRequestJson(const OllamaChatRequest& req) {
    json payload = {
        {"model", req.model},
        {"messages", json::array()},
        {"stream", req.stream},
        {"think", false}
    };
    for (const auto& message : req.messages) {
        json item = {
            {"role", message.role},
            {"content", message.content}
        };
        if (!message.tool_call_id.empty()) item["tool_call_id"] = message.tool_call_id;
        if (!message.tool_calls.is_null() && message.tool_calls.is_array()) {
            item["tool_calls"] = message.tool_calls;
        }
        payload["messages"].push_back(std::move(item));
    }
    if (!req.options.empty()) {
        payload["options"] = json::object();
        for (const auto& [key, value] : req.options) {
            payload["options"][key] = OllamaOptionValue(value);
        }
    }
    if (!req.tools.is_null() && req.tools.is_array() && !req.tools.empty()) {
        payload["tools"] = req.tools;
    }
    return payload.dump();
}

OllamaResponse OllamaClient::parseResponse(const std::string& json_str) {
    OllamaResponse resp;

    // Production-ready JSON parsing with nlohmann/json
    try {
        json j = json::parse(json_str);

        // Extract response fields with safe access
        resp.model = j.value("model", std::string());
        resp.response = j.value("response", std::string());
        resp.done = j.value("done", false);
        resp.done_reason = j.value("done_reason", std::string());

        // Ollama reports transport/model failures as {"error":"..."}
        // without a chat message. Preserve that diagnostic so callers can
        // distinguish an upstream rejection from an empty successful answer.
        if (j.contains("error") && j["error"].is_string()) {
            resp.response = j["error"].get<std::string>();
            resp.done = true;
            resp.done_reason = "error";
        }

        // Chat-mode fields (used by /api/chat)
        if (j.contains("message")) {
            const auto& msg = j["message"];
            resp.message = msg.value("content", std::string());
            if (msg.contains("tool_calls")) {
                resp.tool_calls = msg["tool_calls"];
            }
        }

        // Extract performance metrics
        resp.total_duration = j.value("total_duration", uint64_t(0));
        resp.prompt_eval_count = j.value("prompt_eval_count", uint64_t(0));
        resp.eval_count = j.value("eval_count", uint64_t(0));

        // Extract optional fields
        if (j.contains("load_duration")) {
            resp.load_duration = j["load_duration"].get<uint64_t>();
        }
        if (j.contains("prompt_eval_duration")) {
            resp.prompt_eval_duration = j["prompt_eval_duration"].get<uint64_t>();
        }
        if (j.contains("eval_duration")) {
            resp.eval_duration = j["eval_duration"].get<uint64_t>();
        }

    } catch (const json::exception& e) {
        // Log parsing error and return partial response
        std::cerr << "JSON parsing error in parseResponse: " << e.what() << std::endl;
        // resp already initialized with defaults
    }

    return resp;
}

std::vector<OllamaModel> OllamaClient::parseModels(const std::string& json_str) {
    std::vector<OllamaModel> models;
    
    // Production-ready JSON parsing with nlohmann/json
    try {
        json j = json::parse(json_str);
        
        // Extract models array
        if (j.contains("models") && j["models"].is_array()) {
            for (const auto& model_json : j["models"]) {
                OllamaModel model;
                
                // Extract model fields with safe access
                model.name = model_json.value("name", std::string());
                model.modified_at = model_json.value("modified_at", std::string());
                model.size = model_json.value("size", uint64_t(0));
                model.digest = model_json.value("digest", std::string());
                
                // Extract details if present
                if (model_json.contains("details")) {
                    const auto& details = model_json["details"];
                    model.format = details.value("format", std::string());
                    model.family = details.value("family", std::string());
                    model.parameter_size = details.value("parameter_size", std::string());
                    model.quantization_level = details.value("quantization_level", std::string());
                }
                
                models.push_back(model);
            }
        }
        
    } catch (const json::exception& e) {
        // Log parsing error and return empty list
        std::cerr << "JSON parsing error in parseModels: " << e.what() << std::endl;
    }
    
    return models;
}

// Platform-specific HTTP implementations
#ifdef _WIN32

namespace {

bool CrackOllamaBaseUrl(const std::string& base_url,
                        std::wstring& host,
                        INTERNET_PORT& port) {
    std::wstring wide(base_url.begin(), base_url.end());
    if (wide.empty()) return false;

    wchar_t host_buffer[256]{};
    URL_COMPONENTS parts{};
    parts.dwStructSize = sizeof(parts);
    parts.lpszHostName = host_buffer;
    parts.dwHostNameLength = static_cast<DWORD>(std::size(host_buffer));

    if (!WinHttpCrackUrl(wide.c_str(), 0, 0, &parts) ||
        parts.dwHostNameLength == 0) {
        return false;
    }

    host.assign(parts.lpszHostName, parts.dwHostNameLength);
    port = parts.nPort != 0
        ? parts.nPort
        : (parts.nScheme == INTERNET_SCHEME_HTTPS
            ? INTERNET_DEFAULT_HTTPS_PORT
            : INTERNET_DEFAULT_HTTP_PORT);
    return true;
}

void ConfigureWinHttpTimeouts(HINTERNET session, int timeout_seconds) {
    const int bounded = std::clamp(timeout_seconds, 1, 3600);
    const DWORD timeout_ms = static_cast<DWORD>(bounded * 1000);
    WinHttpSetTimeouts(session, timeout_ms, timeout_ms, timeout_ms, timeout_ms);
}

} // namespace

std::string OllamaClient::makeGetRequest(const std::string& endpoint) {
    // Initialize WinHTTP
    HINTERNET hSession = WinHttpOpen(L"RawrXD/1.0",
                                     WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                     WINHTTP_NO_PROXY_NAME,
                                     WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return "";

    std::wstring host;
    INTERNET_PORT port = INTERNET_DEFAULT_HTTP_PORT;
    if (!CrackOllamaBaseUrl(m_base_url, host, port)) {
        WinHttpCloseHandle(hSession);
        return "";
    }
    ConfigureWinHttpTimeouts(hSession, m_timeout_seconds);

    HINTERNET hConnect = WinHttpConnect(hSession, host.c_str(), port, 0);
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

std::string OllamaClient::makePostRequest(const std::string& endpoint, const std::string& json_body) {
    HINTERNET hSession = WinHttpOpen(L"RawrXD/1.0",
                                     WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                     WINHTTP_NO_PROXY_NAME,
                                     WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return "";

    std::wstring host;
    INTERNET_PORT port = INTERNET_DEFAULT_HTTP_PORT;
    if (!CrackOllamaBaseUrl(m_base_url, host, port)) {
        WinHttpCloseHandle(hSession);
        return "";
    }
    ConfigureWinHttpTimeouts(hSession, m_timeout_seconds);

    HINTERNET hConnect = WinHttpConnect(hSession, host.c_str(), port, 0);
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
    
    TraceOllamaExchange(endpoint.c_str(), json_body, response);
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
    // Streaming implementation using WinHTTP
    // For now, fall back to sync mode
    OllamaResponse resp;
    resp.response = makePostRequest(endpoint, json_body);
    resp.done = true;
    
    if (on_chunk) on_chunk(resp);
    if (on_complete) on_complete(resp);
    
    return true;
}

#else
// Linux/Mac implementation would use libcurl here
#endif

// ---------------------------------------------------------------------------
// OllamaResponse factory methods
// ---------------------------------------------------------------------------
static OllamaResponse MakeOkResponse(const std::string& text, uint64_t ptok, uint64_t ctok) {
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

static OllamaResponse MakeErrorResponse(const std::string& msg) {
    OllamaResponse r;
    r.done = true;
    r.done_reason = "error";
    // Encode error in the response field so callers that only inspect
    // .response still see a distinguishable failure marker.
    r.response = "[ERROR] " + msg;
    return r;
}

} // namespace Backend
} // namespace RawrXD
