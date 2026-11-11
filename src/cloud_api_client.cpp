// cloud_api_client.cpp - Implementation of Cloud API Client
// Pure Windows native implementation using WinHTTP (no Qt dependency)
#include "cloud_api_client.h"
#include <windows.h>
#include <winhttp.h>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <algorithm>
#include <codecvt>
#include <nlohmann/json.hpp>

#pragma comment(lib, "winhttp.lib")

#ifndef WINHTTP_NO_REQUEST_HEADERS
#define WINHTTP_NO_REQUEST_HEADERS NULL
#endif
#ifndef WINHTTP_FLAG_NUMBER
#define WINHTTP_FLAG_NUMBER 0x40000000
#endif

// Helper: UTF-8 to wide string
static std::wstring utf8ToWide(const std::string& s) {
    if (s.empty()) return L"";
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), NULL, 0);
    std::wstring wstr(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &wstr[0], size_needed);
    return wstr;
}

// Helper: wide string to UTF-8
static std::string wideToUtf8(const std::wstring& ws) {
    if (ws.empty()) return "";
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), (int)ws.size(), NULL, 0, NULL, NULL);
    std::string str(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), (int)ws.size(), &str[0], size_needed, NULL, NULL);
    return str;
}

// Helper: current ISO timestamp
std::string CloudApiClient::currentTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    std::tm tm;
    localtime_s(&tm, &time_t_now);
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%S");
    return oss.str();
}

CloudApiClient::CloudApiClient() {
    initializeApiEndpoints();
}

CloudApiClient::~CloudApiClient() = default;

void CloudApiClient::initializeApiEndpoints() {
    // KILO GATEWAY API - OpenAI-compatible, free model catalog
    api_endpoints[static_cast<int>(ModelBackend::KILO_GATEWAY)] = {
        "https://api.kilo.ai",
        "/api/gateway/chat/completions",
        "/api/gateway/models"
    };

    // OPENROUTER API - OpenAI-compatible, free models
    api_endpoints[static_cast<int>(ModelBackend::OPENROUTER)] = {
        "https://openrouter.ai",
        "/api/v1/chat/completions",
        "/api/v1/models"
    };

    // ANTHROPIC API
    api_endpoints[static_cast<int>(ModelBackend::ANTHROPIC)] = {
        "https://api.anthropic.com",
        "/v1/messages",
        "/v1/models"
    };

    // OPENAI API
    api_endpoints[static_cast<int>(ModelBackend::OPENAI)] = {
        "https://api.openai.com",
        "/v1/chat/completions",
        "/v1/models"
    };

    // GOOGLE GEMINI API
    api_endpoints[static_cast<int>(ModelBackend::GOOGLE)] = {
        "https://generativelanguage.googleapis.com",
        "/v1beta/models",
        "/v1beta/models"
    };
}

std::string CloudApiClient::generate(const std::string& prompt, const ModelConfig& config) {
    if (!config.isValid()) {
        return "";
    }

    // Prepare headers
    std::map<std::string, std::string> headers;

    if (config.backend == ModelBackend::ANTHROPIC) {
        headers["x-api-key"] = config.api_key;
        headers["anthropic-version"] = "2023-06-01";
    } else if (config.backend == ModelBackend::OPENROUTER) {
        if (config.parameters.count("http_referer")) {
            headers["HTTP-Referer"] = config.parameters.at("http_referer");
        }
        if (config.parameters.count("x_title")) {
            headers["X-Title"] = config.parameters.at("x_title");
        }
    }

    std::string full_endpoint =
        api_endpoints[static_cast<int>(config.backend)].base_url +
        api_endpoints[static_cast<int>(config.backend)].chat_endpoint;

    std::string body = buildOpenAICompatibleRequest(prompt, config);

    // Anthropic uses a different request format
    if (config.backend == ModelBackend::ANTHROPIC) {
        // Build Anthropic-format request
        std::ostringstream oss;
        oss << "{";
        oss << "\"model\":\"" << config.model_id << "\",";
        oss << "\"max_tokens\":" << (config.parameters.count("max_tokens") ? config.parameters.at("max_tokens") : "4096") << ",";
        if (config.parameters.count("temperature")) {
            oss << "\"temperature\":" << config.parameters.at("temperature") << ",";
        }
        oss << "\"messages\":[{\"role\":\"user\",\"content\":\"" << prompt << "\"}";
        oss << "]}";
        body = oss.str();
    }

    ApiResponse response = executeRequest(full_endpoint, "POST", body, config.api_key, headers);

    if (!response.success) {
        std::fprintf(stderr,
                     "[CLOUD_ERROR] provider=%s model=%s endpoint=%s "
                     "status=%d latency_ms=%lld error=%s\n",
                     config.backend == ModelBackend::KILO_GATEWAY ? "kilo" :
                     config.backend == ModelBackend::OPENROUTER ? "openrouter" :
                     config.backend == ModelBackend::ANTHROPIC ? "anthropic" : "unknown",
                     config.model_id.c_str(),
                     full_endpoint.c_str(),
                     response.status_code,
                     response.latency_ms,
                     response.error_message.c_str());
        if (!response.raw_body.empty()) {
            std::string body_preview = response.raw_body.substr(0, 500);
            std::fprintf(stderr,
                         "[CLOUD_ERROR] response_body=%s\n", body_preview.c_str());
        }
        std::fflush(stderr);
        return "";
    }

    // Parse response using the appropriate parser
    std::string content = parseOpenAIResponse(response.raw_body);

    // If parser didn't extract content, use raw body
    if (content.empty() && !response.raw_body.empty()) {
        content = response.raw_body;
    }

    logApiCall({currentTimestamp(),
                config.backend == ModelBackend::KILO_GATEWAY ? "kilo" :
                config.backend == ModelBackend::OPENROUTER ? "openrouter" :
                config.backend == ModelBackend::ANTHROPIC ? "anthropic" : "unknown",
                config.model_id,
                full_endpoint,
                body,
                response.raw_body,
                response.status_code,
                response.latency_ms,
                response.success,
                response.error_message});

    return content;
}

void CloudApiClient::generateAsync(const std::string& prompt,
                                   const ModelConfig& config,
                                   std::function<void(const ApiResponse&)> callback) {
    auto result = generate(prompt, config);
    ApiResponse response;
    response.content = result;
    response.success = !result.empty();
    callback(response);
}

bool CloudApiClient::checkProviderHealth(const ModelConfig& config) {
    auto models = listModels(config);
    bool healthy = !models.empty();

    logApiCall({currentTimestamp(),
                config.backend == ModelBackend::KILO_GATEWAY ? "kilo" : "openrouter",
                config.model_id,
                api_endpoints[static_cast<int>(config.backend)].model_list_endpoint,
                "",
                "",
                healthy ? 200 : 0,
                0,
                healthy,
                healthy ? "" : "no models returned"});

    return healthy;
}

std::vector<std::string> CloudApiClient::listModels(const ModelConfig& config) {
    std::string full_endpoint =
        api_endpoints[static_cast<int>(config.backend)].base_url +
        api_endpoints[static_cast<int>(config.backend)].model_list_endpoint;

    ApiResponse response = executeRequest(full_endpoint, "GET", "", config.api_key, {});

    if (!response.success) {
        return {};
    }

    // Parse model IDs from response
    std::vector<std::string> models;
    // Simple JSON parsing - look for "id" fields
    size_t pos = 0;
    while ((pos = response.raw_body.find("\"id\"", pos)) != std::string::npos) {
        size_t colon = response.raw_body.find(':', pos);
        if (colon == std::string::npos) break;
        size_t quote = response.raw_body.find('"', colon + 1);
        if (quote == std::string::npos) break;
        size_t end_quote = response.raw_body.find('"', quote + 1);
        if (end_quote == std::string::npos) break;
        std::string model_id = response.raw_body.substr(quote + 1, end_quote - quote - 1);
        models.push_back(model_id);
        pos = end_quote + 1;
    }

    return models;
}

std::string CloudApiClient::buildOpenAICompatibleRequest(const std::string& prompt, const ModelConfig& config) {
    nlohmann::json request = {
        {"model", config.model_id},
        {"max_tokens", 4096},
        {"messages", nlohmann::json::array({
            {{"role", "user"}, {"content", prompt}}
        })}
    };
    if (const auto it = config.parameters.find("max_tokens"); it != config.parameters.end()) {
        try {
            request["max_tokens"] = std::max(1, std::stoi(it->second));
        } catch (...) {
            request["max_tokens"] = 4096;
        }
    }
    if (const auto it = config.parameters.find("temperature"); it != config.parameters.end()) {
        try {
            request["temperature"] = std::stod(it->second);
        } catch (...) {
        }
    }
    return request.dump();
}

std::string CloudApiClient::buildOpenRouterRequest(const std::string& prompt, const ModelConfig& config) {
    std::string body = buildOpenAICompatibleRequest(prompt, config);
    // OpenRouter-specific headers are applied in executeRequest via the headers map
    return body;
}

std::string CloudApiClient::parseOpenAIResponse(const std::string& raw_body) {
    try {
        const auto response = nlohmann::json::parse(raw_body);
        if (!response.contains("choices") || !response["choices"].is_array() ||
            response["choices"].empty()) {
            return "";
        }
        const auto& first = response["choices"][0];
        if (first.contains("message") && first["message"].is_object()) {
            const auto& content = first["message"]["content"];
            if (content.is_string()) return content.get<std::string>();
            if (content.is_array()) {
                std::string text;
                for (const auto& part : content) {
                    if (part.is_object() && part.contains("text") && part["text"].is_string()) {
                        text += part["text"].get<std::string>();
                    }
                }
                return text;
            }
        }
        if (first.contains("text") && first["text"].is_string()) {
            return first["text"].get<std::string>();
        }
    } catch (...) {
    }
    return "";
}

ApiResponse CloudApiClient::executeRequest(const std::string& endpoint,
                                           const std::string& method,
                                           const std::string& body,
                                           const std::string& api_key,
                                           const std::map<std::string, std::string>& headers) {
    ApiResponse response;
    response.success = false;
    response.status_code = 0;
    response.latency_ms = 0;

    HINTERNET hSession = WinHttpOpen(L"RawrXD/1.0",
                                     WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                     WINHTTP_NO_PROXY_NAME,
                                     WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        response.error_message = "WinHttpOpen failed";
        return response;
    }

    std::wstring wEndpoint = utf8ToWide(endpoint);
    // Parse URL to get host and path
    // Simple parse: https://host/path
    std::wstring scheme = L"https";
    std::wstring host;
    std::wstring path = L"/";

    size_t scheme_sep = wEndpoint.find(L"://");
    if (scheme_sep != std::wstring::npos) {
        scheme = wEndpoint.substr(0, scheme_sep);
        size_t path_start = wEndpoint.find(L"/", scheme_sep + 3);
        if (path_start != std::wstring::npos) {
            host = wEndpoint.substr(scheme_sep + 3, path_start - scheme_sep - 3);
            path = wEndpoint.substr(path_start);
        } else {
            host = wEndpoint.substr(scheme_sep + 3);
        }
    }

    INTERNET_PORT port = (scheme == L"https") ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT;

    HINTERNET hConnect = WinHttpConnect(hSession, host.c_str(), port, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        response.error_message = "WinHttpConnect failed";
        return response;
    }

    DWORD flags = WINHTTP_FLAG_SECURE;
    HINTERNET hRequest = WinHttpOpenRequest(hConnect,
                                            method == "POST" ? L"POST" : L"GET",
                                            path.c_str(),
                                            NULL, WINHTTP_NO_REFERER,
                                            WINHTTP_DEFAULT_ACCEPT_TYPES,
                                            flags);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        response.error_message = "WinHttpOpenRequest failed";
        return response;
    }

    // Set headers
    std::wstring all_headers;
    for (const auto& kv : headers) {
        all_headers += utf8ToWide(kv.first) + L": " + utf8ToWide(kv.second) + L"\r\n";
    }
    if (!api_key.empty()) {
        all_headers += L"Authorization: Bearer " + utf8ToWide(api_key) + L"\r\n";
    }
    all_headers += L"Content-Type: application/json\r\n";
    all_headers += L"Accept: application/json\r\n";

    // Set timeouts
    WinHttpSetTimeouts(hRequest, 10000, 10000, 30000, 30000);

    auto t_start = std::chrono::steady_clock::now();

    BOOL sent = WinHttpSendRequest(hRequest,
                                   all_headers.empty() ? WINHTTP_NO_REQUEST_HEADERS : all_headers.c_str(),
                                   (DWORD)-1L,  // -1L means headers are null-terminated
                                   (LPVOID)body.c_str(),
                                   (DWORD)body.size(),
                                   (DWORD)body.size(),
                                   0);

    if (!sent) {
        response.error_message = "WinHttpSendRequest failed";
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return response;
    }

    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        response.error_message = "WinHttpReceiveResponse failed";
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return response;
    }

    DWORD status_code = 0;
    DWORD status_size = sizeof(status_code);
    WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX, &status_code, &status_size, WINHTTP_NO_HEADER_INDEX);
    response.status_code = (int)status_code;

    // Read response
    std::string response_body;
    char buffer[4096];
    DWORD bytes_read = 0;
    while (WinHttpReadData(hRequest, buffer, sizeof(buffer), &bytes_read) && bytes_read > 0) {
        response_body.append(buffer, bytes_read);
    }
    response.raw_body = response_body;

    auto t_end = std::chrono::steady_clock::now();
    response.latency_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t_end - t_start).count();

    if (status_code >= 200 && status_code < 300) {
        response.success = true;
    } else {
        response.error_message = "HTTP " + std::to_string(status_code);
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return response;
}

std::string CloudApiClient::formatErrorResponse(int status_code, const std::string& body) {
    return "HTTP " + std::to_string(status_code) + ": " + body;
}

void CloudApiClient::logApiCall(const ApiCallLog& log) {
    call_history.push_back(log);
    if (call_history.size() > MAX_HISTORY_SIZE) {
        call_history.erase(call_history.begin());
    }
}

std::vector<ApiCallLog> CloudApiClient::getCallHistory() const {
    return call_history;
}

void CloudApiClient::clearCallHistory() {
    call_history.clear();
}

ApiCallLog CloudApiClient::getLastCall() const {
    if (call_history.empty()) {
        return ApiCallLog();
    }
    return call_history.back();
}

double CloudApiClient::getAverageLatency() const {
    if (call_history.empty()) return 0.0;
    int64_t total = 0;
    for (const auto& log : call_history) {
        total += log.latency_ms;
    }
    return (double)total / (double)call_history.size();
}

int CloudApiClient::getSuccessRate() const {
    if (call_history.empty()) return 0;
    int successful = 0;
    for (const auto& log : call_history) {
        if (log.success) successful++;
    }
    return (successful * 100) / (int)call_history.size();
}
