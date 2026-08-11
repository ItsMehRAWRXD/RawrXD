/**
 * @file llm_http_client_impl.cpp
 * @brief LLMHttpClient implementation — WinHTTP-based HTTP client for LLM APIs
 *
 * Implements the LLMHttpClient class declared in llm_http_client.h.
 * Uses WinHTTP on Windows for real HTTP calls to Ollama, OpenAI, Anthropic.
 * No Qt, no curl dependency. Structured result returns (no exceptions in hot paths).
 */

#include "llm_http_client.h"
#include <windows.h>
#include <winhttp.h>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <random>
#include <algorithm>
#include <regex>

#pragma comment(lib, "winhttp.lib")

// ============================================================================
// URL parsing helper
// ============================================================================
namespace {

struct ParsedUrl {
    std::wstring host;
    std::wstring path;
    uint16_t     port   = 80;
    bool         isTls  = false;
};

ParsedUrl parseUrl(const std::string& url) {
    ParsedUrl p;
    p.isTls = (url.rfind("https", 0) == 0);
    p.port  = p.isTls ? 443 : 80;

    size_t schemeEnd = url.find("://");
    if (schemeEnd == std::string::npos) {
        p.host = L"localhost";
        p.path = std::wstring(url.begin(), url.end());
        return p;
    }
    schemeEnd += 3;

    size_t pathStart = url.find('/', schemeEnd);
    if (pathStart == std::string::npos) pathStart = url.size();

    std::string hostPort(url.begin() + schemeEnd, url.begin() + pathStart);
    std::string pathStr(url.begin() + pathStart, url.end());
    if (pathStr.empty()) pathStr = "/";

    auto colon = hostPort.find(':');
    if (colon != std::string::npos) {
        std::string portStr(hostPort.begin() + colon + 1, hostPort.end());
        p.port = static_cast<uint16_t>(std::stoi(portStr));
        hostPort = hostPort.substr(0, colon);
    }

    p.host = std::wstring(hostPort.begin(), hostPort.end());
    p.path = std::wstring(pathStr.begin(), pathStr.end());
    return p;
}

int64_t nowMs() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

std::string wstringToUtf8(const std::wstring& wstr) {
    if (wstr.empty()) return {};
    int size = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (size <= 0) return {};
    std::string result(size - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, result.data(), size - 1, nullptr, nullptr);
    return result;
}

} // anonymous namespace

// ============================================================================
// LLMHttpClient — construction / destruction
// ============================================================================
LLMHttpClient::LLMHttpClient()
    : m_backend(LLMBackend::OLLAMA),
      m_initTime(std::chrono::high_resolution_clock::now()),
      m_activeConnections(0)
{
}

LLMHttpClient::~LLMHttpClient() {
}

// ============================================================================
// Initialization
// ============================================================================
bool LLMHttpClient::initialize(
    LLMBackend backend,
    const HTTPConfig& config,
    const AuthCredentials& credentials)
{
    m_backend = backend;
    m_config = config;
    m_credentials = credentials;

    if (config.baseUrl.empty()) {
        return false;
    }

    return true;
}

// ============================================================================
// Main HTTP Operations
// ============================================================================
APIResponse LLMHttpClient::makeRequest(const APIRequest& request) {
    return sendHTTPRequest(request, true);
}

APIResponse LLMHttpClient::makeStreamingRequest(
    const APIRequest& request,
    std::function<void(const StreamChunk&)> chunkCallback)
{
    if (!checkRateLimit()) {
        APIResponse resp;
        resp.success = false;
        resp.error = "Rate limit exceeded";
        return resp;
    }

    return sendHTTPStreamingRequest(request, chunkCallback);
}

// ============================================================================
// Request Building
// ============================================================================
APIRequest LLMHttpClient::buildOllamaCompletionRequest(
    const std::string& prompt,
    const json& config)
{
    APIRequest req;
    req.backend = LLMBackend::OLLAMA;
    req.endpoint = "/api/generate";
    req.method = "POST";
    req.body = json::object();
    req.body["model"] = config.value("model", "llama3.2");
    req.body["prompt"] = prompt;
    req.body["stream"] = config.value("stream", false);
    if (config.contains("options")) req.body["options"] = config["options"];
    req.createdAt = nowMs();
    return req;
}

APIRequest LLMHttpClient::buildOllamaChatRequest(
    const std::vector<json>& messages,
    const json& config)
{
    APIRequest req;
    req.backend = LLMBackend::OLLAMA;
    req.endpoint = "/api/chat";
    req.method = "POST";
    req.body = json::object();
    req.body["model"] = config.value("model", "llama3.2");
    req.body["messages"] = messages;
    req.body["stream"] = config.value("stream", false);
    req.createdAt = nowMs();
    return req;
}

APIRequest LLMHttpClient::buildOpenAIChatRequest(
    const std::vector<json>& messages,
    const std::string& model,
    const json& config)
{
    APIRequest req;
    req.backend = LLMBackend::OPENAI;
    req.endpoint = "/v1/chat/completions";
    req.method = "POST";
    req.body = json::object();
    req.body["model"] = model;
    req.body["messages"] = messages;
    req.body["stream"] = config.value("stream", false);
    if (config.contains("max_tokens")) req.body["max_tokens"] = config["max_tokens"];
    if (config.contains("temperature")) req.body["temperature"] = config["temperature"];
    req.createdAt = nowMs();
    return req;
}

APIRequest LLMHttpClient::buildAnthropicMessageRequest(
    const std::vector<json>& messages,
    const std::string& model,
    const json& config)
{
    APIRequest req;
    req.backend = LLMBackend::ANTHROPIC;
    req.endpoint = "/v1/messages";
    req.method = "POST";
    req.body = json::object();
    req.body["model"] = model;
    req.body["messages"] = messages;
    req.body["max_tokens"] = config.value("max_tokens", 1024);
    if (config.contains("temperature")) req.body["temperature"] = config["temperature"];
    req.createdAt = nowMs();
    return req;
}

// ============================================================================
// Stream Parsing
// ============================================================================
StreamChunk LLMHttpClient::parseOllamaStreamChunk(const std::string& chunk) {
    StreamChunk result;
    try {
        auto j = json::parse(chunk);
        if (j.contains("message") && j["message"].contains("content")) {
            result.content = j["message"]["content"].get<std::string>();
        } else if (j.contains("response")) {
            result.content = j["response"].get<std::string>();
        }
        if (j.contains("done") && j["done"].get<bool>()) {
            result.isComplete = true;
        }
        result.tokenCount = 1;
    } catch (...) {
        result.content = chunk;
    }
    return result;
}

StreamChunk LLMHttpClient::parseOpenAIStreamChunk(const std::string& line) {
    StreamChunk result;
    if (line.rfind("data: ", 0) == 0) {
        std::string jsonStr = line.substr(6);
        if (jsonStr == "[DONE]") {
            result.isComplete = true;
            return result;
        }
        try {
            auto j = json::parse(jsonStr);
            if (j.contains("choices") && !j["choices"].empty()) {
                auto& delta = j["choices"][0]["delta"];
                if (delta.contains("content")) {
                    result.content = delta["content"].get<std::string>();
                }
            }
            result.tokenCount = 1;
        } catch (...) {
            result.content = jsonStr;
        }
    }
    return result;
}

StreamChunk LLMHttpClient::parseAnthropicStreamChunk(const std::string& line) {
    StreamChunk result;
    if (line.rfind("data: ", 0) == 0) {
        std::string jsonStr = line.substr(6);
        try {
            auto j = json::parse(jsonStr);
            if (j.contains("delta") && j["delta"].contains("text")) {
                result.content = j["delta"]["text"].get<std::string>();
            }
            result.tokenCount = 1;
        } catch (...) {
            result.content = jsonStr;
        }
    }
    return result;
}

// ============================================================================
// Connectivity Test
// ============================================================================
bool LLMHttpClient::testConnectivity() {
    APIRequest req;
    req.backend = m_backend;
    req.endpoint = "/";
    req.method = "GET";
    req.body = json::object();
    auto resp = sendHTTPRequest(req, false);
    return resp.success || resp.statusCode == 404; // 404 means server is up
}

// ============================================================================
// List Models
// ============================================================================
json LLMHttpClient::listAvailableModels() {
    APIRequest req;
    req.backend = m_backend;
    req.endpoint = "/api/tags"; // Ollama endpoint
    req.method = "GET";
    req.body = json::object();
    auto resp = sendHTTPRequest(req, true);
    if (resp.success && resp.body.contains("models")) {
        return resp.body["models"];
    }
    return json::array();
}

// ============================================================================
// Credentials
// ============================================================================
void LLMHttpClient::setCredentials(const AuthCredentials& credentials) {
    m_credentials = credentials;
}

// ============================================================================
// Rate Limiting
// ============================================================================
void LLMHttpClient::setRateLimit(double requestsPerSecond) {
    std::lock_guard<std::mutex> lock(m_rateLimitMutex);
    m_requestsPerSecond = requestsPerSecond;
}

bool LLMHttpClient::checkRateLimit() {
    std::lock_guard<std::mutex> lock(m_rateLimitMutex);
    if (m_requestsPerSecond <= 0) return true;
    int64_t now = nowMs();
    int64_t intervalMs = static_cast<int64_t>(1000.0 / m_requestsPerSecond);
    if (now - m_lastRequestTime >= intervalMs) {
        m_lastRequestTime = now;
        return true;
    }
    return false;
}

// ============================================================================
// Internal HTTP Operations
// ============================================================================
APIResponse LLMHttpClient::sendHTTPRequest(const APIRequest& request, bool retry) {
    auto startT = nowMs();
    m_stats.totalRequests++;

    std::string url = m_config.baseUrl + request.endpoint;
    auto parsed = parseUrl(url);

    HINTERNET hSession = WinHttpOpen(
        L"RawrXD-LLMClient/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0);
    if (!hSession) {
        m_stats.failedRequests++;
        APIResponse resp;
        resp.success = false;
        resp.error = "WinHttpOpen failed";
        resp.responseTimeMs = nowMs() - startT;
        return resp;
    }

    WinHttpSetTimeouts(hSession, m_config.timeoutMs, m_config.timeoutMs,
                       m_config.timeoutMs, m_config.timeoutMs);

    HINTERNET hConnect = WinHttpConnect(hSession, parsed.host.c_str(), parsed.port, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        m_stats.failedRequests++;
        APIResponse resp;
        resp.success = false;
        resp.error = "WinHttpConnect failed";
        resp.responseTimeMs = nowMs() - startT;
        return resp;
    }

    DWORD flags = parsed.isTls ? WINHTTP_FLAG_SECURE : 0;
    std::wstring wMethod(request.method.begin(), request.method.end());
    std::wstring wPath(request.endpoint.begin(), request.endpoint.end());
    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect, wMethod.c_str(), wPath.c_str(),
        nullptr, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        m_stats.failedRequests++;
        APIResponse resp;
        resp.success = false;
        resp.error = "WinHttpOpenRequest failed";
        resp.responseTimeMs = nowMs() - startT;
        return resp;
    }

    // Build headers
    std::wstring headers = L"Content-Type: application/json\r\n";
    auto authHeaders = buildAuthHeaders();
    for (const auto& [k, v] : authHeaders) {
        std::wstring wk(k.begin(), k.end());
        std::wstring wv(v.begin(), v.end());
        headers += wk + L": " + wv + L"\r\n";
    }

    std::string bodyStr = request.body.dump();
    LPVOID bodyData = bodyStr.empty() ? WINHTTP_NO_REQUEST_DATA : const_cast<char*>(bodyStr.c_str());
    DWORD bodyLen = static_cast<DWORD>(bodyStr.size());

    BOOL sent = WinHttpSendRequest(
        hRequest,
        headers.c_str(), static_cast<DWORD>(headers.size()),
        bodyData, bodyLen, bodyLen, 0);

    if (!sent) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        m_stats.failedRequests++;
        APIResponse resp;
        resp.success = false;
        resp.error = "WinHttpSendRequest failed";
        resp.responseTimeMs = nowMs() - startT;
        return resp;
    }

    if (!WinHttpReceiveResponse(hRequest, nullptr)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        m_stats.failedRequests++;
        APIResponse resp;
        resp.success = false;
        resp.error = "WinHttpReceiveResponse failed";
        resp.responseTimeMs = nowMs() - startT;
        return resp;
    }

    // Read status code
    DWORD statusCode = 0, statusSize = sizeof(statusCode);
    WinHttpQueryHeaders(hRequest,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusSize,
        WINHTTP_NO_HEADER_INDEX);

    // Read body
    std::string responseBody;
    DWORD bytesAvail = 0;
    while (WinHttpQueryDataAvailable(hRequest, &bytesAvail) && bytesAvail > 0) {
        size_t pos = responseBody.size();
        responseBody.resize(pos + bytesAvail);
        DWORD bytesRead = 0;
        WinHttpReadData(hRequest, responseBody.data() + pos, bytesAvail, &bytesRead);
        responseBody.resize(pos + bytesRead);
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    int64_t latency = nowMs() - startT;
    m_stats.totalLatencyMs += latency;

    APIResponse resp;
    resp.statusCode = static_cast<int>(statusCode);
    resp.rawBody = responseBody;
    resp.responseTimeMs = latency;
    resp.receivedAt = nowMs();
    resp.success = (statusCode >= 200 && statusCode < 300);

    if (resp.success) {
        m_stats.successfulRequests++;
        try {
            resp.body = json::parse(responseBody);
        } catch (...) {
            resp.body = json::object();
        }
    } else {
        m_stats.failedRequests++;
        resp.error = "HTTP " + std::to_string(statusCode);
    }

    return resp;
}

APIResponse LLMHttpClient::sendHTTPStreamingRequest(
    const APIRequest& request,
    std::function<void(const StreamChunk&)> chunkCallback)
{
    auto startT = nowMs();
    m_stats.totalRequests++;

    std::string url = m_config.baseUrl + request.endpoint;
    auto parsed = parseUrl(url);

    HINTERNET hSession = WinHttpOpen(
        L"RawrXD-LLMClient/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0);
    if (!hSession) {
        m_stats.failedRequests++;
        APIResponse resp;
        resp.success = false;
        resp.error = "WinHttpOpen failed";
        resp.responseTimeMs = nowMs() - startT;
        return resp;
    }

    WinHttpSetTimeouts(hSession, m_config.timeoutMs, m_config.timeoutMs,
                       m_config.timeoutMs, m_config.timeoutMs);

    HINTERNET hConnect = WinHttpConnect(hSession, parsed.host.c_str(), parsed.port, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        m_stats.failedRequests++;
        APIResponse resp;
        resp.success = false;
        resp.error = "WinHttpConnect failed";
        resp.responseTimeMs = nowMs() - startT;
        return resp;
    }

    DWORD flags = parsed.isTls ? WINHTTP_FLAG_SECURE : 0;
    std::wstring wMethod(request.method.begin(), request.method.end());
    std::wstring wPath(request.endpoint.begin(), request.endpoint.end());
    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect, wMethod.c_str(), wPath.c_str(),
        nullptr, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        m_stats.failedRequests++;
        APIResponse resp;
        resp.success = false;
        resp.error = "WinHttpOpenRequest failed";
        resp.responseTimeMs = nowMs() - startT;
        return resp;
    }

    std::wstring headers = L"Content-Type: application/json\r\nAccept: text/event-stream\r\n";
    auto authHeaders = buildAuthHeaders();
    for (const auto& [k, v] : authHeaders) {
        std::wstring wk(k.begin(), k.end());
        std::wstring wv(v.begin(), v.end());
        headers += wk + L": " + wv + L"\r\n";
    }

    std::string bodyStr = request.body.dump();
    LPVOID bodyData = bodyStr.empty() ? WINHTTP_NO_REQUEST_DATA : const_cast<char*>(bodyStr.c_str());
    DWORD bodyLen = static_cast<DWORD>(bodyStr.size());

    BOOL sent = WinHttpSendRequest(
        hRequest,
        headers.c_str(), static_cast<DWORD>(headers.size()),
        bodyData, bodyLen, bodyLen, 0);

    if (!sent || !WinHttpReceiveResponse(hRequest, nullptr)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        m_stats.failedRequests++;
        APIResponse resp;
        resp.success = false;
        resp.error = "Request failed";
        resp.responseTimeMs = nowMs() - startT;
        return resp;
    }

    // Read streaming response
    std::string buffer;
    DWORD bytesAvail = 0;
    while (WinHttpQueryDataAvailable(hRequest, &bytesAvail)) {
        if (bytesAvail == 0) {
            Sleep(10);
            continue;
        }
        size_t pos = buffer.size();
        buffer.resize(pos + bytesAvail);
        DWORD bytesRead = 0;
        WinHttpReadData(hRequest, buffer.data() + pos, bytesAvail, &bytesRead);
        buffer.resize(pos + bytesRead);

        // Process lines
        size_t lineStart = 0;
        for (size_t i = 0; i < buffer.size(); ++i) {
            if (buffer[i] == '\n') {
                std::string line = buffer.substr(lineStart, i - lineStart);
                lineStart = i + 1;
                if (!line.empty()) {
                    StreamChunk chunk;
                    switch (m_backend) {
                        case LLMBackend::OLLAMA:
                            chunk = parseOllamaStreamChunk(line);
                            break;
                        case LLMBackend::OPENAI:
                            chunk = parseOpenAIStreamChunk(line);
                            break;
                        case LLMBackend::ANTHROPIC:
                            chunk = parseAnthropicStreamChunk(line);
                            break;
                        default:
                            chunk.content = line;
                            break;
                    }
                    if (chunkCallback) chunkCallback(chunk);
                }
            }
        }
        if (lineStart > 0) {
            buffer = buffer.substr(lineStart);
        }
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    int64_t latency = nowMs() - startT;
    m_stats.totalLatencyMs += latency;
    m_stats.successfulRequests++;

    APIResponse resp;
    resp.success = true;
    resp.responseTimeMs = latency;
    resp.receivedAt = nowMs();
    return resp;
}

// ============================================================================
// Auth Headers
// ============================================================================
std::map<std::string, std::string> LLMHttpClient::buildAuthHeaders() {
    std::map<std::string, std::string> headers;
    switch (m_credentials.type) {
        case AuthType::BEARER_TOKEN:
            headers["Authorization"] = "Bearer " + m_credentials.token;
            break;
        case AuthType::API_KEY:
            headers["Authorization"] = "Bearer " + m_credentials.apiKey;
            break;
        case AuthType::BASIC_AUTH:
            headers["Authorization"] = "Basic " + m_credentials.username + ":" + m_credentials.password;
            break;
        case AuthType::OAUTH2:
            if (!m_credentials.oauthTokenUrl.empty()) {
                headers["Authorization"] = "Bearer " + m_credentials.token;
            }
            break;
        default:
            break;
    }
    if (!m_credentials.customHeader.empty() && !m_credentials.apiKey.empty()) {
        headers[m_credentials.customHeader] = m_credentials.apiKey;
    }
    return headers;
}

std::map<std::string, std::string> LLMHttpClient::buildDefaultHeaders() {
    std::map<std::string, std::string> headers;
    headers["User-Agent"] = m_config.userAgent;
    headers["Content-Type"] = "application/json";
    if (m_config.enableCompression) {
        headers["Accept-Encoding"] = "gzip, deflate";
    }
    return headers;
}

// ============================================================================
// Response Parsing
// ============================================================================
json LLMHttpClient::validateAndSanitizeRequest(const json& request) {
    return request;
}

APIResponse LLMHttpClient::parseHTTPResponse(
    int statusCode,
    const std::string& body,
    int64_t latencyMs)
{
    APIResponse resp;
    resp.statusCode = statusCode;
    resp.rawBody = body;
    resp.responseTimeMs = latencyMs;
    resp.success = (statusCode >= 200 && statusCode < 300);
    try {
        resp.body = json::parse(body);
    } catch (...) {
        resp.body = json::object();
    }
    return resp;
}

json LLMHttpClient::parseJSONResponse(const std::string& body) {
    try {
        return json::parse(body);
    } catch (...) {
        return json::object();
    }
}

// ============================================================================
// Error Handling and Retry
// ============================================================================
bool LLMHttpClient::shouldRetry(int statusCode, int retryCount) {
    if (retryCount >= m_config.maxRetries) return false;
    return (statusCode == 429 || statusCode == 503 || statusCode == 502 || statusCode == 504 || statusCode == 0);
}

int LLMHttpClient::calculateBackoffDelay(int retryCount) {
    int baseDelay = m_config.retryDelayMs * (1 << retryCount);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, baseDelay / 2);
    return baseDelay + dis(gen);
}

std::string LLMHttpClient::formatErrorMessage(int statusCode, const std::string& body) {
    return "HTTP " + std::to_string(statusCode) + ": " + body;
}

// ============================================================================
// OAuth2 Token Management
// ============================================================================
bool LLMHttpClient::refreshOAuth2Token() {
    return false;
}

bool LLMHttpClient::isTokenExpired() const {
    if (m_credentials.tokenExpiresAt <= 0) return false;
    return nowMs() >= m_credentials.tokenExpiresAt;
}

// ============================================================================
// Stream Parsing Helpers
// ============================================================================
std::vector<std::string> LLMHttpClient::splitSSELines(const std::string& data) {
    std::vector<std::string> lines;
    std::stringstream ss(data);
    std::string line;
    while (std::getline(ss, line)) {
        lines.push_back(line);
    }
    return lines;
}

std::string LLMHttpClient::extractJSONFromSSE(const std::string& line) {
    if (line.rfind("data: ", 0) == 0) {
        return line.substr(6);
    }
    return line;
}
