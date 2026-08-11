// ============================================================================
// Deep2Discovery.cpp - Backend Auto-Discovery Utility
// Phase 0: Runtime Wiring - Removes Ollama hard dependency
// ============================================================================

#include "Deep2Discovery.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winhttp.h>
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <nlohmann/json.hpp>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "winhttp.lib")

using json = nlohmann::json;

namespace Deep2 {

// ============================================================================
// Backend Discovery Implementation
// ============================================================================

std::vector<DiscoveredBackend> Deep2Discovery::DiscoverBackends() {
    std::vector<DiscoveredBackend> backends;
    
    // Priority order: Deep2 Native -> RawrXD -> Ollama (fallback)
    
    // 1. Try Deep2 Native on port 11436
    if (TestConnection("http://127.0.0.1:11436")) {
        DiscoveredBackend deep2;
        deep2.type = "deep2";
        deep2.url = "http://127.0.0.1:11436";
        deep2.priority = 1;
        deep2.status = "online";
        deep2.native = true;
        
        // Get version info
        std::string versionJson = HttpGet("http://127.0.0.1:11436/api/version");
        if (!versionJson.empty()) {
            try {
                json j = json::parse(versionJson);
                deep2.version = j.value("version", "1.0.0");
                deep2.engine = j.value("engine", "Deep2");
            } catch (...) {
                deep2.version = "1.0.0";
            }
        }
        
        // Get capabilities
        deep2.capabilities = GetCapabilities(deep2.url);
        backends.push_back(deep2);
    }
    
    // 2. Try RawrXD on port 8080
    if (TestConnection("http://127.0.0.1:8080")) {
        DiscoveredBackend rawrxd;
        rawrxd.type = "rawrxd";
        rawrxd.url = "http://127.0.0.1:8080";
        rawrxd.priority = 2;
        rawrxd.status = "online";
        rawrxd.native = false;
        backends.push_back(rawrxd);
    }
    
    // 3. Try Ollama on port 11434 (fallback)
    if (TestConnection("http://127.0.0.1:11434")) {
        DiscoveredBackend ollama;
        ollama.type = "ollama";
        ollama.url = "http://127.0.0.1:11434";
        ollama.priority = 4;
        ollama.status = "fallback";
        ollama.native = false;
        
        std::string versionJson = HttpGet("http://127.0.0.1:11434/api/version");
        if (!versionJson.empty()) {
            try {
                json j = json::parse(versionJson);
                ollama.version = j.value("version", "unknown");
            } catch (...) {
                ollama.version = "unknown";
            }
        }
        
        backends.push_back(ollama);
    }
    
    return backends;
}

DiscoveredBackend Deep2Discovery::GetPreferredBackend() {
    auto backends = DiscoverBackends();
    
    if (backends.empty()) {
        // Return fallback Ollama config even if not running
        DiscoveredBackend fallback;
        fallback.type = "ollama";
        fallback.url = "http://127.0.0.1:11434";
        fallback.priority = 4;
        fallback.status = "offline";
        fallback.native = false;
        return fallback;
    }
    
    // Sort by priority and return highest
    DiscoveredBackend best = backends[0];
    for (const auto& backend : backends) {
        if (backend.priority < best.priority) {
            best = backend;
        }
    }
    
    return best;
}

bool Deep2Discovery::TestConnection(const std::string& url) {
    // Quick TCP connect test
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return false;
    }
    
    // Parse URL to get host and port
    std::string host = "127.0.0.1";
    int port = 11436;
    
    size_t protoEnd = url.find("://");
    size_t hostStart = (protoEnd == std::string::npos) ? 0 : protoEnd + 3;
    size_t portStart = url.find(':', hostStart);
    size_t pathStart = url.find('/', hostStart);
    
    if (portStart != std::string::npos) {
        host = url.substr(hostStart, portStart - hostStart);
        size_t portEnd = (pathStart != std::string::npos) ? pathStart : url.length();
        port = std::stoi(url.substr(portStart + 1, portEnd - portStart - 1));
    }
    
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        WSACleanup();
        return false;
    }
    
    // Set short timeout
    DWORD timeout = 1000; // 1 second
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));
    
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, host.c_str(), &addr.sin_addr);
    
    bool connected = (connect(sock, (sockaddr*)&addr, sizeof(addr)) == 0);
    
    closesocket(sock);
    WSACleanup();
    
    return connected;
}

std::vector<std::string> Deep2Discovery::GetCapabilities(const std::string& url) {
    std::vector<std::string> caps;
    
    std::string backendsJson = HttpGet(url + "/api/backends");
    if (!backendsJson.empty()) {
        try {
            json j = json::parse(backendsJson);
            if (j.contains("backends") && !j["backends"].empty()) {
                auto& backend = j["backends"][0];
                if (backend.contains("capabilities")) {
                    for (const auto& cap : backend["capabilities"]) {
                        caps.push_back(cap.get<std::string>());
                    }
                }
            }
        } catch (...) {
            // Ignore parse errors
        }
    }
    
    // Default capabilities
    if (caps.empty()) {
        caps = {"generate", "chat", "embeddings"};
    }
    
    return caps;
}

std::string Deep2Discovery::HttpGet(const std::string& url) {
    HINTERNET hSession = WinHttpOpen(L"Deep2Discovery/1.0", 
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, 
        WINHTTP_NO_PROXY_BYPASS, 0);
    
    if (!hSession) return "";
    
    // Parse URL
    std::wstring wUrl(url.begin(), url.end());
    URL_COMPONENTS urlComp = {};
    urlComp.dwStructSize = sizeof(urlComp);
    urlComp.dwSchemeLength = (DWORD)-1;
    urlComp.dwHostNameLength = (DWORD)-1;
    urlComp.dwUrlPathLength = (DWORD)-1;
    
    if (!WinHttpCrackUrl(wUrl.c_str(), (DWORD)wUrl.length(), 0, &urlComp)) {
        WinHttpCloseHandle(hSession);
        return "";
    }
    
    std::wstring hostName(urlComp.lpszHostName, urlComp.dwHostNameLength);
    std::wstring urlPath(urlComp.lpszUrlPath, urlComp.dwUrlPathLength);
    
    HINTERNET hConnect = WinHttpConnect(hSession, hostName.c_str(), 
        urlComp.nPort, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return "";
    }
    
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", urlPath.c_str(),
        NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return "";
    }
    
    // Set timeout
    DWORD timeout = 2000;
    WinHttpSetOption(hRequest, WINHTTP_OPTION_RECEIVE_TIMEOUT, 
        (void*)&timeout, sizeof(DWORD));
    
    BOOL sent = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    if (!sent) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return "";
    }
    
    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return "";
    }
    
    std::string response;
    DWORD dwSize = 0;
    DWORD dwDownloaded = 0;
    
    do {
        dwSize = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) break;
        
        if (dwSize > 0) {
            std::vector<char> buffer(dwSize + 1);
            ZeroMemory(buffer.data(), dwSize + 1);
            
            if (WinHttpReadData(hRequest, buffer.data(), dwSize, &dwDownloaded)) {
                response.append(buffer.data(), dwDownloaded);
            }
        }
    } while (dwSize > 0);
    
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    
    return response;
}

// ============================================================================
// Deep2BackendClient Implementation
// ============================================================================

Deep2BackendClient::Deep2BackendClient() 
    : baseUrl_("http://127.0.0.1:11436"), connected_(false) {
    AutoConnect();
}

Deep2BackendClient::Deep2BackendClient(const std::string& url)
    : baseUrl_(url), connected_(false) {
    Connect(url);
}

bool Deep2BackendClient::AutoConnect() {
    auto backend = Deep2Discovery::GetPreferredBackend();
    return Connect(backend.url);
}

bool Deep2BackendClient::Connect(const std::string& url) {
    baseUrl_ = url;
    connected_ = Deep2Discovery::TestConnection(url);
    
    if (connected_) {
        // Verify it's actually Deep2 by checking version
        std::string versionJson = HttpGet(baseUrl_ + "/api/version");
        if (!versionJson.empty()) {
            try {
                json j = json::parse(versionJson);
                if (j.value("engine", "") == "Deep2" || 
                    j.value("native", false)) {
                    // It's Deep2!
                    return true;
                }
            } catch (...) {
                // Not Deep2, but might still work
            }
        }
    }
    
    return connected_;
}

void Deep2BackendClient::Disconnect() {
    connected_ = false;
}

bool Deep2BackendClient::IsConnected() const {
    return connected_;
}

std::string Deep2BackendClient::GetBaseUrl() const {
    return baseUrl_;
}

std::vector<ModelInfo> Deep2BackendClient::ListModels() {
    std::vector<ModelInfo> models;
    
    if (!connected_) return models;
    
    std::string response = HttpGet(baseUrl_ + "/api/tags");
    if (response.empty()) return models;
    
    try {
        json j = json::parse(response);
        if (j.contains("models")) {
            for (const auto& m : j["models"]) {
                ModelInfo info;
                info.id = m.value("name", "");
                info.name = m.value("model", info.id);
                info.quantization = m.value("quantization", "unknown");
                
                if (m.contains("details")) {
                    auto& details = m["details"];
                    info.parameterCount = ParseParamSize(details.value("parameter_size", ""));
                    info.quantization = details.value("quantization_level", info.quantization);
                }
                
                models.push_back(info);
            }
        }
    } catch (...) {
        // Parse error
    }
    
    return models;
}

bool Deep2BackendClient::LoadModel(const std::string& modelId) {
    if (!connected_) return false;
    
    // POST to /api/model/load
    json request;
    request["model"] = modelId;
    
    std::string response = HttpPost(baseUrl_ + "/api/model/load", request.dump());
    if (response.empty()) return false;
    
    try {
        json j = json::parse(response);
        return j.value("success", false);
    } catch (...) {
        return false;
    }
}

bool Deep2BackendClient::UnloadModel() {
    if (!connected_) return false;
    
    std::string response = HttpPost(baseUrl_ + "/api/model/unload", "{}");
    if (response.empty()) return false;
    
    try {
        json j = json::parse(response);
        return j.value("success", false);
    } catch (...) {
        return false;
    }
}

std::string Deep2BackendClient::Generate(const std::string& prompt, int maxTokens, 
                                           float temperature) {
    if (!connected_) return "";
    
    json request;
    request["prompt"] = prompt;
    request["max_tokens"] = maxTokens;
    request["temperature"] = temperature;
    request["stream"] = false;
    
    std::string response = HttpPost(baseUrl_ + "/api/generate", request.dump());
    if (response.empty()) return "";
    
    try {
        json j = json::parse(response);
        return j.value("response", "");
    } catch (...) {
        return "";
    }
}

void Deep2BackendClient::GenerateStream(const std::string& prompt, int maxTokens,
                                         float temperature,
                                         std::function<void(const std::string&)> onToken) {
    std::string response = Generate(prompt, maxTokens, temperature);
    if (!response.empty() && onToken) {
        onToken(response);
    }
}

std::string Deep2BackendClient::Chat(const std::vector<std::pair<std::string, std::string>>& messages,
                                      int maxTokens, float temperature) {
    if (!connected_) return "";
    
    json request;
    request["max_tokens"] = maxTokens;
    request["temperature"] = temperature;
    request["stream"] = false;
    
    json msgs = json::array();
    for (const auto& msg : messages) {
        json m;
        m["role"] = msg.first;
        m["content"] = msg.second;
        msgs.push_back(m);
    }
    request["messages"] = msgs;
    
    std::string response = HttpPost(baseUrl_ + "/api/chat", request.dump());
    if (response.empty()) return "";
    
    try {
        json j = json::parse(response);
        if (j.contains("message")) {
            return j["message"].value("content", "");
        }
        return j.value("response", "");
    } catch (...) {
        return "";
    }
}

bool Deep2BackendClient::HealthCheck() {
    return Deep2Discovery::TestConnection(baseUrl_);
}

// ============================================================================
// Private Helpers
// ============================================================================

std::string Deep2BackendClient::HttpGet(const std::string& url) {
    return Deep2Discovery::HttpGet(url);
}

std::string Deep2BackendClient::HttpPost(const std::string& url, const std::string& body) {
    HINTERNET hSession = WinHttpOpen(L"Deep2BackendClient/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);
    
    if (!hSession) return "";
    
    std::wstring wUrl(url.begin(), url.end());
    URL_COMPONENTS urlComp = {};
    urlComp.dwStructSize = sizeof(urlComp);
    urlComp.dwSchemeLength = (DWORD)-1;
    urlComp.dwHostNameLength = (DWORD)-1;
    urlComp.dwUrlPathLength = (DWORD)-1;
    
    if (!WinHttpCrackUrl(wUrl.c_str(), (DWORD)wUrl.length(), 0, &urlComp)) {
        WinHttpCloseHandle(hSession);
        return "";
    }
    
    std::wstring hostName(urlComp.lpszHostName, urlComp.dwHostNameLength);
    std::wstring urlPath(urlComp.lpszUrlPath, urlComp.dwUrlPathLength);
    
    HINTERNET hConnect = WinHttpConnect(hSession, hostName.c_str(),
        urlComp.nPort, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return "";
    }
    
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", urlPath.c_str(),
        NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return "";
    }
    
    // Set timeout
    DWORD timeout = 30000;
    WinHttpSetOption(hRequest, WINHTTP_OPTION_RECEIVE_TIMEOUT,
        (void*)&timeout, sizeof(DWORD));
    
    // Add Content-Type header
    std::wstring headers = L"Content-Type: application/json\r\n";
    
    std::wstring wBody(body.begin(), body.end());
    
    BOOL sent = WinHttpSendRequest(hRequest, headers.c_str(), (DWORD)headers.length(),
        (LPVOID)wBody.c_str(), (DWORD)wBody.length() * sizeof(wchar_t), 
        (DWORD)wBody.length() * sizeof(wchar_t), 0);
    
    if (!sent) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return "";
    }
    
    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return "";
    }
    
    std::string response;
    DWORD dwSize = 0;
    DWORD dwDownloaded = 0;
    
    do {
        dwSize = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) break;
        
        if (dwSize > 0) {
            std::vector<char> buffer(dwSize + 1);
            ZeroMemory(buffer.data(), dwSize + 1);
            
            if (WinHttpReadData(hRequest, buffer.data(), dwSize, &dwDownloaded)) {
                response.append(buffer.data(), dwDownloaded);
            }
        }
    } while (dwSize > 0);
    
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    
    return response;
}

size_t Deep2BackendClient::ParseParamSize(const std::string& paramStr) {
    // Parse strings like "7B", "13B", "70B"
    if (paramStr.empty()) return 0;
    
    size_t multiplier = 1;
    std::string numStr = paramStr;
    
    if (paramStr.back() == 'B' || paramStr.back() == 'b') {
        numStr = paramStr.substr(0, paramStr.length() - 1);
    }
    
    if (paramStr.find('M') != std::string::npos || 
        paramStr.find('m') != std::string::npos) {
        multiplier = 1000000;
        numStr = paramStr.substr(0, paramStr.find_first_of("Mm"));
    } else if (paramStr.find('B') != std::string::npos || 
               paramStr.find('b') != std::string::npos) {
        multiplier = 1000000000;
    }
    
    try {
        float val = std::stof(numStr);
        return static_cast<size_t>(val * multiplier);
    } catch (...) {
        return 0;
    }
}

} // namespace Deep2
