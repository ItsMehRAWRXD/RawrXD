// ============================================================================
// RawrXD HTTP Client - WinHTTP Implementation
// Zero external dependencies, native Windows API
// ============================================================================

#include "HttpClient.hpp"
#include <cstdio>

namespace RawrXD {
namespace Codex {

HttpClient::HttpClient() = default;

HttpClient::~HttpClient() {
    if (m_hSession) {
        WinHttpCloseHandle(m_hSession);
    }
}

bool HttpClient::Initialize(const std::wstring& userAgent) {
    m_hSession = WinHttpOpen(
        userAgent.c_str(),
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    );
    
    if (!m_hSession) {
        SetError("Failed to initialize WinHTTP session");
        return false;
    }
    
    return true;
}

void HttpClient::SetTimeout(int connectMs, int sendMs, int receiveMs) {
    if (!m_hSession) return;
    
    WinHttpSetTimeouts(m_hSession, connectMs, connectMs, sendMs, receiveMs);
}

bool HttpClient::Post(const std::wstring& url,
                      const std::string& headers,
                      const std::string& body,
                      std::string& response) {
    std::wstring server, path;
    INTERNET_PORT port;
    BOOL isHttps;
    
    if (!ParseUrl(url, server, path, port, isHttps)) {
        return false;
    }
    
    // Connect
    HINTERNET hConnect = WinHttpConnect(m_hSession, server.c_str(), port, 0);
    if (!hConnect) {
        SetError("Failed to connect");
        return false;
    }
    
    // Open request
    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect,
        L"POST",
        path.c_str(),
        nullptr,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        isHttps ? WINHTTP_FLAG_SECURE : 0
    );
    
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        SetError("Failed to open request");
        return false;
    }
    
    // Set headers
    std::wstring wHeaders(headers.begin(), headers.end());
    
    // Send request
    BOOL result = WinHttpSendRequest(
        hRequest,
        wHeaders.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : wHeaders.c_str(),
        (DWORD)wHeaders.length(),
        (LPVOID)body.c_str(),
        (DWORD)body.length(),
        (DWORD)body.length(),
        0
    );
    
    if (!result) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        SetError("Failed to send request");
        return false;
    }
    
    // Receive response
    result = WinHttpReceiveResponse(hRequest, nullptr);
    if (!result) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        SetError("Failed to receive response");
        return false;
    }
    
    // Read response
    bool success = ReadResponse(hRequest, response);
    
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    
    return success;
}

bool HttpClient::PostStreaming(const std::wstring& url,
                               const std::string& headers,
                               const std::string& body,
                               ResponseCallback callback) {
    std::wstring server, path;
    INTERNET_PORT port;
    BOOL isHttps;
    
    if (!ParseUrl(url, server, path, port, isHttps)) {
        return false;
    }
    
    // Connect
    HINTERNET hConnect = WinHttpConnect(m_hSession, server.c_str(), port, 0);
    if (!hConnect) {
        SetError("Failed to connect");
        return false;
    }
    
    // Open request
    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect,
        L"POST",
        path.c_str(),
        nullptr,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        isHttps ? WINHTTP_FLAG_SECURE : 0
    );
    
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        SetError("Failed to open request");
        return false;
    }
    
    // Set headers
    std::wstring wHeaders(headers.begin(), headers.end());
    
    // Send request
    BOOL result = WinHttpSendRequest(
        hRequest,
        wHeaders.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : wHeaders.c_str(),
        (DWORD)wHeaders.length(),
        (LPVOID)body.c_str(),
        (DWORD)body.length(),
        (DWORD)body.length(),
        0
    );
    
    if (!result) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        SetError("Failed to send request");
        return false;
    }
    
    // Receive response
    result = WinHttpReceiveResponse(hRequest, nullptr);
    if (!result) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        SetError("Failed to receive response");
        return false;
    }
    
    // Read response streaming
    bool success = ReadResponseStreaming(hRequest, callback);
    
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    
    return success;
}

bool HttpClient::ParseUrl(const std::wstring& url,
                          std::wstring& server,
                          std::wstring& path,
                          INTERNET_PORT& port,
                          BOOL& isHttps) {
    URL_COMPONENTS urlComp = {};
    urlComp.dwStructSize = sizeof(urlComp);
    
    wchar_t hostName[256] = {};
    wchar_t urlPath[1024] = {};
    
    urlComp.lpszHostName = hostName;
    urlComp.dwHostNameLength = _countof(hostName);
    urlComp.lpszUrlPath = urlPath;
    urlComp.dwUrlPathLength = _countof(urlPath);
    
    if (!WinHttpCrackUrl(url.c_str(), (DWORD)url.length(), 0, &urlComp)) {
        SetError("Failed to parse URL");
        return false;
    }
    
    server = hostName;
    path = urlPath;
    port = urlComp.nPort;
    isHttps = (urlComp.nScheme == INTERNET_SCHEME_HTTPS);
    
    return true;
}

bool HttpClient::ReadResponse(HINTERNET hRequest, std::string& response) {
    response.clear();
    
    DWORD bytesAvailable;
    while (WinHttpQueryDataAvailable(hRequest, &bytesAvailable) && bytesAvailable > 0) {
        std::vector<char> buffer(bytesAvailable);
        DWORD bytesRead;
        
        if (WinHttpReadData(hRequest, buffer.data(), bytesAvailable, &bytesRead)) {
            response.append(buffer.data(), bytesRead);
        } else {
            SetError("Failed to read data");
            return false;
        }
    }
    
    return true;
}

bool HttpClient::ReadResponseStreaming(HINTERNET hRequest, ResponseCallback callback) {
    std::string buffer;
    buffer.reserve(4096);
    
    DWORD bytesAvailable;
    while (WinHttpQueryDataAvailable(hRequest, &bytesAvailable) && bytesAvailable > 0) {
        std::vector<char> chunk(bytesAvailable);
        DWORD bytesRead;
        
        if (WinHttpReadData(hRequest, chunk.data(), bytesAvailable, &bytesRead)) {
            callback(std::string(chunk.data(), bytesRead), false);
        } else {
            SetError("Failed to read data");
            return false;
        }
    }
    
    callback("", true); // Signal completion
    return true;
}

void HttpClient::SetError(const char* msg) {
    m_lastError = msg;
}

} // namespace Codex
} // namespace RawrXD
