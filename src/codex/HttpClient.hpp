#pragma once
#include <string>
#include <functional>
#include <windows.h>
#include <winhttp.h>

#pragma comment(lib, "winhttp.lib")

namespace RawrXD {
namespace Codex {

// Lightweight HTTP client using WinHTTP
class HttpClient {
public:
    using ResponseCallback = std::function<void(const std::string& chunk, bool isFinal)>;
    
    HttpClient();
    ~HttpClient();
    
    // Initialize session
    bool Initialize(const std::wstring& userAgent = L"RawrXD-Codex/1.0");
    
    // POST request (blocking)
    bool Post(const std::wstring& url, 
              const std::string& headers,
              const std::string& body,
              std::string& response);
    
    // POST request (streaming)
    bool PostStreaming(const std::wstring& url,
                       const std::string& headers,
                       const std::string& body,
                       ResponseCallback callback);
    
    // Set timeout
    void SetTimeout(int connectMs, int sendMs, int receiveMs);
    
    // Get last error
    const char* GetLastError() const { return m_lastError.c_str(); }
    
private:
    HINTERNET m_hSession = nullptr;
    std::string m_lastError;
    
    // Parse URL into components
    bool ParseUrl(const std::wstring& url, 
                  std::wstring& server,
                  std::wstring& path,
                  INTERNET_PORT& port,
                  BOOL& isHttps);
    
    // Read response
    bool ReadResponse(HINTERNET hRequest, std::string& response);
    bool ReadResponseStreaming(HINTERNET hRequest, ResponseCallback callback);
    
    // Set error
    void SetError(const char* msg);
};

} // namespace Codex
} // namespace RawrXD
