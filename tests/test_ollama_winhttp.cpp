/**
 * @file test_ollama_winhttp.cpp
 * @brief Test WinHTTP Ollama integration directly
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>
#include <iostream>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>

#pragma comment(lib, "winhttp.lib")

using json = nlohmann::json;

auto logDebug = [](const char* fmt, ...) {
    char buf[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    OutputDebugStringA(buf);
    FILE* f = fopen("F:\\rawrxd\\ollama_debug.log", "a");
    if (f) {
        fprintf(f, "%s", buf);
        fclose(f);
    }
};

int main() {
    std::cout << "=== Testing Ollama WinHTTP directly ===\n\n";
    
    std::string model = "nemotron-3-nano:4b";
    std::string prompt = "Reply with exactly RAWRXD_CHAT_OK";
    int maxTokens = 128;
    std::string baseUrl = "http://127.0.0.1:11434";
    
    std::cout << "Model: " << model << "\n";
    std::cout << "Prompt: " << prompt << "\n\n";
    
    // Parse URL
    std::string url = baseUrl;
    size_t scheme = url.find("://");
    if (scheme == std::string::npos) {
        std::cerr << "Invalid URL\n";
        return 1;
    }
    bool https = url.compare(0, scheme, "https") == 0;
    size_t authorityStart = scheme + 3;
    size_t pathStart = url.find('/', authorityStart);
    std::string authority = url.substr(authorityStart,
        pathStart == std::string::npos ? std::string::npos : pathStart - authorityStart);
    size_t colon = authority.rfind(':');
    std::string host = colon == std::string::npos ? authority : authority.substr(0, colon);
    INTERNET_PORT port = colon == std::string::npos
        ? (https ? INTERNET_DEFAULT_HTTPS_PORT : static_cast<INTERNET_PORT>(11434))
        : static_cast<INTERNET_PORT>(std::atoi(authority.c_str() + colon + 1));
    if (host.empty() || port == 0) {
        std::cerr << "Invalid host/port\n";
        return 1;
    }
    
    std::cout << "Connecting to " << host << ":" << port << "\n";
    
    json bodyJson = {
        {"model", model}, {"prompt", "Reply with exactly RAWRXD_CHAT_OK"}, {"stream", false},
        {"options", {{"num_predict", 128}}}
    };
    std::string body = bodyJson.dump();
    std::wstring wideHost(host.begin(), host.end());
    
    HINTERNET session = WinHttpOpen(L"RawrXD Test/1.0", WINHTTP_ACCESS_TYPE_NO_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) {
        std::cerr << "WinHttpOpen failed: " << GetLastError() << "\n";
        return 1;
    }
    WinHttpSetTimeouts(session, 1500, 1500, 30000, 30000);
    HINTERNET connect = WinHttpConnect(session, std::wstring(host.begin(), host.end()).c_str(), port, 0);
    if (!connect) {
        std::cerr << "WinHttpConnect failed: " << GetLastError() << "\n";
        WinHttpCloseHandle(session);
        return 1;
    }
    DWORD flags = 0;
    HINTERNET request = WinHttpOpenRequest(connect, L"POST", L"/api/generate", nullptr,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!request) {
        std::cerr << "WinHttpOpenRequest failed: " << GetLastError() << "\n";
        WinHttpCloseHandle(connect); WinHttpCloseHandle(session);
        return 1;
    }
    
    std::string raw;
    const wchar_t headers[] = L"Content-Type: application/json\r\n";
    if (WinHttpSendRequest(request, headers, static_cast<DWORD>(-1L),
            const_cast<char*>(bodyJson.dump().data()), static_cast<DWORD>(bodyJson.dump().size()),
            static_cast<DWORD>(bodyJson.dump().size()), 0) && WinHttpReceiveResponse(request, nullptr)) {
        DWORD available = 0;
        while (WinHttpQueryDataAvailable(request, &available) && available) {
            std::string chunk(available, '\0');
            DWORD read = 0;
            if (!WinHttpReadData(request, chunk.data(), available, &read) || !read) break;
            raw.append(chunk.data(), read);
        }
    } else {
        std::cerr << "WinHttpSendRequest/ReceiveResponse failed: " << GetLastError() << "\n";
    }
    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connect);
    WinHttpCloseHandle(session);
    
    std::cout << "Raw response length: " << raw.length() << "\n";
    if (!raw.empty()) {
        std::cout << "Raw response (first 500 chars): " << raw.substr(0, 500) << "\n";
    }
    
    try {
        auto response = json::parse(raw);
        if (response.contains("response") && response["response"].is_string()) {
            std::string result = response["response"].get<std::string>();
            std::cout << "\n=== SUCCESS ===\n";
            std::cout << "Response: " << result << "\n";
            std::cout << "Length: " << result.length() << "\n";
            return 0;
        } else {
            std::cerr << "Response missing 'response' field\n";
        }
    } catch (const std::exception& e) {
        std::cerr << "JSON parse error: " << e.what() << "\n";
    }
    
    return 1;
}