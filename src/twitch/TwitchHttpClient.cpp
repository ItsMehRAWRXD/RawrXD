/* TwitchHttpClient.cpp */
#include "TwitchHttpClient.hpp"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")
#endif

namespace RawrXD {
namespace Twitch {

TwitchHttpClient::TwitchHttpClient(const std::string& accessToken)
    : token_(accessToken) {}

void TwitchHttpClient::SetAccessToken(const std::string& token) noexcept {
    token_ = token;
}

bool TwitchHttpClient::Get(const std::string& url, std::string& outResponse) noexcept {
    return request(url, "GET", {}, {}, outResponse);
}

bool TwitchHttpClient::Post(const std::string& url,
                            const std::string& contentType,
                            const std::string& body,
                            std::string& outResponse) noexcept {
    return request(url, "POST", contentType, body, outResponse);
}

bool TwitchHttpClient::Delete(const std::string& url, std::string& outResponse) noexcept {
    return request(url, "DELETE", {}, {}, outResponse);
}

#ifdef _WIN32
static bool DoRequest(const std::string& url,
                      const std::string& method,
                      const std::string& contentType,
                      const std::string& body,
                      const std::string& authToken,
                      std::string& outResponse) {
    URL_COMPONENTSA uc{};
    uc.dwStructSize = sizeof(uc);
    char host[256]{};
    char path[1024]{};
    uc.lpszHostName = host;
    uc.dwHostNameLength = sizeof(host);
    uc.lpszUrlPath = path;
    uc.dwUrlPathLength = sizeof(path);
    if (!WinHttpCrackUrlA(url.c_str(), static_cast<DWORD>(url.size()), 0, &uc))
        return false;

    HINTERNET hSession = WinHttpOpen(L"RawrXD_TwitchBot/1.0",
                                     WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                     WINHTTP_NO_PROXY_NAME,
                                     WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return false;

    HINTERNET hConnect = WinHttpConnectA(hSession, host, uc.nPort, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return false; }

    HINTERNET hRequest = WinHttpOpenRequestA(hConnect, method.c_str(), path,
                                               nullptr, WINHTTP_NO_REFERER,
                                               WINHTTP_DEFAULT_ACCEPT_TYPES,
                                               (uc.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0);
    if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return false; }

    std::string headers;
    if (!authToken.empty()) {
        headers += "Authorization: Bearer " + authToken + "\r\n";
    }
    if (!contentType.empty()) {
        headers += "Content-Type: " + contentType + "\r\n";
    }
    if (!headers.empty()) {
        WinHttpAddRequestHeadersA(hRequest, headers.c_str(),
                                  static_cast<DWORD>(headers.size()),
                                  WINHTTP_ADDREQ_FLAG_ADD);
    }

    const char* bodyPtr = body.empty() ? nullptr : body.data();
    DWORD bodyLen = static_cast<DWORD>(body.size());
    BOOL sent = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                   const_cast<void*>(static_cast<const void*>(bodyPtr)),
                                   bodyLen, bodyLen, 0);
    if (!sent) { WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return false; }

    if (!WinHttpReceiveResponse(hRequest, nullptr)) {
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession);
        return false;
    }

    DWORD status = 0;
    DWORD statusSize = sizeof(status);
    WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX, &status, &statusSize, WINHTTP_NO_HEADER_INDEX);

    outResponse.clear();
    DWORD total = 0;
    for (;;) {
        DWORD avail = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &avail)) break;
        if (avail == 0) break;
        std::string chunk(avail, '\0');
        DWORD read = 0;
        WinHttpReadData(hRequest, chunk.data(), avail, &read);
        if (read == 0) break;
        outResponse.append(chunk.data(), read);
        total += read;
        if (total > 8 * 1024 * 1024) break;
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return (status >= 200 && status < 300);
}
#else
static bool DoRequest(const std::string&, const std::string&, const std::string&, const std::string&, const std::string&, std::string&) { return false; }
#endif

bool TwitchHttpClient::request(const std::string& url,
                               const std::string& method,
                               const std::string& contentType,
                               const std::string& body,
                               std::string& outResponse) noexcept {
    return DoRequest(url, method, contentType, body, token_, outResponse);
}

bool TwitchHttpClient::UrlEncode(const std::string& in, std::string& out) noexcept {
    out.clear();
    for (unsigned char c : in) {
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            out += static_cast<char>(c);
        } else if (c == ' ') {
            out += '+';
        } else {
            char buf[4];
            std::snprintf(buf, sizeof(buf), "%%%02X", c);
            out += buf;
        }
    }
    return true;
}

} // namespace Twitch
} // namespace RawrXD
