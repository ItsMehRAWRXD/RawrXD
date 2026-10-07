/* TwitchOAuth.cpp — Device Code Grant + WinHTTP HTTPS */
#include "TwitchOAuth.hpp"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")
#endif

#include <cstring>
#include <thread>
#include <chrono>

namespace RawrXD {
namespace Twitch {

TwitchOAuth::TwitchOAuth(const std::string& clientId, LogFn log)
    : clientId_(clientId), log_(std::move(log)) {}

static void LogRaw(LogFn& log, const char* msg) {
    if (log) log(msg);
}

#ifdef _WIN32

static bool WinHttpRequest(const std::string& url,
                           const std::string& method,
                           const std::string& body,
                           const std::string& authHeader,
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
                                               (uc.nScheme == INTERNET_SCHEME_HTTPS)
                                                   ? WINHTTP_FLAG_SECURE : 0);
    if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return false; }

    if (!authHeader.empty()) {
        WinHttpAddRequestHeadersA(hRequest, authHeader.c_str(),
                                  static_cast<DWORD>(authHeader.size()),
                                  WINHTTP_ADDREQ_FLAG_ADD);
    }

    BOOL sent = WinHttpSendRequest(hRequest,
                                   L"Content-Type: application/x-www-form-urlencoded\r\n",
                                   static_cast<DWORD>(-1L),
                                   const_cast<char*>(body.data()),
                                   static_cast<DWORD>(body.size()),
                                   static_cast<DWORD>(body.size()), 0);
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
        if (total > 8 * 1024 * 1024) break; /* 8 MB safety limit */
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return (status >= 200 && status < 300);
}

#else
static bool WinHttpRequest(const std::string&, const std::string&, const std::string&, const std::string&, std::string&) { return false; }
#endif

bool TwitchOAuth::HttpPost(const std::string& url,
                           const std::string& body,
                           std::string& outResponse,
                           const std::string& authHeader) noexcept {
    return WinHttpRequest(url, "POST", body, authHeader, outResponse);
}

/* Minimal JSON parse helpers — sufficient for Twitch token/device responses */
static std::string ExtractJsonString(const std::string& json, const char* key) {
    std::string k = std::string("\"") + key + "\":";
    size_t pos = json.find(k);
    if (pos == std::string::npos) {
        /* try without quotes around key */
        k = std::string("\"") + key + "\" :";
        pos = json.find(k);
        if (pos == std::string::npos) return "";
    }
    pos += k.size();
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t')) ++pos;
    if (pos >= json.size()) return "";
    bool quoted = (json[pos] == '"');
    if (quoted) {
        size_t end = json.find('"', pos + 1);
        if (end == std::string::npos) return "";
        return json.substr(pos + 1, end - pos - 1);
    } else {
        size_t end = json.find_first_of(",}\r\n", pos);
        if (end == std::string::npos) end = json.size();
        return json.substr(pos, end - pos);
    }
}

static uint32_t ExtractJsonUint(const std::string& json, const char* key) {
    std::string s = ExtractJsonString(json, key);
    return static_cast<uint32_t>(std::strtoul(s.c_str(), nullptr, 10));
}

bool TwitchOAuth::ParseJsonDevice(const std::string& json, OAuthDeviceCode& out) noexcept {
    out.deviceCode   = ExtractJsonString(json, "device_code");
    out.userCode     = ExtractJsonString(json, "user_code");
    out.verificationUri = ExtractJsonString(json, "verification_uri");
    if (out.verificationUri.empty()) out.verificationUri = ExtractJsonString(json, "verification_uri_complete");
    out.expiresIn    = ExtractJsonUint(json, "expires_in");
    out.interval     = ExtractJsonUint(json, "interval");
    return !out.deviceCode.empty();
}

bool TwitchOAuth::ParseJsonToken(const std::string& json, OAuthTokenResponse& out) noexcept {
    out.accessToken  = ExtractJsonString(json, "access_token");
    out.refreshToken = ExtractJsonString(json, "refresh_token");
    out.tokenType    = ExtractJsonString(json, "token_type");
    out.expiresIn    = ExtractJsonUint(json, "expires_in");
    out.scope        = ExtractJsonString(json, "scope");
    return !out.accessToken.empty();
}

bool TwitchOAuth::RequestDeviceCode(OAuthDeviceCode& out) noexcept {
    std::string body = "client_id=" + clientId_ +
                       "&scopes=user:read:chat+user:write:chat";
    std::string resp;
    if (!HttpPost("https://id.twitch.tv/oauth2/device", body, resp)) {
        LogRaw(log_, "[OAuth] Device code request failed\n");
        return false;
    }
    if (!ParseJsonDevice(resp, out)) {
        LogRaw(log_, "[OAuth] Failed to parse device code response\n");
        return false;
    }
    return true;
}

bool TwitchOAuth::PollForToken(const OAuthDeviceCode& device,
                               OAuthTokenResponse& out,
                               uint32_t maxTotalSeconds) noexcept {
    uint32_t elapsed = 0;
    uint32_t intervalSec = device.interval ? device.interval : 5;
    while (elapsed < maxTotalSeconds && elapsed < device.expiresIn) {
        std::this_thread::sleep_for(std::chrono::seconds(intervalSec));
        elapsed += intervalSec;

        std::string body = "client_id=" + clientId_ +
                           "&device_code=" + device.deviceCode +
                           "&grant_type=urn:ietf:params:oauth:grant-type:device_code";
        std::string resp;
        if (!HttpPost("https://id.twitch.tv/oauth2/token", body, resp)) {
            LogRaw(log_, "[OAuth] Token poll POST failed\n");
            continue;
        }
        std::string error = ExtractJsonString(resp, "error");
        if (error == "authorization_pending") {
            continue; /* normal — user hasn't confirmed yet */
        }
        if (error == "slow_down") {
            intervalSec += 5;
            continue;
        }
        if (error == "expired_token" || error == "access_denied") {
            LogRaw(log_, "[OAuth] Device code expired or denied\n");
            return false;
        }
        if (!error.empty()) {
            LogRaw(log_, "[OAuth] Unknown error during poll\n");
            return false;
        }
        return ParseJsonToken(resp, out);
    }
    LogRaw(log_, "[OAuth] Poll timeout\n");
    return false;
}

bool TwitchOAuth::RefreshToken(const std::string& refreshToken,
                               OAuthTokenResponse& out) noexcept {
    std::string body = "client_id=" + clientId_ +
                       "&refresh_token=" + refreshToken +
                       "&grant_type=refresh_token";
    std::string resp;
    if (!HttpPost("https://id.twitch.tv/oauth2/token", body, resp)) {
        LogRaw(log_, "[OAuth] Refresh token POST failed\n");
        return false;
    }
    return ParseJsonToken(resp, out);
}

bool TwitchOAuth::RevokeToken(const std::string& token) noexcept {
    std::string body = "client_id=" + clientId_ + "&token=" + token;
    std::string resp;
    return HttpPost("https://id.twitch.tv/oauth2/revoke", body, resp);
}

} // namespace Twitch
} // namespace RawrXD
