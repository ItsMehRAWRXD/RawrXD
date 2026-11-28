// ScreenPilotModelHub.cpp — Screen Pilot / Remote Control (Batch 6 C05)
#include "ScreenPilotModelHub.h"
#include <windows.h>
#include <winhttp.h>
#include <string>

namespace ScreenPilot {

ModelHub& ModelHub::Instance() {
    static ModelHub inst;
    return inst;
}

bool ModelHub::Connect(const std::string& endpoint) {
    m_endpoint = endpoint;
    m_connected = true;
    return true;
}

void ModelHub::Disconnect() {
    m_connected = false;
}

bool ModelHub::IsConnected() const {
    return m_connected;
}

bool ModelHub::SendControlCommand(const std::string& command, std::string& response,
                                  std::string& error) {
    response.clear();
    error.clear();
    if (!m_connected || m_endpoint.empty() || command.empty()) {
        error = "not connected";
        return false;
    }

    std::string body = "{\"command\":\"";
    for (char c : command) {
        if (c == '\\' || c == '\"') body += '\\';
        body += c;
    }
    body += "\"}";

    URL_COMPONENTS uc{};
    uc.dwStructSize = sizeof(uc);
    wchar_t host[256] = {};
    wchar_t path[1024] = {};
    uc.lpszHostName = host;
    uc.dwHostNameLength = 255;
    uc.lpszUrlPath = path;
    uc.dwUrlPathLength = 1023;
    if (!WinHttpCrackUrl(std::wstring(m_endpoint.begin(), m_endpoint.end()).c_str(),
                         static_cast<DWORD>(m_endpoint.size()), 0, &uc)) {
        error = "invalid endpoint";
        return false;
    }

    HINTERNET session = WinHttpOpen(L"RawrXD/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                    WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) { error = "WinHttpOpen failed"; return false; }
    WinHttpSetTimeouts(session, 10000, 10000, 10000, 10000);
    HINTERNET connect = WinHttpConnect(session, host, uc.nPort, 0);
    if (!connect) { error = "WinHttpConnect failed"; WinHttpCloseHandle(session); return false; }
    HINTERNET request = WinHttpOpenRequest(connect, L"POST", path, nullptr,
                                           WINHTTP_NO_REFERER,
                                           WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!request) {
        error = "WinHttpOpenRequest failed";
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return false;
    }

    const wchar_t* headers = L"Content-Type: application/json\r\n";
    if (!WinHttpSendRequest(request, headers, static_cast<DWORD>(wcslen(headers)),
                            const_cast<char*>(body.data()), static_cast<DWORD>(body.size()),
                            static_cast<DWORD>(body.size()), 0) ||
        !WinHttpReceiveResponse(request, nullptr)) {
        error = "request failed";
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return false;
    }

    char buffer[4096];
    DWORD bytes = 0;
    do {
        bytes = 4096;
        if (!WinHttpReadData(request, buffer, bytes, &bytes) || bytes == 0) break;
        response.append(buffer, bytes);
    } while (bytes == 4096);

    DWORD status = 0;
    DWORD statusLen = sizeof(status);
    if (WinHttpQueryHeaders(request,
                            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &status, &statusLen,
                            WINHTTP_NO_HEADER_INDEX) && status != 200) {
        error = "HTTP status " + std::to_string(status);
    } else if (response.find("\"status\"") == std::string::npos) {
        error = "response missing status field";
    }

    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connect);
    WinHttpCloseHandle(session);
    return true;
}

} // namespace ScreenPilot
