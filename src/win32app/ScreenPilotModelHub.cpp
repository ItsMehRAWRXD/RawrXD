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

void ModelHub::SendControlCommand(const std::string& command) {
    if (!m_connected || m_endpoint.empty() || command.empty()) return;

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
        return;
    }

    HINTERNET session = WinHttpOpen(L"RawrXD/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                    WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) return;
    HINTERNET connect = WinHttpConnect(session, host, uc.nPort, 0);
    if (!connect) { WinHttpCloseHandle(session); return; }
    HINTERNET request = WinHttpOpenRequest(connect, L"POST", path, nullptr,
                                           WINHTTP_NO_REFERER,
                                           WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!request) {
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return;
    }

    const wchar_t* headers = L"Content-Type: application/json\r\n";
    WinHttpSendRequest(request, headers, static_cast<DWORD>(wcslen(headers)),
                       const_cast<char*>(body.data()), static_cast<DWORD>(body.size()),
                       static_cast<DWORD>(body.size()), 0);
    WinHttpReceiveResponse(request, nullptr);

    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connect);
    WinHttpCloseHandle(session);
}

} // namespace ScreenPilot
