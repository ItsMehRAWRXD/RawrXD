// Win32IDE_SwarmOllamaHttpTags.cpp — local Ollama /api/tags discovery (127.0.0.1)
#include "Win32IDE_SwarmModelSelector.h"

#include <windows.h>
#include <winhttp.h>

#include <cstdlib>
#include <string>
#include <vector>

#pragma comment(lib, "winhttp.lib")

namespace RawrXD {
namespace Win32App {
namespace {

bool envTruthy(const char* v) {
    return v && v[0] && v[0] != '0' &&
           !(v[0] == 'f' || v[0] == 'F' || v[0] == 'n' || v[0] == 'N');
}

void parseTagNames(const std::string& body, std::vector<std::string>& out,
                   unsigned maxEntries) {
    // Minimal JSON walk: "name":"<tag>" — skip *:cloud
    size_t pos = 0;
    while (out.size() < maxEntries) {
        const size_t k = body.find("\"name\"", pos);
        if (k == std::string::npos) break;
        const size_t colon = body.find(':', k + 6);
        if (colon == std::string::npos) break;
        const size_t q1 = body.find('"', colon + 1);
        if (q1 == std::string::npos) break;
        const size_t q2 = body.find('"', q1 + 1);
        if (q2 == std::string::npos) break;
        std::string name = body.substr(q1 + 1, q2 - q1 - 1);
        pos = q2 + 1;
        if (name.empty() || name.find(":cloud") != std::string::npos) continue;
        if (name.find("ollama.com") != std::string::npos) continue;
        out.push_back(name);
    }
}

} // namespace

void appendLocalOllamaHttpTags(std::vector<std::string>& out, unsigned maxEntries) {
    if (out.size() >= maxEntries) return;
    if (envTruthy(std::getenv("LOCAL_ONLY_NO_OLLAMA"))) return;

    HINTERNET ses = WinHttpOpen(L"RawrXD-SwarmTags/1.0", WINHTTP_ACCESS_TYPE_NO_PROXY,
                                WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!ses) return;
    WinHttpSetTimeouts(ses, 1500, 1500, 1500, 3000);
    HINTERNET con = WinHttpConnect(ses, L"127.0.0.1", 11434, 0);
    if (!con) {
        WinHttpCloseHandle(ses);
        return;
    }
    HINTERNET req = WinHttpOpenRequest(con, L"GET", L"/api/tags", nullptr,
                                       WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!req) {
        WinHttpCloseHandle(con);
        WinHttpCloseHandle(ses);
        return;
    }
    std::string body;
    if (WinHttpSendRequest(req, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
        WinHttpReceiveResponse(req, nullptr)) {
        for (;;) {
            DWORD avail = 0;
            if (!WinHttpQueryDataAvailable(req, &avail) || avail == 0) break;
            std::string chunk(avail, '\0');
            DWORD got = 0;
            if (!WinHttpReadData(req, chunk.data(), avail, &got)) break;
            body.append(chunk.data(), got);
        }
    }
    WinHttpCloseHandle(req);
    WinHttpCloseHandle(con);
    WinHttpCloseHandle(ses);
    if (!body.empty()) parseTagNames(body, out, maxEntries);
}

} // namespace Win32App
} // namespace RawrXD
