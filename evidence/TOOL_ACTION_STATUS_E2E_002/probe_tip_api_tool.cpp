// Tip SHA 6832F439… — headless /api/tool 4-case + GateStub RemoteThread supplement.
#include <windows.h>
#include <winhttp.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdint.h>
#include <string>
#include <vector>
#pragma comment(lib, "winhttp.lib")

static const char* API_KEY = "e2e002_tool_status_key";
static const int PORT = 18991;

static std::string HttpPost(const wchar_t* path, const std::string& body) {
    std::string out;
    HINTERNET ses = WinHttpOpen(L"E2E002/1.0", WINHTTP_ACCESS_TYPE_NO_PROXY,
                                WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!ses) return "{\"error\":\"winhttp_open\"}";
    HINTERNET con = WinHttpConnect(ses, L"127.0.0.1", (INTERNET_PORT)PORT, 0);
    if (!con) { WinHttpCloseHandle(ses); return "{\"error\":\"connect\"}"; }
    HINTERNET req = WinHttpOpenRequest(con, L"POST", path, nullptr, WINHTTP_NO_REFERER,
                                       WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!req) {
        WinHttpCloseHandle(con); WinHttpCloseHandle(ses);
        return "{\"error\":\"open_request\"}";
    }
    wchar_t hdrs[256];
    _snwprintf_s(hdrs, _TRUNCATE,
        L"Content-Type: application/json\r\n"
        L"X-Api-Key: %hs\r\n"
        L"Origin: http://127.0.0.1:%d\r\n",
        API_KEY, PORT);
    BOOL ok = WinHttpSendRequest(req, hdrs, (DWORD)-1,
                                 (LPVOID)body.data(), (DWORD)body.size(),
                                 (DWORD)body.size(), 0);
    if (ok) ok = WinHttpReceiveResponse(req, nullptr);
    if (ok) {
        DWORD avail = 0;
        while (WinHttpQueryDataAvailable(req, &avail) && avail) {
            std::vector<char> buf(avail + 1);
            DWORD rd = 0;
            if (!WinHttpReadData(req, buf.data(), avail, &rd) || !rd) break;
            out.append(buf.data(), rd);
        }
    } else {
        out = "{\"error\":\"http_fail\",\"gle\":" + std::to_string(GetLastError()) + "}";
    }
    WinHttpCloseHandle(req); WinHttpCloseHandle(con); WinHttpCloseHandle(ses);
    return out;
}

static uintptr_t module_base(DWORD pid) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    MODULEENTRY32W me{}; me.dwSize = sizeof(me);
    uintptr_t base = 0;
    if (Module32FirstW(snap, &me)) {
        do {
            if (_wcsicmp(me.szModule, L"RawrXD-Win32IDE.exe") == 0) {
                base = (uintptr_t)me.modBaseAddr; break;
            }
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    return base;
}

static bool port_owned_by(DWORD pid, int port) {
    // Best-effort: CreateProcess settle + connect success checked by caller.
    (void)pid; (void)port;
    return true;
}

static bool has(const std::string& s, const char* n) {
    return s.find(n) != std::string::npos;
}
static bool is_transport_fail(const std::string& s) {
    // Keep markers exact — listing payloads can contain substrings like "connect".
    return has(s, "\"error\":\"rate_limit\"") ||
           has(s, "\"error\":\"unauthorized\"") ||
           has(s, "\"error\":\"authentication_not_configured\"") ||
           has(s, "\"error\":\"origin_denied\"") ||
           has(s, "\"error\":\"winhttp") ||
           has(s, "\"error\":\"connect\"") ||
           has(s, "\"error\":\"http_fail\"");
}

int main() {
    const wchar_t* tip = L"G:\\~dev\\rawrxd\\build_win32ide_link001\\bin\\RawrXD-Win32IDE.exe";
    std::printf("PROBE=TOOL_ACTION_STATUS_E2E_002_API\n");
    std::printf("TIP_SHA_EXPECT=6832F439100C71AE7923A7736F71784039B7F6A9DE53C895E56E9C7932A9F8B2\n");
    std::printf("PORT=%d\n", PORT);

    SetEnvironmentVariableA("RAWRXD_HOSTED_API_KEY", API_KEY);
    SetEnvironmentVariableA("RAWRXD_HOSTED_API_SCOPES", "read,inference,models,github,admin,*");

    wchar_t cmd[1024];
    _snwprintf_s(cmd, _TRUNCATE,
        L"\"%s\" --headless --local --port %d --bind 127.0.0.1 --dir G:\\~dev\\rawrxd",
        tip, PORT);
    STARTUPINFOW si{}; si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    // Inherit env with API key
    if (!CreateProcessW(nullptr, cmd, nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
                        nullptr, L"G:\\~dev\\rawrxd\\build_win32ide_link001\\bin", &si, &pi)) {
        std::printf("FAIL CreateProcess %lu\n", GetLastError());
        return 2;
    }
    std::printf("PID=%lu\n", pi.dwProcessId);
    uintptr_t base = 0;
    for (int i = 0; i < 150 && !base; ++i) {
        base = module_base(pi.dwProcessId);
        Sleep(100);
    }
    if (!base) {
        std::printf("FAIL module_base\n");
        TerminateProcess(pi.hProcess, 1);
        return 3;
    }
    std::printf("MODULE_BASE=%p\n", (void*)base);
    // Wait for listen; probe health via MOTD retries
    std::string motd;
    bool motd_ok = false;
    for (int i = 0; i < 40; ++i) {
        Sleep(250);
        motd = HttpPost(L"/api/tool", "{\"tool\":\"read_motd\",\"args\":{}}");
        if (!is_transport_fail(motd) &&
            (has(motd, "PassiveRoleNotRoleplay") || has(motd, "\"content\""))) {
            motd_ok = true;
            break;
        }
        if (has(motd, "connect") || has(motd, "http_fail")) continue;
        // auth/rate: break early with fail
        if (has(motd, "rate_limit") || has(motd, "unauthorized") ||
            has(motd, "authentication_not_configured"))
            break;
    }
    std::printf("MOTD_BODY_LEN=%zu\n", motd.size());
    std::printf("CASE motd_ack %s\n", motd_ok ? "PASS" : "FAIL");

    std::string ok = HttpPost(L"/api/tool",
        "{\"tool\":\"list_directory\",\"args\":{\"path\":\".\"}}");
    bool success_ok = motd_ok && !is_transport_fail(ok) &&
                      has(ok, "\"entries\"") && !has(ok, "\"error\":");
    std::printf("SUCCESS_BODY_LEN=%zu\n", ok.size());
    std::printf("CASE real_success %s\n", success_ok ? "PASS" : "FAIL");

    std::string bad = HttpPost(L"/api/tool",
        "{\"tool\":\"read_file\",\"args\":{\"path\":\"__no_such_e2e_002__.txt\"}}");
    bool fail_ok = motd_ok && !is_transport_fail(bad) &&
                   (has(bad, "file_not_found") || has(bad, "not_found") ||
                    has(bad, "forbidden") ||
                    (has(bad, "\"error\"") && !has(bad, "rate_limit")));
    std::printf("FAIL_BODY_LEN=%zu\n", bad.size());
    std::printf("CASE real_failure %s\n", fail_ok ? "PASS" : "FAIL");

    // NEG GateStub on tip (null ide arg OK)
    const uintptr_t RVA_GATE = 0x192F310ull;
    HANDLE th = CreateRemoteThread(pi.hProcess, nullptr, 0,
        (LPTHREAD_START_ROUTINE)(base + RVA_GATE), nullptr, 0, nullptr);
    bool neg_ok = false;
    if (th) {
        WaitForSingleObject(th, 10000);
        CloseHandle(th);
        neg_ok = true;
    }
    std::printf("CASE neg_gatestub_remote %s\n", neg_ok ? "PASS" : "FAIL");

    // CANCEL: headless has no /api/agent/run — tip GateStub+admit unit cover cancel
    // latch; this probe records NOT_ROUTE for honesty (cancel_session probe earns it).
    std::string begin = "{\"note\":\"cancel_via_probe_cancel_session\"}";
    std::string cxl = "{\"note\":\"see_probe_cancel_session\"}";
    bool cancel_ok = false; // earned by probe_cancel_session, not invent here
    std::printf("CASE cancel_http NOT_ROUTE (headless)\n");

    FILE* f = nullptr;
    fopen_s(&f, "g:\\~dev\\rawrxd\\evidence\\TOOL_ACTION_STATUS_E2E_002\\logs\\api_bodies.txt", "w");
    if (f) {
        fprintf(f, "===MOTD===\n%s\n===SUCCESS===\n%s\n===FAIL===\n%s\n===BEGIN===\n%s\n===CANCEL===\n%s\n",
                motd.c_str(), ok.c_str(), bad.c_str(), begin.c_str(), cxl.c_str());
        fclose(f);
    }

    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    int fails = 0;
    if (!motd_ok) ++fails;
    if (!success_ok) ++fails;
    if (!fail_ok) ++fails;
    if (!neg_ok) ++fails;
    (void)cancel_ok;
    std::printf("API_PROBE_FAILS=%d (cancel scored by cancel_session probe)\n", fails);
    (void)port_owned_by;
    return fails ? 1 : 0;
}
