#include "AgentSession.hpp"
#include <cstdio>
#include <string>
#include <windows.h>

static std::string TextOf(HWND parent, int id) {
    char buf[128] = {};
    GetWindowTextA(GetDlgItem(parent, id), buf, sizeof(buf));
    return buf;
}

static bool WaitText(HWND hwnd, int id, const char* want, int ms) {
    DWORD end = GetTickCount() + ms;
    while (GetTickCount() < end) {
        MSG msg;
        while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg); DispatchMessageW(&msg);
        }
        if (TextOf(hwnd, id) == want) return true;
        Sleep(15);
    }
    return TextOf(hwnd, id) == want;
}

int AgentSessionGuiProof() {
    HWND hwnd = nullptr;
    AgentSessionAttachBar(nullptr);
    hwnd = FindWindowW(L"RawrXD_AgentSession", L"RawrXD IDE — Agent Session");
    if (!hwnd) { std::printf("AGENT_GUI_PROOF FAIL window\n"); return 1; }
    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);
    auto click = [&](int id) { SendMessageW(hwnd, WM_COMMAND, id, 0); };
    click(4103);
    if (TextOf(hwnd, 4110) != "2 Files Changed") { std::printf("AGENT_GUI_PROOF FAIL two\n"); return 1; }
    click(4104);
    if (TextOf(hwnd, 4110) != "1 Files Changed") { std::printf("AGENT_GUI_PROOF FAIL revert\n"); return 1; }
    click(4101);
    char diff[256] = {};
    GetWindowTextA(GetDlgItem(hwnd, 4112), diff, sizeof(diff));
    if (std::string(diff).find("beta") == std::string::npos) { std::printf("AGENT_GUI_PROOF FAIL review\n"); return 1; }
    click(4105);
    if (!WaitText(hwnd, 4111, "1 terminals", 3000)) { std::printf("AGENT_GUI_PROOF FAIL terminal\n"); return 1; }
    click(4102);
    if (!WaitText(hwnd, 4111, "0 terminals", 3000)) { std::printf("AGENT_GUI_PROOF FAIL stop\n"); return 1; }
    uint64_t sid = 0;
    { AgentSessionNote n{}; AgentSessionRestore("agent_gui_session", &n); sid = n.sessionId; }
    AgentSessionAbandonLive();
    DestroyWindow(hwnd);
    AgentSessionAttachBar(nullptr);
    hwnd = FindWindowW(L"RawrXD_AgentSession", L"RawrXD IDE — Agent Session");
    SendMessageW(hwnd, WM_COMMAND, 4106, 0);
    if (TextOf(hwnd, 4110) != "1 Files Changed" || TextOf(hwnd, 4111) != "0 terminals") {
        std::printf("AGENT_GUI_PROOF FAIL restore\n"); return 1;
    }
    std::printf("AGENT_GUI_PROOF files=1 review=1 stop=1 restore=1 session=%llu\n",
                static_cast<unsigned long long>(sid));
    DestroyWindow(hwnd);
    return 0;
}
