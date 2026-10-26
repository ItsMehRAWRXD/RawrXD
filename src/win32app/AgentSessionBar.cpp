#include "AgentSession.hpp"
#include "AgentProduct.hpp"
#include "IdeAuthBoundary.hpp"
#include <string>
#include <thread>
#include <windows.h>

namespace {
HWND g_files = nullptr, g_terms = nullptr, g_diff = nullptr;
bool g_ready = false;
void Ensure() {
    RawrXD::IdeAuth::SetWorkspaceRoot("agent_gui_session");
    if (!g_ready) { AgentSessionBegin("agent_gui_session", nullptr, nullptr); g_ready = true; }
}
void Refresh() {
    if (g_files) SetWindowTextA(g_files, (std::to_string(AgentSessionFilesChanged()) + " Files Changed").c_str());
    if (g_terms) SetWindowTextA(g_terms, (std::to_string(AgentSessionTerminals()) + " terminals").c_str());
}
void OnCommand(int id) {
    if (id == 4103) {
        Ensure();
        DeleteFileA("agent_gui_session\\a.txt");
        DeleteFileA("agent_gui_session\\b.txt");
        AgentExecTool("write_file", "{\"path\":\"a.txt\",\"content\":\"alpha\"}", nullptr);
        AgentExecTool("write_file", "{\"path\":\"b.txt\",\"content\":\"beta\"}", nullptr);
    } else if (id == 4104) {
        Ensure();
        AgentExecTool("write_file", "{\"path\":\"a.txt\",\"content\":\"\"}", nullptr);
    } else if (id == 4101 && g_diff) {
        SetWindowTextA(g_diff, AgentSessionReviewFirst().c_str());
    } else if (id == 4105) {
        Ensure();
        _putenv("RAWRXD_IDE_EXEC_GRANT=1");
        std::thread([] { AgentRunCommand("execute_command", "{\"command\":\"ping -n 6 127.0.0.1\"}"); }).detach();
    } else if (id == 4102) {
        AgentSessionCancel();
    } else if (id == 4106) {
        AgentSessionNote note{};
        g_ready = AgentSessionRestore("agent_gui_session", &note);
    }
    Refresh();
}
LRESULT CALLBACK Proc(HWND hwnd, UINT msg, WPARAM w, LPARAM l) {
    if (msg == WM_TIMER) { Refresh(); return 0; }
    if (msg == WM_COMMAND) { OnCommand(LOWORD(w)); return 0; }
    return DefWindowProcW(hwnd, msg, w, l);
}
HWND Make(HWND parent, DWORD style) {
    static bool reg = false;
    if (!reg) {
        WNDCLASSW wc{}; wc.lpfnWndProc = Proc; wc.hInstance = GetModuleHandleW(nullptr);
        wc.lpszClassName = L"RawrXD_AgentSession"; wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
        RegisterClassW(&wc); reg = true;
    }
    HWND hwnd = CreateWindowExW(0, L"RawrXD_AgentSession", L"RawrXD IDE — Agent Session",
        style, 40, 40, 640, 280, parent, nullptr, GetModuleHandleW(nullptr), nullptr);
    g_files = CreateWindowExA(0, "STATIC", "0 Files Changed", WS_CHILD | WS_VISIBLE, 8, 8, 180, 24, hwnd, (HMENU)4110, nullptr, nullptr);
    g_terms = CreateWindowExA(0, "STATIC", "0 terminals", WS_CHILD | WS_VISIBLE, 200, 8, 140, 24, hwnd, (HMENU)4111, nullptr, nullptr);
    CreateWindowExA(0, "BUTTON", "Two edits", WS_CHILD | WS_VISIBLE, 8, 40, 100, 28, hwnd, (HMENU)4103, nullptr, nullptr);
    CreateWindowExA(0, "BUTTON", "Revert one", WS_CHILD | WS_VISIBLE, 116, 40, 100, 28, hwnd, (HMENU)4104, nullptr, nullptr);
    CreateWindowExA(0, "BUTTON", "Review", WS_CHILD | WS_VISIBLE, 224, 40, 80, 28, hwnd, (HMENU)4101, nullptr, nullptr);
    CreateWindowExA(0, "BUTTON", "Terminal", WS_CHILD | WS_VISIBLE, 312, 40, 90, 28, hwnd, (HMENU)4105, nullptr, nullptr);
    CreateWindowExA(0, "BUTTON", "Stop", WS_CHILD | WS_VISIBLE, 410, 40, 70, 28, hwnd, (HMENU)4102, nullptr, nullptr);
    CreateWindowExA(0, "BUTTON", "Restore", WS_CHILD | WS_VISIBLE, 488, 40, 80, 28, hwnd, (HMENU)4106, nullptr, nullptr);
    g_diff = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "", WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_AUTOVSCROLL,
        8, 80, 600, 150, hwnd, (HMENU)4112, nullptr, nullptr);
    SetTimer(hwnd, 1, 100, nullptr);
    Refresh();
    return hwnd;
}
}

void AgentSessionAttachBar(void* parentHwnd) {
    HWND parent = static_cast<HWND>(parentHwnd);
    Make(parent, parent ? (WS_CHILD | WS_VISIBLE) : (WS_OVERLAPPEDWINDOW | WS_VISIBLE));
}
