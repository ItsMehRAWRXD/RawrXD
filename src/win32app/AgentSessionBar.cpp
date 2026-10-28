#include "AgentSession.hpp"
#include "AgentProduct.hpp"
#include "IdeAuthBoundary.hpp"
#include <string>
#include <thread>
#include <windows.h>

// SWARM_PATH_B_4111_SOURCE_001: control IDs must NOT collide with Agent/SubAgent
// menu band 4100–4119 (IDM_SUBAGENT_SWARM=4111). Prior tip PathB saw WM_COMMAND
// 4111 delivered but CmdDiag id=4111 never earned; AgentSessionBar STATIC used
// HMENU 4111 alongside the swarm menu id.
namespace {
enum : int {
    IDC_ASB_REVIEW = 48101,
    IDC_ASB_STOP = 48102,
    IDC_ASB_TWO_EDITS = 48103,
    IDC_ASB_REVERT = 48104,
    IDC_ASB_TERMINAL = 48105,
    IDC_ASB_RESTORE = 48106,
    IDC_ASB_FILES = 48110,
    IDC_ASB_TERMS = 48111,
    IDC_ASB_DIFF = 48112,
};

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
    if (id == IDC_ASB_TWO_EDITS) {
        Ensure();
        DeleteFileA("agent_gui_session\\a.txt");
        DeleteFileA("agent_gui_session\\b.txt");
        AgentExecTool("write_file", "{\"path\":\"a.txt\",\"content\":\"alpha\"}", nullptr);
        AgentExecTool("write_file", "{\"path\":\"b.txt\",\"content\":\"beta\"}", nullptr);
    } else if (id == IDC_ASB_REVERT) {
        Ensure();
        AgentExecTool("write_file", "{\"path\":\"a.txt\",\"content\":\"\"}", nullptr);
    } else if (id == IDC_ASB_REVIEW && g_diff) {
        SetWindowTextA(g_diff, AgentSessionReviewFirst().c_str());
    } else if (id == IDC_ASB_TERMINAL) {
        Ensure();
        _putenv("RAWRXD_IDE_EXEC_GRANT=1");
        std::thread([] { AgentRunCommand("execute_command", "{\"command\":\"ping -n 6 127.0.0.1\"}"); }).detach();
    } else if (id == IDC_ASB_STOP) {
        AgentSessionCancel();
    } else if (id == IDC_ASB_RESTORE) {
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
    g_files = CreateWindowExA(0, "STATIC", "0 Files Changed", WS_CHILD | WS_VISIBLE, 8, 8, 180, 24, hwnd, (HMENU)(INT_PTR)IDC_ASB_FILES, nullptr, nullptr);
    g_terms = CreateWindowExA(0, "STATIC", "0 terminals", WS_CHILD | WS_VISIBLE, 200, 8, 140, 24, hwnd, (HMENU)(INT_PTR)IDC_ASB_TERMS, nullptr, nullptr);
    CreateWindowExA(0, "BUTTON", "Two edits", WS_CHILD | WS_VISIBLE, 8, 40, 100, 28, hwnd, (HMENU)(INT_PTR)IDC_ASB_TWO_EDITS, nullptr, nullptr);
    CreateWindowExA(0, "BUTTON", "Revert one", WS_CHILD | WS_VISIBLE, 116, 40, 100, 28, hwnd, (HMENU)(INT_PTR)IDC_ASB_REVERT, nullptr, nullptr);
    CreateWindowExA(0, "BUTTON", "Review", WS_CHILD | WS_VISIBLE, 224, 40, 80, 28, hwnd, (HMENU)(INT_PTR)IDC_ASB_REVIEW, nullptr, nullptr);
    CreateWindowExA(0, "BUTTON", "Terminal", WS_CHILD | WS_VISIBLE, 312, 40, 90, 28, hwnd, (HMENU)(INT_PTR)IDC_ASB_TERMINAL, nullptr, nullptr);
    CreateWindowExA(0, "BUTTON", "Stop", WS_CHILD | WS_VISIBLE, 410, 40, 70, 28, hwnd, (HMENU)(INT_PTR)IDC_ASB_STOP, nullptr, nullptr);
    CreateWindowExA(0, "BUTTON", "Restore", WS_CHILD | WS_VISIBLE, 488, 40, 80, 28, hwnd, (HMENU)(INT_PTR)IDC_ASB_RESTORE, nullptr, nullptr);
    g_diff = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "", WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_AUTOVSCROLL,
        8, 80, 600, 150, hwnd, (HMENU)(INT_PTR)IDC_ASB_DIFF, nullptr, nullptr);
    SetTimer(hwnd, 1, 100, nullptr);
    Refresh();
    return hwnd;
}
}

void AgentSessionAttachBar(void* parentHwnd) {
    HWND parent = static_cast<HWND>(parentHwnd);
    Make(parent, parent ? (WS_CHILD | WS_VISIBLE) : (WS_OVERLAPPEDWINDOW | WS_VISIBLE));
}
