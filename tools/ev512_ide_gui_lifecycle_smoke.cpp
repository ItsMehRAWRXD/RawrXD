// ev512_ide_gui_lifecycle_smoke.cpp — real HWND lifecycle for EV512 IDE claims.
// Zero speculation: CreateWindow/EDIT append/file persist/DestroyWindow only.
#include "RuntimeEvidence512Surface.hpp"
#include "RuntimeEvidence512HostIDE.hpp"
#include <windows.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <fstream>

static HWND g_main = nullptr;
static HWND g_edit = nullptr;
static uint64_t g_painted = 0;

static LRESULT CALLBACK WndProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    if (m == WM_DESTROY) {
        Deep2::Ev512::HostEmitIDEExitEntry(
            (uint64_t)GetCurrentProcessId(), 1);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(h, m, w, l);
}

int main() {
    Deep2::Ev512::HostTryArm(0x494445475549ull); /* IDEGUI */
    Deep2::Ev512::HostSurfaceGuard surface(stderr);
    Deep2::Ev512::HostEmitIDEBootEntry(
        (uint64_t)GetCurrentProcessId(), (uint64_t)GetCurrentThreadId());

    WNDCLASSW wc{};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.lpszClassName = L"RawrXD_EV512_IDE_Smoke";
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    if (!RegisterClassW(&wc)) {
        std::fprintf(stderr, "EV512_IDE_SMOKE RegisterClass failed\n");
        return 2;
    }
    g_main = CreateWindowExW(0, wc.lpszClassName, L"RawrXD EV512 IDE Smoke",
                             WS_OVERLAPPEDWINDOW | WS_VISIBLE, 40, 40, 480, 240,
                             nullptr, nullptr, wc.hInstance, nullptr);
    if (!g_main) {
        std::fprintf(stderr, "EV512_IDE_SMOKE CreateWindow failed\n");
        return 3;
    }
    g_edit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                             WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_AUTOVSCROLL,
                             8, 8, 448, 160, g_main, nullptr, wc.hInstance, nullptr);
    UpdateWindow(g_main);
    Deep2::Ev512::HostEmitIDEWindowReady(
        (uint64_t)(uintptr_t)g_main, (uint64_t)GetCurrentThreadId());
    Deep2::Ev512::HostEmitCoreInitComplete(1, 1);

    char cwd[MAX_PATH];
    DWORD n = GetCurrentDirectoryA(MAX_PATH, cwd);
    const uint64_t wh = Deep2::Ev512::HostPathHash(n ? cwd : ".");
    Deep2::Ev512::HostEmitWorkspaceOpen(wh, wh);

    const char* piece = "ev512-ui-stream\n";
    if (g_edit) {
        SendMessageA(g_edit, EM_REPLACESEL, FALSE, (LPARAM)piece);
        g_painted += std::strlen(piece);
        Deep2::Ev512::HostEmitUIStreamAppend(1, g_painted);
        SendMessageA(g_edit, EM_REPLACESEL, FALSE, (LPARAM)"finalize\n");
        g_painted += 9;
        Deep2::Ev512::HostEmitUIStreamFinalize(1, g_painted);
    }

    const char* sessPath = "ev512_ide_session_smoke.json";
    {
        std::ofstream f(sessPath, std::ios::binary | std::ios::trunc);
        f << "{\"smoke\":1,\"cwd\":\"" << (n ? cwd : ".") << "\"}\n";
    }
    std::ifstream in(sessPath, std::ios::binary | std::ios::ate);
    const uint64_t bytes = in ? (uint64_t)in.tellg() : 0ull;
    Deep2::Ev512::HostEmitSessionPersist(
        Deep2::Ev512::HostPathHash(sessPath), bytes);

    DestroyWindow(g_main);
    g_main = nullptr;
    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    Deep2::Ev512::HostEmitIDEExitComplete(
        (uint64_t)GetCurrentProcessId(), 0);
    std::fprintf(stderr, "EV512_IDE_SMOKE_DONE=1\n");
    return 0;
}
