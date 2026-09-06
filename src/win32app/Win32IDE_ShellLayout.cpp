// Win32IDE_ShellLayout.cpp — persistent chrome allow-list policy (P1_UI_SHELL_LAYOUT_001)
#include "Win32IDE_ShellLayout.hpp"
#include "Win32IDE.h"
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <algorithm>

#ifndef HCBT_MINMAX
#define HCBT_MINMAX 1
#endif

namespace RawrXD::ShellLayout {
namespace {

HWND g_mainHwnd = nullptr;
HHOOK g_cbtHook = nullptr;
bool g_transitionLogged = false;
bool g_policyInstalled = false;

HWND g_allowActivity = nullptr;
HWND g_allowSidebar = nullptr;
HWND g_allowEditor = nullptr;
HWND g_allowStatus = nullptr;

static void JournalTransition(HWND hwnd, const char* callsite, bool oldVis, bool newVis)
{
    if (g_transitionLogged)
        return;
    if (!(oldVis == false && newVis == true))
        return;
    if (!RebuildRestrictActive())
        return;

    g_transitionLogged = true;
    CreateDirectoryA("evidence", nullptr);
    CreateDirectoryA("evidence\\P1_UI_SHELL_LAYOUT_001", nullptr);

    char cls[64] = {};
    GetClassNameA(hwnd, cls, 64);
    wchar_t titleW[64] = {};
    GetWindowTextW(hwnd, titleW, 64);
    char titleA[64] = {};
    WideCharToMultiByte(CP_UTF8, 0, titleW, -1, titleA, 64, nullptr, nullptr);

    FILE* f = nullptr;
    if (fopen_s(&f, "evidence\\P1_UI_SHELL_LAYOUT_001\\CHROME_VIS_TRANSITION.txt", "wb") == 0 &&
        f) {
        std::fprintf(f, "CHROME_VIS_TRANSITION\n");
        std::fprintf(f, "HWND=%p\n", static_cast<void*>(hwnd));
        std::fprintf(f, "CLASS=%s\n", cls);
        std::fprintf(f, "CONTROL=%s\n", titleA);
        std::fprintf(f, "CALLSITE=%s\n", callsite ? callsite : "?");
        std::fprintf(f, "OLD_VISIBLE=0\n");
        std::fprintf(f, "NEW_VISIBLE=1\n");
        std::fprintf(f, "PHASE=%d\n", PhaseFromEnvironment());
        std::fclose(f);
    }
}

static bool IsDescendantOf(HWND hwnd, HWND root)
{
    if (!hwnd || !root)
        return false;
    HWND p = hwnd;
    while (p) {
        if (p == root)
            return true;
        p = GetParent(p);
    }
    return false;
}

static bool IsAllowedVisible(HWND hwnd)
{
    if (!RebuildRestrictActive())
        return true;
    const int phase = PhaseFromEnvironment();
    if (phase <= 0)
        return false;
    if (phase >= 1 && IsDescendantOf(hwnd, g_allowActivity))
        return true;
    if (phase >= 2 && IsDescendantOf(hwnd, g_allowSidebar))
        return true;
    if (phase >= 3 && IsDescendantOf(hwnd, g_allowEditor))
        return true;
    if (phase >= 4 && IsDescendantOf(hwnd, g_allowStatus))
        return true;
    return false;
}

static void HideRecursive(HWND h)
{
    EnumChildWindows(
        h,
        [](HWND child, LPARAM) -> BOOL {
            HideRecursive(child);
            ShowWindow(child, SW_HIDE);
            return TRUE;
        },
        0);
    ShowWindow(h, SW_HIDE);
}

static void ShowTree(HWND h)
{
    if (!h || !IsWindow(h))
        return;
    ShowWindow(h, SW_SHOWNA);
    EnumChildWindows(
        h,
        [](HWND child, LPARAM) -> BOOL {
            ShowTree(child);
            return TRUE;
        },
        0);
}

static void HideAllChrome(HWND main)
{
    if (!main || !IsWindow(main))
        return;
    EnumChildWindows(
        main,
        [](HWND child, LPARAM) -> BOOL {
            HideRecursive(child);
            ShowWindow(child, SW_HIDE);
            return TRUE;
        },
        0);
}

static void RestoreAllowedChrome()
{
    const int phase = PhaseFromEnvironment();
    if (phase >= 1)
        ShowTree(g_allowActivity);
    if (phase >= 2)
        ShowTree(g_allowSidebar);
    if (phase >= 3)
        ShowTree(g_allowEditor);
    if (phase >= 4)
        ShowTree(g_allowStatus);
}

static bool IsUnderMain(HWND hwnd)
{
    if (!g_mainHwnd || !hwnd || hwnd == g_mainHwnd)
        return false;
    return IsDescendantOf(hwnd, g_mainHwnd);
}

static LRESULT CALLBACK CbtProc(int nCode, WPARAM wParam, LPARAM lParam)
{
    if (!RebuildRestrictActive())
        return CallNextHookEx(g_cbtHook, nCode, wParam, lParam);

    // CreateWindow(WS_VISIBLE) bypasses HCBT_SHOWWINDOW — strip WS_VISIBLE under
    // main (and under non-allowed parents). Allowed roots are revealed by
    // RestoreAllowedChrome / ShowTree.
    if (nCode == 3 /* HCBT_CREATEWND */ && g_mainHwnd && lParam) {
        auto* info = reinterpret_cast<CBT_CREATEWNDW*>(lParam);
        if (info && info->lpcs) {
            HWND parent = info->lpcs->hwndParent;
            if (parent == g_mainHwnd ||
                (parent && IsDescendantOf(parent, g_mainHwnd) &&
                 !IsAllowedVisible(parent))) {
                info->lpcs->style &= ~static_cast<LONG>(WS_VISIBLE);
            }
        }
    }

    // Block unauthorized ShowWindow (HCBT_SHOWWINDOW == 9).
    if (nCode == 9) {
        HWND hwnd = reinterpret_cast<HWND>(wParam);
        const bool showing = (LOWORD(lParam) != 0);
        if (showing && IsUnderMain(hwnd) && !IsAllowedVisible(hwnd)) {
            JournalTransition(hwnd, "CBT_SHOWWINDOW_BLOCK", false, true);
            return 1;
        }
    }
    return CallNextHookEx(g_cbtHook, nCode, wParam, lParam);
}

static void MoveHwnd(HWND h, int x, int y, int w, int hh)
{
    if (!h || !IsWindow(h))
        return;
    w = (std::max)(0, w);
    hh = (std::max)(0, hh);
    MoveWindow(h, x, y, w, hh, TRUE);
}

}  // namespace

// Prefer control-ID resolve: getter can lag create or point at a non-root host.
static HWND ResolveEditor(Win32IDE* ide, HWND main)
{
    HWND byId = main ? GetDlgItem(main, 1001) : nullptr;
    if (byId && IsWindow(byId))
        return byId;
    HWND e = ide ? ide->getEditor() : nullptr;
    if (e && IsWindow(e))
        return e;
    return nullptr;
}

int PhaseFromEnvironment()
{
    const char* p = std::getenv("RAWRXD_SHELL_LAYOUT_PHASE");
    if (!p || !p[0])
        return 3;
    const int v = std::atoi(p);
    if (v < 0)
        return 0;
    if (v > 6)
        return 6;
    return v;
}

bool RebuildActive()
{
    const char* v = std::getenv("RAWRXD_SHELL_LAYOUT_REBUILD");
    return v && v[0] && v[0] != '0';
}

bool UseLegacySpatial(int phase) { return phase >= 6; }

bool FrameOnlyMode() { return RebuildActive() && PhaseFromEnvironment() == 0; }

bool RebuildRestrictActive()
{
    if (!RebuildActive())
        return false;
    const int p = PhaseFromEnvironment();
    return p >= 0 && p <= 4;
}

void RegisterAllowedRoots(HWND activity, HWND sidebar, HWND editor, HWND status)
{
    g_allowActivity = activity;
    g_allowSidebar = sidebar;
    g_allowEditor = editor;
    g_allowStatus = status;
}

void ApplyFromIde(Win32IDE* ide)
{
    if (!ide)
        return;
    if (ide->isCommandHomeShell()) {
        ide->applyShellModeChrome();
        return;
    }
    HWND main = ide->getMainWindow();
    RegisterAllowedRoots(ide->getActivityBar(), ide->getSidebar(),
                         ResolveEditor(ide, main), ide->getStatusBar());
    ApplyChromeVisibilityPolicy(main);
}

void EnsurePolicyInstalled(HWND mainHwnd)
{
    if (!mainHwnd || !IsWindow(mainHwnd))
        return;
    g_mainHwnd = mainHwnd;
    if (!RebuildRestrictActive()) {
        if (g_cbtHook) {
            UnhookWindowsHookEx(g_cbtHook);
            g_cbtHook = nullptr;
            g_policyInstalled = false;
        }
        return;
    }
    if (g_policyInstalled && g_cbtHook)
        return;
    g_cbtHook = SetWindowsHookExW(WH_CBT, CbtProc, nullptr, GetCurrentThreadId());
    g_policyInstalled = (g_cbtHook != nullptr);
    g_transitionLogged = false;
}

void ApplyChromeVisibilityPolicy(HWND mainHwnd)
{
    if (!mainHwnd || !IsWindow(mainHwnd))
        return;
    EnsurePolicyInstalled(mainHwnd);
    if (!RebuildRestrictActive())
        return;
    HideAllChrome(mainHwnd);
    RestoreAllowedChrome();
}

bool SetChildVisible(HWND child, bool visible, const char* callsite)
{
    if (!child || !IsWindow(child))
        return false;
    if (RebuildRestrictActive() && visible && !IsAllowedVisible(child)) {
        JournalTransition(child, callsite ? callsite : "SetChildVisible",
                          IsWindowVisible(child) != FALSE, true);
        ShowWindow(child, SW_HIDE);
        return false;
    }
    if (visible)
        ShowTree(child);
    else
        HideRecursive(child);
    return visible;
}

void LayoutIDE(Win32IDE* ide, int clientW, int clientH)
{
    if (!ide || clientW <= 0 || clientH <= 0)
        return;
    if (ide->isCommandHomeShell()) {
        ide->applyShellModeChrome();
        return;
    }

    HWND main = ide->getMainWindow();
    if (!main)
        return;

    HWND activity = ide->getActivityBar();
    HWND sidebar = ide->getSidebar();
    HWND editor = ResolveEditor(ide, main);
    HWND status = ide->getStatusBar();
    RegisterAllowedRoots(activity, sidebar, editor, status);

    EnsurePolicyInstalled(main);
    ApplyChromeVisibilityPolicy(main);

    const int phase = PhaseFromEnvironment();
    constexpr int activityW = 48;
    constexpr int sidebarW = 250;
    constexpr int statusH = 24;
    constexpr int terminalH = 200;
    (void)terminalH;

    if (phase < 1)
        return;

    if (activity) {
        SetChildVisible(activity, true, "LayoutIDE:activity");
        MoveHwnd(activity, 0, 0, activityW, clientH);
    }

    int x = activityW;
    int workH = clientH;

    if (phase < 2)
        return;

    if (sidebar) {
        SetChildVisible(sidebar, true, "LayoutIDE:sidebar");
        MoveHwnd(sidebar, x, 0, sidebarW, clientH);
        x += sidebarW;
    }

    if (phase < 3)
        return;

    int bottomReserve = 0;
    if (phase >= 5)
        bottomReserve += terminalH;
    if (phase >= 4)
        bottomReserve += statusH;
    workH = (std::max)(0, clientH - bottomReserve);

    if (editor) {
        SetChildVisible(editor, true, "LayoutIDE:editor");
        MoveHwnd(editor, x, 0, (std::max)(0, clientW - x), workH);
    }

    if (phase < 4)
        return;

    if (status) {
        SetChildVisible(status, true, "LayoutIDE:status");
        MoveHwnd(status, 0, clientH - statusH, clientW, statusH);
        SendMessageW(status, WM_SIZE, 0, 0);
    }

    if (phase < 5)
        return;
    // PHASE=5 RESERVED: terminal stub — NOT_TESTED / UNIMPLEMENTED.
}

}  // namespace RawrXD::ShellLayout
