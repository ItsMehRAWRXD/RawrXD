// ============================================================================
// P1_UI_WINDOW_OWNERSHIP_001 — top-level / dock-root diagnostics
// Enumerate process top-level HWNDs and assert dock panes share MAIN_HWND.
// ============================================================================
#include "Win32IDE.h"

#include <cstdarg>
#include <cstdio>
#include <cstring>

namespace {

constexpr const char* kProductClass = "RawrXD_IDE_MainWindow";
constexpr const char* kLegacyClass = "RawrXD_Win32IDE";

struct DumpCtx {
    DWORD pid = 0;
    HWND mainHwnd = nullptr;
    int productShells = 0;
    int topLevelTotal = 0;
};

static void emitLine(const char* line)
{
    if (!line)
        return;
    OutputDebugStringA(line);
    fputs(line, stderr);
    fflush(stderr);
    fileTrace(line);
}

static void emitf(const char* fmt, ...)
{
    char buf[1280];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    emitLine(buf);
}

static bool isProductShellClass(const char* cls)
{
    return cls && (_stricmp(cls, kProductClass) == 0 || _stricmp(cls, kLegacyClass) == 0);
}

static BOOL CALLBACK dumpTopLevel(HWND hwnd, LPARAM lp)
{
    auto* ctx = reinterpret_cast<DumpCtx*>(lp);
    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    if (pid != ctx->pid)
        return TRUE;

    ++ctx->topLevelTotal;

    char title[256] = {};
    char cls[256] = {};
    GetWindowTextA(hwnd, title, 255);
    GetClassNameA(hwnd, cls, 255);

    const LONG_PTR style = GetWindowLongPtrA(hwnd, GWL_STYLE);
    const LONG_PTR exStyle = GetWindowLongPtrA(hwnd, GWL_EXSTYLE);
    RECT r{};
    GetWindowRect(hwnd, &r);

    emitf("TOP HWND=%p ROOT=%p PARENT=%p CLASS='%s' TITLE='%s' STYLE=%p EX=%p RECT=%ld,%ld,%ld,%ld\n",
          (void*)hwnd, (void*)GetAncestor(hwnd, GA_ROOT), (void*)GetParent(hwnd), cls, title,
          (void*)style, (void*)exStyle, r.left, r.top, r.right, r.bottom);

    if (isProductShellClass(cls))
        ++ctx->productShells;

    return TRUE;
}

static bool rootEqMain(HWND pane, HWND mainHwnd)
{
    if (!pane || !IsWindow(pane) || !mainHwnd)
        return false;
    return GetAncestor(pane, GA_ROOT) == mainHwnd;
}

static bool hasPopupStyle(HWND hwnd)
{
    if (!hwnd || !IsWindow(hwnd))
        return false;
    const LONG_PTR style = GetWindowLongPtrA(hwnd, GWL_STYLE);
    if (style & WS_CHILD)
        return (style & WS_POPUP) != 0;
    return (style & WS_POPUP) != 0 || (style & (WS_CAPTION | WS_THICKFRAME | WS_SYSMENU)) != 0;
}

static void assertRoot(const char* name, HWND pane, HWND mainHwnd, bool* allPass)
{
    const bool ok = !pane || !IsWindow(pane) || rootEqMain(pane, mainHwnd);
    emitf("%s_ROOT_EQ_MAIN=%s hwnd=%p root=%p\n", name, ok ? "PASS" : "FAIL", (void*)pane,
          pane && IsWindow(pane) ? (void*)GetAncestor(pane, GA_ROOT) : nullptr);
    if (!ok)
        *allPass = false;
}

}  // namespace

void Win32IDE::dumpUiWindowOwnership(const char* phaseTag)
{
    const char* phase = phaseTag ? phaseTag : "UNNAMED";
    emitf("=== P1_UI_WINDOW_OWNERSHIP_001 phase=%s ===\n", phase);

    if (!m_hwndMain || !IsWindow(m_hwndMain)) {
        emitLine("MAIN_HWND=INVALID — abort dump\n");
        return;
    }

    DumpCtx ctx{};
    ctx.pid = GetCurrentProcessId();
    ctx.mainHwnd = m_hwndMain;
    EnumWindows(dumpTopLevel, reinterpret_cast<LPARAM>(&ctx));

    emitf("RAWRXD_TOPLEVEL_PRODUCT_WINDOWS=%d (pid_toplevel=%d MAIN=%p)\n", ctx.productShells,
          ctx.topLevelTotal, (void*)m_hwndMain);
    emitf("MAIN_TOPLEVEL_COUNT=%s\n", ctx.productShells == 1 ? "PASS" : "FAIL");
    emitf("NO_SECOND_PRODUCT_SHELL=%s\n", ctx.productShells <= 1 ? "PASS" : "FAIL");

    bool allPass = (ctx.productShells == 1);

    assertRoot("EXPLORER", m_hwndSidebar, m_hwndMain, &allPass);
    HWND editorPane = (m_hwndMonacoContainer && IsWindow(m_hwndMonacoContainer)) ? m_hwndMonacoContainer
                                                                                : m_hwndEditor;
    assertRoot("EDITOR", editorPane, m_hwndMain, &allPass);
    assertRoot("CHAT", m_hwndSecondarySidebar, m_hwndMain, &allPass);
    assertRoot("OUTPUT", m_hwndOutputTabs ? m_hwndOutputTabs : m_hwndOutputPanel, m_hwndMain, &allPass);
    assertRoot("TERMINAL", m_hwndPowerShellPanel, m_hwndMain, &allPass);
    assertRoot("STATUS", m_hwndStatusBar, m_hwndMain, &allPass);

    bool chatPopup = false;
    if (m_hwndSecondarySidebar && IsWindow(m_hwndSecondarySidebar) && m_secondarySidebarVisible) {
        chatPopup = hasPopupStyle(m_hwndSecondarySidebar) || GetParent(m_hwndSecondarySidebar) == nullptr;
        if (chatPopup) {
            emitf("CHAT_DOCK_REPAIR: reparent + WS_CHILD (was parent=%p style=%p)\n",
                  (void*)GetParent(m_hwndSecondarySidebar),
                  (void*)GetWindowLongPtrA(m_hwndSecondarySidebar, GWL_STYLE));
            LONG_PTR st = GetWindowLongPtrA(m_hwndSecondarySidebar, GWL_STYLE);
            st &= ~(WS_POPUP | WS_OVERLAPPEDWINDOW | WS_CAPTION | WS_THICKFRAME | WS_SYSMENU);
            st |= (WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS | WS_CLIPCHILDREN);
            SetWindowLongPtrA(m_hwndSecondarySidebar, GWL_STYLE, st);
            SetParent(m_hwndSecondarySidebar, m_hwndMain);
            chatPopup = hasPopupStyle(m_hwndSecondarySidebar) || GetParent(m_hwndSecondarySidebar) != m_hwndMain;
        }
    }
    emitf("NO_DOCK_PANE_WS_POPUP=%s\n", chatPopup ? "FAIL" : "PASS");
    if (chatPopup)
        allPass = false;

    emitf("P1_UI_WINDOW_OWNERSHIP_001 phase=%s RESULT=%s\n", phase, allPass ? "PASS" : "FAIL");
}
