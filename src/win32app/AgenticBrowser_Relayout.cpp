// ============================================================================
// AgenticBrowser_Relayout.cpp - Implementation of Win32IDE_AgenticBrowser_Relayout
// ============================================================================
// Provides browser-style relayout for the agentic AI panel in the RawrXD IDE.
//
// History:
//   2026-08-26  Created as part of Batch 1 unresolved external resolution.
// ============================================================================

#include <windows.h>
#include <string>

// ---------------------------------------------------------------------------
// Internal state
// ---------------------------------------------------------------------------
static HWND g_hwndAgenticBrowser = nullptr;
static bool g_agenticBrowserVisible = false;
static int g_agenticBrowserWidth = 320;

// ---------------------------------------------------------------------------
// Exported function (used by Win32IDE_Core.cpp)
// ---------------------------------------------------------------------------

extern void Win32IDE_AgenticBrowser_Relayout()
{
    if (!g_hwndAgenticBrowser || !IsWindow(g_hwndAgenticBrowser))
        return;
    
    // Get parent window client area
    HWND hwndParent = GetParent(g_hwndAgenticBrowser);
    if (!hwndParent)
        return;
    
    RECT rcParent;
    GetClientRect(hwndParent, &rc);
    
    // Position browser panel on the right side
    int x = rcParent.right - g_agenticBrowserWidth;
    int y = 0;
    int width = g_agenticBrowserWidth;
    int height = rcParent.bottom;
    
    SetWindowPos(g_hwndAgenticBrowser, nullptr,
                 x, y, width, height,
                 SWP_NOZORDER | SWP_NOACTIVATE | SWP_SHOWWINDOW);
    
    OutputDebugStringA("[AgenticBrowser] Relayout complete\n");
}

// ---------------------------------------------------------------------------
// Additional agentic browser functions
// ---------------------------------------------------------------------------

extern void Win32IDE_AgenticBrowser_Show(HWND parent)
{
    if (g_hwndAgenticBrowser && IsWindow(g_hwndAgenticBrowser))
    {
        ShowWindow(g_hwndAgenticBrowser, SW_SHOW);
        g_agenticBrowserVisible = true;
        return;
    }
    
    // Create browser panel window
    static bool classRegistered = false;
    if (!classRegistered)
    {
        WNDCLASSW wc = {};
        wc.lpfnWndProc = DefWindowProcW;
        wc.hInstance = GetModuleHandleW(nullptr);
        wc.lpszClassName = L"RawrXD_AgenticBrowser";
        wc.hbrBackground = CreateSolidBrush(RGB(37, 37, 38));  // VS Code dark sidebar
        RegisterClassW(&wc);
        classRegistered = true;
    }
    
    g_hwndAgenticBrowser = CreateWindowExW(WS_EX_CLIENTEDGE, L"RawrXD_AgenticBrowser",
                                           L"Agentic Browser",
                                           WS_CHILD | WS_CLIPCHILDREN | WS_CLIPSIBLINGS,
                                           0, 0, g_agenticBrowserWidth, 100,
                                           parent, nullptr, GetModuleHandleW(nullptr), nullptr);
    
    if (g_hwndAgenticBrowser)
    {
        g_agenticBrowserVisible = true;
        Win32IDE_AgenticBrowser_Relayout();
    }
}

extern void Win32IDE_AgenticBrowser_Hide()
{
    if (g_hwndAgenticBrowser && IsWindow(g_hwndAgenticBrowser))
    {
        ShowWindow(g_hwndAgenticBrowser, SW_HIDE);
    }
    g_agenticBrowserVisible = false;
}

extern bool Win32IDE_AgenticBrowser_IsVisible()
{
    return g_agenticBrowserVisible;
}

extern void Win32IDE_AgenticBrowser_SetWidth(int width)
{
    if (width >= 200 && width <= 600)
    {
        g_agenticBrowserWidth = width;
        Win32IDE_AgenticBrowser_Relayout();
    }
}
