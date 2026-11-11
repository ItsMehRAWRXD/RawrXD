// Win32IDE_AgenticBrowser.cpp — terminal command generation via agentic browser
#include "Win32IDE.h"
#include "Win32IDE_AgenticBrowser.h"
#include "IDELogger.h"
#include "rawrxd/ide/AgenticBrowserLayer.hpp"

#include <algorithm>
#include <cstdlib>
#include <memory>

namespace {

HWND g_main = nullptr;
HWND g_host = nullptr;
std::unique_ptr<RawrXD::Ide::AgenticBrowserLayer> g_layer;
bool g_visible = false;

constexpr wchar_t kClassName[] = L"RawrXDAgenticBrowserHost";

void layoutHostToBottomThird() {
    if (!g_main || !g_host) return;
    RECT cr{};
    GetClientRect(g_main, &cr);
    int h = static_cast<int>((cr.bottom - cr.top) / 3);
    if (h < 120) h = 120;
    const int top = cr.bottom - h;
    SetWindowPos(g_host, nullptr, 0, top, cr.right - cr.left, h,
                 SWP_NOZORDER | SWP_NOACTIVATE);
}

LRESULT CALLBACK hostWndProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    if (m == WM_SIZE && g_layer) {
        RECT rc{};
        GetClientRect(h, &rc);
        g_layer->setBounds(rc);
    }
    return DefWindowProc(h, m, w, l);
}

} // namespace

bool Win32IDE::initAgenticBrowser() {
    if (g_host) return true;
    g_main = m_hwndMain;

    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = hostWndProc;
    wc.hInstance = m_hInstance;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = kClassName;
    wc.hIcon = LoadIcon(nullptr, IDI_APPLICATION);
    wc.hIconSm = LoadIcon(nullptr, IDI_APPLICATION);

    if (!RegisterClassExW(&wc)) {
        if (GetLastError() != ERROR_CLASS_ALREADY_EXISTS) return false;
    }

    g_host = CreateWindowExW(WS_EX_CLIENTEDGE, kClassName,
                             L"Agentic Browser",
                             WS_CHILD | WS_VISIBLE,
                             0, 0, 200, 100,
                             g_main, nullptr, m_hInstance, this);
    if (!g_host) return false;

    g_layer = std::make_unique<RawrXD::Ide::AgenticBrowserLayer>();
    g_visible = true;
    layoutHostToBottomThird();
    appendToOutput("[AgenticBrowser] Terminal command generation panel initialized.\n",
                   "Output", OutputSeverity::Info);
    return true;
}

void Win32IDE::showAgenticBrowser() {
    if (g_host) {
        ShowWindow(g_host, SW_SHOW);
        g_visible = true;
        layoutHostToBottomThird();
    }
}

void Win32IDE::hideAgenticBrowser() {
    if (g_host) {
        ShowWindow(g_host, SW_HIDE);
        g_visible = false;
    }
}

bool Win32IDE::isAgenticBrowserVisible() const {
    return g_visible;
}
