#include "WindowWin32.hpp"
#include <string>

namespace Sunshine {

static Window* g_window = nullptr;

LRESULT CALLBACK Window::WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (g_window && hwnd == g_window->m_hwnd) {
        return g_window->handleMessage(msg, wParam, lParam);
    }
    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

LRESULT Window::handleMessage(UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CLOSE:
            m_shouldClose = true;
            return 0;
        case WM_SIZE:
            if (wParam != SIZE_MINIMIZED) {
                m_width = LOWORD(lParam);
                m_height = HIWORD(lParam);
                if (m_resizeCb) m_resizeCb(m_width, m_height);
            }
            return 0;
        case WM_KEYDOWN:
            if (wParam == VK_ESCAPE) m_shouldClose = true;
            return 0;
        default:
            break;
    }
    return DefWindowProcA(m_hwnd, msg, wParam, lParam);
}

bool Window::initialize(const WindowConfig& config) {
    m_hinst = GetModuleHandleA(nullptr);
    m_width = config.width;
    m_height = config.height;

    WNDCLASSEXA wc = {};
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW | CS_OWNDC;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = m_hinst;
    wc.hCursor = LoadCursorA(nullptr, IDC_ARROW);
    wc.lpszClassName = "SunshineWindowClass";
    if (!RegisterClassExA(&wc)) return false;

    RECT rc = {0, 0, config.width, config.height};
    AdjustWindowRectEx(&rc, WS_OVERLAPPEDWINDOW, FALSE, 0);

    m_hwnd = CreateWindowExA(
        0, wc.lpszClassName, config.title,
        WS_OVERLAPPEDWINDOW | WS_VISIBLE,
        CW_USEDEFAULT, CW_USEDEFAULT,
        rc.right - rc.left, rc.bottom - rc.top,
        nullptr, nullptr, m_hinst, nullptr);

    if (!m_hwnd) return false;
    g_window = this;
    ShowWindow(m_hwnd, SW_SHOW);
    UpdateWindow(m_hwnd);
    return true;
}

void Window::shutdown() {
    if (m_hwnd) {
        DestroyWindow(m_hwnd);
        m_hwnd = nullptr;
    }
    UnregisterClassA("SunshineWindowClass", m_hinst);
    g_window = nullptr;
}

bool Window::processMessages() {
    MSG msg = {};
    while (PeekMessageA(&msg, nullptr, 0, 0, PM_REMOVE)) {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }
    return !m_shouldClose;
}

void Window::present() {
}

} // namespace Sunshine
