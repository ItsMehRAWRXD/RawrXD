// ============================================================================
// RawrWindow.cpp — Native Window Manager Implementation
// ============================================================================

#include "RawrWindow.hpp"
#include "../runtime/RawrRuntime.hpp"

namespace rawr {

// Forward declare window procedure
static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    RawrWindow* window = nullptr;
    if (msg == WM_CREATE) {
        auto* cs = reinterpret_cast<CREATESTRUCT*>(lParam);
        window = static_cast<RawrWindow*>(cs->lpCreateParams);
        SetWindowLongPtr(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(window));
    } else {
        window = reinterpret_cast<RawrWindow*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));
    }

    if (window) {
        return window->HandleMessage(hwnd, msg, wParam, lParam);
    }

    return DefWindowProc(hwnd, msg, wParam, lParam);
}

RawrWindow& RawrWindow::Get() {
    static RawrWindow instance;
    return instance;
}

bool RawrWindow::Create(const WindowConfig& config) {
    m_config = config;
    m_hInstance = GetModuleHandle(nullptr);

    if (!RegisterClass(m_hInstance)) {
        RawrRuntime::Get().Log(LogLevel::Error, "Failed to register window class");
        return false;
    }

    DWORD style = WS_OVERLAPPEDWINDOW;
    if (!config.resizable) {
        style &= ~(WS_THICKFRAME | WS_MAXIMIZEBOX);
    }

    RECT rect = { 0, 0, (LONG)config.width, (LONG)config.height };
    AdjustWindowRect(&rect, style, FALSE);

    m_hwnd = CreateWindowEx(
        0,
        "RawrXDClass",
        config.title,
        style,
        CW_USEDEFAULT, CW_USEDEFAULT,
        rect.right - rect.left,
        rect.bottom - rect.top,
        nullptr, nullptr,
        (HINSTANCE)m_hInstance,
        this
    );

    if (!m_hwnd) {
        RawrRuntime::Get().Log(LogLevel::Error, "Failed to create window");
        return false;
    }

    if (config.maximized) {
        ShowWindow((HWND)m_hwnd, SW_MAXIMIZE);
    } else {
        ShowWindow((HWND)m_hwnd, SW_SHOW);
    }

    RawrRuntime::Get().Log(LogLevel::Info, "Window created");
    return true;
}

void RawrWindow::Destroy() {
    if (m_hwnd) {
        DestroyWindow((HWND)m_hwnd);
        m_hwnd = nullptr;
    }
}

int RawrWindow::Run() {
    m_running = true;
    MSG msg = {};

    while (m_running && GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    m_running = false;
    return (int)msg.wParam;
}

void RawrWindow::RequestClose() {
    if (m_hwnd) {
        PostMessage((HWND)m_hwnd, WM_CLOSE, 0, 0);
    }
}

void RawrWindow::GetSize(uint32_t& width, uint32_t& height) const {
    if (m_hwnd) {
        RECT rect;
        GetClientRect((HWND)m_hwnd, &rect);
        width = rect.right - rect.left;
        height = rect.bottom - rect.top;
    }
}

void RawrWindow::SetSize(uint32_t width, uint32_t height) {
    if (m_hwnd) {
        SetWindowPos((HWND)m_hwnd, nullptr, 0, 0, (int)width, (int)height,
                     SWP_NOMOVE | SWP_NOZORDER);
    }
}

void RawrWindow::SetTitle(const char* title) {
    if (m_hwnd && title) {
        SetWindowTextA((HWND)m_hwnd, title);
    }
}

bool RawrWindow::RegisterClass(void* hInstance) {
    WNDCLASSEXA wc = {};
    wc.cbSize = sizeof(WNDCLASSEXA);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = (HINSTANCE)hInstance;
    wc.hIcon = LoadIcon(nullptr, IDI_APPLICATION);
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = "RawrXDClass";

    return RegisterClassExA(&wc) != 0;
}

LRESULT RawrWindow::HandleMessage(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_DESTROY:
            m_running = false;
            PostQuitMessage(0);
            return 0;

        case WM_CLOSE:
            if (m_onClose) {
                if (!m_onClose()) return 0;
            }
            Destroy();
            return 0;

        case WM_SIZE: {
            uint32_t w = LOWORD(lParam);
            uint32_t h = HIWORD(lParam);
            if (m_onResize) m_onResize(w, h);
            return 0;
        }

        case WM_GETMINMAXINFO: {
            auto* mmi = (MINMAXINFO*)lParam;
            mmi->ptMinTrackSize.x = (LONG)m_config.minWidth;
            mmi->ptMinTrackSize.y = (LONG)m_config.minHeight;
            return 0;
        }
    }

    return DefWindowProc(hwnd, msg, wParam, lParam);
}

} // namespace rawr
