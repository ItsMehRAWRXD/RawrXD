#include "Win32IDE_AgentHUD.h"
#include <commctrl.h>
#include <sstream>

#pragma comment(lib, "comctl32.lib")

namespace RawrXD::UX {

AgentExecutionHUD& AgentExecutionHUD::instance() {
    static AgentExecutionHUD inst;
    return inst;
}

bool AgentExecutionHUD::create(HWND hwndParent) {
    if (m_hwnd) return true;
    
    WNDCLASSEXW wc = { sizeof(wc) };
    wc.lpfnWndProc = wndProc;
    wc.hInstance = GetModuleHandle(nullptr);
    wc.lpszClassName = L"RawrXD_AgentHUD";
    wc.hbrBackground = CreateSolidBrush(RGB(30, 30, 30)); // Dark grey
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    RegisterClassExW(&wc);
    
    m_hwnd = CreateWindowExW(
        WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE | WS_EX_TOPMOST,
        L"RawrXD_AgentHUD",
        L"Agent Tool",
        WS_POPUP | WS_BORDER,
        0, 0, 400, 80,
        hwndParent, nullptr, GetModuleHandle(nullptr), this
    );
    
    if (!m_hwnd) return false;
    
    // Progress Bar (Marquee)
    m_hwndProgress = CreateWindowExW(0, PROGRESS_CLASSW, nullptr,
        WS_CHILD | WS_VISIBLE | PBS_MARQUEE,
        10, 45, 380, 16, m_hwnd, reinterpret_cast<HMENU>(1), GetModuleHandle(nullptr), nullptr);
    SendMessage(m_hwndProgress, PBM_SETMARQUEE, TRUE, 50);
    
    // Status text (Static)
    m_hwndStatus = CreateWindowExW(0, L"STATIC", L"Ready",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        10, 10, 300, 20, m_hwnd, nullptr, GetModuleHandle(nullptr), nullptr);
    
    HFONT hFont = CreateFontW(14, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
    SendMessage(m_hwndStatus, WM_SETFONT, reinterpret_cast<WPARAM>(hFont), TRUE);
    
    // Cancel button
    m_hwndCancel = CreateWindowExW(0, L"BUTTON", L"Cancel",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        320, 10, 70, 25, m_hwnd, reinterpret_cast<HMENU>(2), GetModuleHandle(nullptr), nullptr);
    
    m_visible = false;
    ShowWindow(m_hwnd, SW_HIDE);
    return true;
}

void AgentExecutionHUD::showToolExecuting(const std::string& toolName, const std::string& args) {
    m_currentTool = toolName;
    std::wstring status = L"Running: " + std::wstring(toolName.begin(), toolName.end());
    
    if (!args.empty() && args.length() < 30) {
        status += L" (" + std::wstring(args.begin(), args.end()) + L")";
    }
    
    SetWindowTextW(m_hwndStatus, status.c_str());
    positionNearCursor();
    ShowWindow(m_hwnd, SW_SHOW);
    m_visible = true;
}

void AgentExecutionHUD::completeTool(const std::string& result, bool success) {
    std::wstring msg = success ? L"Completed: " : L"Failed: ";
    msg += std::wstring(m_currentTool.begin(), m_currentTool.end());
    SetWindowTextW(m_hwndStatus, msg.c_str());
    
    SendMessage(m_hwndProgress, PBM_SETMARQUEE, FALSE, 0);
    SetWindowLong(m_hwndProgress, GWL_STYLE, GetWindowLong(m_hwndProgress, GWL_STYLE) & ~PBS_MARQUEE);
    SendMessage(m_hwndProgress, PBM_SETRANGE, 0, MAKELPARAM(0, 100));
    SendMessage(m_hwndProgress, PBM_SETPOS, 100, 0);
    
    // Auto-hide after 2 seconds
    SetTimer(m_hwnd, 1, 2000, nullptr);
}

void AgentExecutionHUD::hide() {
    ShowWindow(m_hwnd, SW_HIDE);
    m_visible = false;
    SendMessage(m_hwndProgress, PBM_SETMARQUEE, TRUE, 50); // Reset for next use
}

void AgentExecutionHUD::positionNearCursor() {
    POINT pt;
    if (GetCursorPos(&pt)) {
        SetWindowPos(m_hwnd, HWND_TOPMOST, pt.x + 20, pt.y + 20, 0, 0, SWP_NOSIZE);
    }
}

LRESULT CALLBACK AgentExecutionHUD::wndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (msg == WM_CREATE) {
        auto* cs = reinterpret_cast<CREATESTRUCT*>(lParam);
        SetWindowLongPtr(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(cs->lpCreateParams));
        return 0;
    }
    auto* self = reinterpret_cast<AgentExecutionHUD*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));
    if (!self) return DefWindowProc(hwnd, msg, wParam, lParam);
    
    switch (msg) {
        case WM_COMMAND:
            if (LOWORD(wParam) == 2 && self->onCancelRequested) {
                self->onCancelRequested();
                self->hide();
            }
            return 0;
        case WM_TIMER:
            self->hide();
            KillTimer(hwnd, wParam);
            return 0;
    }
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

void AgentExecutionHUD::destroy() {
    if (m_hwnd) {
        DestroyWindow(m_hwnd);
        m_hwnd = nullptr;
    }
}

} // namespace RawrXD::UX
