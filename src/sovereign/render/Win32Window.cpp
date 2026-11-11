// ============================================================================
// Win32Window.cpp - Raw Win32 Windowing Implementation
// ============================================================================

#include "Win32Window.hpp"
#include <windowsx.h>
#include <iostream>

namespace Sovereign {

// ============================================================
// CursorController
// ============================================================

CursorController::CursorController() = default;
CursorController::~CursorController() = default;

void CursorController::Show() {
    while (ShowCursor(TRUE) < 0);
    visible_ = true;
}

void CursorController::Hide() {
    while (ShowCursor(FALSE) >= 0);
    visible_ = false;
}

void CursorController::SetPosition(int x, int y) {
    SetCursorPos(x, y);
}

void CursorController::GetPosition(int& x, int& y) const {
    POINT pt;
    GetCursorPos(&pt);
    x = pt.x;
    y = pt.y;
}

void CursorController::SetCursor(HCURSOR cursor) {
    currentCursor_ = cursor;
    ::SetCursor(cursor);
}

void CursorController::SetArrow() {
    SetCursor(LoadCursor(nullptr, IDC_ARROW));
}

void CursorController::SetHand() {
    SetCursor(LoadCursor(nullptr, IDC_HAND));
}

void CursorController::SetIBeam() {
    SetCursor(LoadCursor(nullptr, IDC_IBEAM));
}

void CursorController::SetCross() {
    SetCursor(LoadCursor(nullptr, IDC_CROSS));
}

void CursorController::SetWait() {
    SetCursor(LoadCursor(nullptr, IDC_WAIT));
}

void CursorController::ClipToRect(int x, int y, int w, int h) {
    RECT rect = {x, y, x + w, y + h};
    ClipCursor(&rect);
    clipX_ = x; clipY_ = y; clipW_ = w; clipH_ = h;
    clipped_ = true;
}

void CursorController::Unclip() {
    ClipCursor(nullptr);
    clipped_ = false;
}

void CursorController::SetSpeed(float multiplier) {
    speed_ = multiplier;
    SystemParametersInfo(SPI_SETMOUSESPEED, 0, UIntToPtr(static_cast<uint32_t>(multiplier * 10)), 0);
}

void CursorController::SetAcceleration(bool enabled) {
    int params[3] = {0, 0, 0};
    if (enabled) {
        params[0] = 2; // Enhanced pointer precision
        params[1] = 10;
        params[2] = 20;
    }
    SystemParametersInfo(SPI_SETMOUSE, 0, params, 0);
}

// ============================================================
// Win32Window
// ============================================================

Win32Window::Win32Window() = default;
Win32Window::~Win32Window() {
    Destroy();
}

bool Win32Window::Create(const WindowConfig& config) {
    config_ = config;
    
    RegisterWindowClass();
    
    DWORD style = WS_OVERLAPPEDWINDOW;
    if (config.borderless) style = WS_POPUP;
    if (!config.resizable) style &= ~WS_THICKFRAME & ~WS_MAXIMIZEBOX;
    if (config.alwaysOnTop) style |= WS_EX_TOPMOST;
    
    RECT rect = {0, 0, static_cast<LONG>(config.width), static_cast<LONG>(config.height)};
    AdjustWindowRect(&rect, style, FALSE);
    
    handle_ = CreateWindowEx(
        config.alwaysOnTop ? WS_EX_TOPMOST : 0,
        L"SovereignWindowClass",
        config.title,
        style,
        config.x, config.y,
        rect.right - rect.left,
        rect.bottom - rect.top,
        static_cast<HWND>(config.parentWindow),
        nullptr,
        GetModuleHandle(nullptr),
        this
    );
    
    if (!handle_) return false;
    
    dc_ = GetDC(handle_);
    SetDPIAware();
    
    return true;
}

void Win32Window::Destroy() {
    if (handle_) {
        if (dc_) ReleaseDC(handle_, dc_);
        DestroyWindow(handle_);
        handle_ = nullptr;
    }
}

void Win32Window::Show() {
    if (handle_) ShowWindow(handle_, SW_SHOW);
}

void Win32Window::Hide() {
    if (handle_) ShowWindow(handle_, SW_HIDE);
}

void Win32Window::Minimize() {
    if (handle_) ShowWindow(handle_, SW_MINIMIZE);
}

void Win32Window::Maximize() {
    if (handle_) ShowWindow(handle_, SW_MAXIMIZE);
}

void Win32Window::Restore() {
    if (handle_) ShowWindow(handle_, SW_RESTORE);
}

void Win32Window::SetFullscreen(bool fullscreen) {
    if (fullscreen_ == fullscreen) return;
    fullscreen_ = fullscreen;
    
    if (fullscreen) {
        SetWindowLong(handle_, GWL_STYLE, WS_POPUP | WS_VISIBLE);
        SetWindowPos(handle_, HWND_TOP, 0, 0, 
            GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN),
            SWP_FRAMECHANGED);
    } else {
        SetWindowLong(handle_, GWL_STYLE, WS_OVERLAPPEDWINDOW | WS_VISIBLE);
        SetWindowPos(handle_, HWND_TOP, 
            config_.x, config_.y, config_.width, config_.height,
            SWP_FRAMECHANGED);
    }
}

void Win32Window::SetTitle(const wchar_t* title) {
    if (handle_) SetWindowText(handle_, title);
}

void Win32Window::SetSize(uint32_t width, uint32_t height) {
    if (handle_) SetWindowPos(handle_, nullptr, 0, 0, width, height, SWP_NOMOVE | SWP_NOZORDER);
}

void Win32Window::GetSize(uint32_t& width, uint32_t& height) const {
    RECT rect;
    if (GetClientRect(handle_, &rect)) {
        width = rect.right - rect.left;
        height = rect.bottom - rect.top;
    }
}

void Win32Window::SetPosition(int32_t x, int32_t y) {
    if (handle_) SetWindowPos(handle_, nullptr, x, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
}

void Win32Window::GetPosition(int32_t& x, int32_t& y) const {
    RECT rect;
    if (GetWindowRect(handle_, &rect)) {
        x = rect.left;
        y = rect.top;
    }
}

float Win32Window::GetDPIScale() const {
    if (!handle_) return 1.0f;
    UINT dpi = GetDpiForWindow(handle_);
    return dpi / 96.0f;
}

void Win32Window::SetDPIAware() {
    SetProcessDPIAware();
    dpiAware_ = true;
}

HDC Win32Window::GetDC() const {
    return dc_;
}

void Win32Window::RegisterWindowClass() {
    static bool registered = false;
    if (registered) return;
    
    WNDCLASSEX wc = {};
    wc.cbSize = sizeof(WNDCLASSEX);
    wc.style = CS_HREDRAW | CS_VREDRAW | CS_DBLCLKS;
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = GetModuleHandle(nullptr);
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)GetStockObject(BLACK_BRUSH);
    wc.lpszClassName = L"SovereignWindowClass";
    wc.hIcon = LoadIcon(nullptr, IDI_APPLICATION);
    
    RegisterClassEx(&wc);
    registered = true;
}

LRESULT CALLBACK Win32Window::WindowProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    Win32Window* window = nullptr;
    
    if (msg == WM_NCCREATE) {
        auto cs = reinterpret_cast<CREATESTRUCT*>(lParam);
        window = static_cast<Win32Window*>(cs->lpCreateParams);
        SetWindowLongPtr(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(window));
    } else {
        window = reinterpret_cast<Win32Window*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));
    }
    
    if (window) {
        return window->HandleMessage(msg, wParam, lParam);
    }
    
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

LRESULT Win32Window::HandleMessage(UINT msg, WPARAM wParam, LPARAM lParam) {
    frameCount_++;
    
    // Forward to message handler
    if (messageHandler_) {
        WindowMessage wm;
        wm.msg = msg;
        wm.wParam = wParam;
        wm.lParam = lParam;
        wm.timestamp = GetTickCount64();
        messageHandler_(wm);
    }
    
    // Handle input
    HandleInput(msg, wParam, lParam);
    
    switch (msg) {
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
            
        case WM_SIZE:
            if (config_.resizable) {
                uint32_t w = LOWORD(lParam);
                uint32_t h = HIWORD(lParam);
                // Notify render backend of resize
            }
            return 0;
            
        case WM_DPICHANGED:
            {
                auto rect = reinterpret_cast<RECT*>(lParam);
                SetWindowPos(handle_, nullptr, rect->left, rect->top,
                    rect->right - rect->left, rect->bottom - rect->top,
                    SWP_NOZORDER | SWP_NOACTIVATE);
            }
            return 0;
            
        case WM_SETCURSOR:
            if (LOWORD(lParam) == HTCLIENT) {
                cursor_.SetCursor(cursor_.GetCurrentCursor());
                return TRUE;
            }
            break;
    }
    
    return DefWindowProc(handle_, msg, wParam, lParam);
}

void Win32Window::HandleInput(UINT msg, WPARAM wParam, LPARAM lParam) {
    if (!inputHandler_) return;
    
    InputEvent event = {};
    
    switch (msg) {
        case WM_KEYDOWN:
            event.type = InputEvent::KEY_DOWN;
            event.vkCode = static_cast<uint32_t>(wParam);
            event.scanCode = (lParam >> 16) & 0xFF;
            break;
            
        case WM_KEYUP:
            event.type = InputEvent::KEY_UP;
            event.vkCode = static_cast<uint32_t>(wParam);
            break;
            
        case WM_CHAR:
            event.type = InputEvent::CHAR;
            event.vkCode = static_cast<uint32_t>(wParam);
            break;
            
        case WM_MOUSEMOVE:
            event.type = InputEvent::MOUSE_MOVE;
            event.x = GET_X_LPARAM(lParam);
            event.y = GET_Y_LPARAM(lParam);
            break;
            
        case WM_LBUTTONDOWN:
            event.type = InputEvent::MOUSE_DOWN;
            event.x = GET_X_LPARAM(lParam);
            event.y = GET_Y_LPARAM(lParam);
            event.vkCode = VK_LBUTTON;
            break;
            
        case WM_LBUTTONUP:
            event.type = InputEvent::MOUSE_UP;
            event.x = GET_X_LPARAM(lParam);
            event.y = GET_Y_LPARAM(lParam);
            event.vkCode = VK_LBUTTON;
            break;
            
        case WM_MOUSEWHEEL:
            event.type = InputEvent::MOUSE_WHEEL;
            event.delta = GET_WHEEL_DELTA_WPARAM(wParam);
            break;
    }
    
    if (event.type != InputEvent::KEY_DOWN || event.type != InputEvent::KEY_UP) {
        inputHandler_(event);
    }
}

void Win32Window::MessageLoop() {
    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
}

void Win32Window::MessageLoopTimed(uint32_t intervalMs) {
    MSG msg;
    while (true) {
        while (PeekMessage(&msg, nullptr, 0, 0, PM_REMOVE)) {
            if (msg.message == WM_QUIT) return;
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
        Sleep(intervalMs);
    }
}

double Win32Window::GetFPS() const {
    uint64_t now = GetTickCount64();
    if (now - lastFPSTime_ >= 1000) {
        fps_ = frameCount_ * 1000.0 / (now - lastFPSTime_);
        return fps_;
    }
    return fps_;
}

} // namespace Sovereign
