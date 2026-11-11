#include "GhostTextOverlay.hpp"
#include <windowsx.h>
#include <dwmapi.h>

#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "gdi32.lib")

namespace RawrXD {
namespace UI {

GhostTextOverlay::GhostTextOverlay() = default;

GhostTextOverlay::~GhostTextOverlay() {
    Shutdown();
}

bool GhostTextOverlay::Initialize(HWND parentHwnd) {
    if (!parentHwnd || !IsWindow(parentHwnd)) {
        return false;
    }
    
    parentHwnd_ = parentHwnd;
    CreateOverlayWindow();
    
    return overlayHwnd_ != nullptr;
}

void GhostTextOverlay::Shutdown() {
    Hide();
    
    if (memDC_) {
        DeleteDC(memDC_);
        memDC_ = nullptr;
    }
    if (memBitmap_) {
        DeleteObject(memBitmap_);
        memBitmap_ = nullptr;
    }
    if (overlayHwnd_) {
        DestroyWindow(overlayHwnd_);
        overlayHwnd_ = nullptr;
    }
    
    parentHwnd_ = nullptr;
}

void GhostTextOverlay::CreateOverlayWindow() {
    static const wchar_t CLASS_NAME[] = L"RawrXD_GhostTextOverlay";
    
    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = GetModuleHandle(nullptr);
    wc.lpszClassName = CLASS_NAME;
    wc.hbrBackground = (HBRUSH)GetStockObject(NULL_BRUSH);
    
    RegisterClassExW(&wc);
    
    overlayHwnd_ = CreateWindowExW(
        WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW,
        CLASS_NAME,
        L"GhostText",
        WS_POPUP,
        0, 0, 0, 0,
        parentHwnd_,
        nullptr,
        GetModuleHandle(nullptr),
        this
    );
    
    if (overlayHwnd_) {
        SetLayeredWindowAttributes(overlayHwnd_, RGB(0, 0, 0), 0, LWA_COLORKEY);
    }
}

void GhostTextOverlay::ShowAt(int line, int column, const std::string& text) {
    if (!overlayHwnd_) return;
    
    anchorLine_ = line;
    anchorColumn_ = column;
    currentText_ = text;
    visible_ = true;
    
    PositionOverlay();
    Render();
    
    ShowWindow(overlayHwnd_, SW_SHOWNA);
    UpdateWindow(overlayHwnd_);
}

void GhostTextOverlay::Hide() {
    if (!overlayHwnd_ || !visible_) return;
    
    visible_ = false;
    ShowWindow(overlayHwnd_, SW_HIDE);
}

void GhostTextOverlay::UpdateText(const std::string& text) {
    currentText_ = text;
    if (visible_) {
        Render();
    }
}

void GhostTextOverlay::AppendText(const std::string& fragment) {
    currentText_ += fragment;
    if (visible_) {
        Render();
    }
}

void GhostTextOverlay::SetAcceptCallback(std::function<void(const std::string&)> callback) {
    onAccept_ = std::move(callback);
}

void GhostTextOverlay::SetDismissCallback(std::function<void()> callback) {
    onDismiss_ = std::move(callback);
}

void GhostTextOverlay::Accept() {
    if (onAccept_) {
        onAccept_(currentText_);
    }
    Hide();
}

void GhostTextOverlay::Dismiss() {
    if (onDismiss_) {
        onDismiss_();
    }
    Hide();
}

void GhostTextOverlay::OnParentResize() {
    if (visible_) {
        PositionOverlay();
        Render();
    }
}

void GhostTextOverlay::OnParentScroll() {
    if (visible_) {
        PositionOverlay();
    }
}

void GhostTextOverlay::PositionOverlay() {
    if (!parentHwnd_ || !overlayHwnd_) return;
    
    // Get caret position in parent (simplified - assumes RichEdit)
    POINT pt = {};
    SendMessage(parentHwnd_, EM_POSFROMCHAR, (WPARAM)&pt, 
                SendMessage(parentHwnd_, EM_LINEINDEX, anchorLine_, 0) + anchorColumn_);
    
    ClientToScreen(parentHwnd_, &pt);
    
    // Calculate size based on text
    HDC hdc = GetDC(overlayHwnd_);
    SIZE size = {};
    
    HFONT font = (HFONT)SendMessage(parentHwnd_, WM_GETFONT, 0, 0);
    HFONT oldFont = (HFONT)SelectObject(hdc, font);
    
    std::wstring wtext(currentText_.begin(), currentText_.end());
    GetTextExtentPoint32W(hdc, wtext.c_str(), (int)wtext.length(), &size);
    
    SelectObject(hdc, oldFont);
    ReleaseDC(overlayHwnd_, hdc);
    
    int width = size.cx + PADDING_X * 2;
    int height = size.cy + PADDING_Y * 2;
    
    SetWindowPos(overlayHwnd_, nullptr, pt.x, pt.y, width, height,
                 SWP_NOZORDER | SWP_NOACTIVATE);
}

void GhostTextOverlay::Render() {
    if (!overlayHwnd_ || currentText_.empty()) return;
    
    RECT rc;
    GetClientRect(overlayHwnd_, &rc);
    int width = rc.right - rc.left;
    int height = rc.bottom - rc.top;
    
    // Create memory DC
    HDC screenDC = GetDC(nullptr);
    if (!memDC_) {
        memDC_ = CreateCompatibleDC(screenDC);
    }
    if (memBitmap_) {
        DeleteObject(memBitmap_);
    }
    memBitmap_ = CreateCompatibleBitmap(screenDC, width, height);
    HGDIOBJ oldBmp = SelectObject(memDC_, memBitmap_);
    ReleaseDC(nullptr, screenDC);
    
    // Clear background
    RECT fillRc = {0, 0, width, height};
    FillRect(memDC_, &fillRc, (HBRUSH)GetStockObject(WHITE_BRUSH));
    
    // Draw text
    SetBkMode(memDC_, TRANSPARENT);
    SetTextColor(memDC_, GHOST_TEXT_COLOR);
    
    HFONT font = (HFONT)SendMessage(parentHwnd_, WM_GETFONT, 0, 0);
    HFONT oldFont = (HFONT)SelectObject(memDC_, font);
    
    std::wstring wtext(currentText_.begin(), currentText_.end());
    TextOutW(memDC_, PADDING_X, PADDING_Y, wtext.c_str(), (int)wtext.length());
    
    SelectObject(memDC_, oldFont);
    
    // Update layered window
    POINT ptSrc = {0, 0};
    SIZE size = {width, height};
    BLENDFUNCTION blend = {AC_SRC_OVER, 0, 220, 0};
    
    UpdateLayeredWindow(overlayHwnd_, nullptr, nullptr, &size, memDC_, &ptSrc, 0, &blend, ULW_ALPHA);
    
    SelectObject(memDC_, oldBmp);
}

LRESULT CALLBACK GhostTextOverlay::WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    GhostTextOverlay* self = nullptr;
    
    if (msg == WM_NCCREATE) {
        LPCREATESTRUCT lpcs = reinterpret_cast<LPCREATESTRUCT>(lParam);
        self = static_cast<GhostTextOverlay*>(lpcs->lpCreateParams);
        SetWindowLongPtr(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
    } else {
        self = reinterpret_cast<GhostTextOverlay*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));
    }
    
    if (!self) {
        return DefWindowProc(hwnd, msg, wParam, lParam);
    }
    
    switch (msg) {
        case WM_PAINT: {
            PAINTSTRUCT ps;
            BeginPaint(hwnd, &ps);
            self->Render();
            EndPaint(hwnd, &ps);
            return 0;
        }
        
        case WM_LBUTTONDOWN:
            self->Accept();
            return 0;
            
        case WM_RBUTTONDOWN:
            self->Dismiss();
            return 0;
            
        case WM_KEYDOWN:
            if (wParam == VK_TAB || wParam == VK_RETURN) {
                self->Accept();
                return 0;
            } else if (wParam == VK_ESCAPE) {
                self->Dismiss();
                return 0;
            }
            break;
    }
    
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

} // namespace UI
} // namespace RawrXD
