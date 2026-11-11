#pragma once
#include <windows.h>
#include <string>
#include <functional>
#include <atomic>

namespace RawrXD {
namespace UI {

class GhostTextOverlay {
public:
    GhostTextOverlay();
    ~GhostTextOverlay();
    
    bool Initialize(HWND parentHwnd);
    void Shutdown();
    
    void ShowAt(int line, int column, const std::string& text);
    void Hide();
    void UpdateText(const std::string& text);
    void AppendText(const std::string& fragment);
    
    bool IsVisible() const { return visible_; }
    std::string GetCurrentText() const { return currentText_; }
    
    void SetAcceptCallback(std::function<void(const std::string&)> callback);
    void SetDismissCallback(std::function<void()> callback);
    
    void Accept();
    void Dismiss();
    
    void OnParentResize();
    void OnParentScroll();
    
private:
    static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    void CreateOverlayWindow();
    void PositionOverlay();
    void Render();
    
    HWND parentHwnd_ = nullptr;
    HWND overlayHwnd_ = nullptr;
    HDC memDC_ = nullptr;
    HBITMAP memBitmap_ = nullptr;
    
    int anchorLine_ = 0;
    int anchorColumn_ = 0;
    std::string currentText_;
    std::atomic<bool> visible_{false};
    
    std::function<void(const std::string&)> onAccept_;
    std::function<void()> onDismiss_;
    
    static constexpr int PADDING_X = 4;
    static constexpr int PADDING_Y = 2;
    static constexpr COLORREF GHOST_TEXT_COLOR = RGB(128, 128, 128);
    static constexpr COLORREF GHOST_BG_COLOR = RGB(240, 240, 240);
};

} // namespace UI
} // namespace RawrXD
