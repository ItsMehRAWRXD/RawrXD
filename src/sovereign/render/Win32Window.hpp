// ============================================================================
// Win32Window.hpp - Raw Win32 Windowing Substrate
// Zero-overhead window management for the Sovereign IDE Canvas
// ============================================================================

#pragma once

#include <cstdint>
#include <string>
#include <functional>
#include <memory>

namespace Sovereign {

// Window style
enum class WindowStyle {
    OVERLAPPED,
    POPUP,
    CHILD,
    LAYERED,
    TRANSPARENT
};

// Window state
enum class WindowState {
    NORMAL,
    MINIMIZED,
    MAXIMIZED,
    FULLSCREEN,
    HIDDEN
};

// Window message
struct WindowMessage {
    uint32_t msg;
    uint64_t wParam;
    int64_t lParam;
    uint64_t timestamp;
};

// Input event
struct InputEvent {
    enum Type {
        KEY_DOWN,
        KEY_UP,
        CHAR,
        MOUSE_MOVE,
        MOUSE_DOWN,
        MOUSE_UP,
        MOUSE_WHEEL,
        MOUSE_HWHEEL,
        TOUCH,
        GESTURE
    };
    Type type;
    uint32_t vkCode;
    uint32_t scanCode;
    int x;
    int y;
    int delta;
    uint32_t flags;
};

// Window configuration
struct WindowConfig {
    const wchar_t* title = L"Sovereign IDE";
    uint32_t width = 1920;
    uint32_t height = 1080;
    int32_t x = CW_USEDEFAULT;
    int32_t y = CW_USEDEFAULT;
    WindowStyle style = WindowStyle::OVERLAPPED;
    bool resizable = true;
    bool borderless = false;
    bool alwaysOnTop = false;
    uint32_t refreshRate = 0; // 0 = default
    void* parentWindow = nullptr;
    HICON icon = nullptr;
    HCURSOR cursor = LoadCursor(nullptr, IDC_ARROW);
};

// Cursor controller
class CursorController {
public:
    CursorController();
    ~CursorController();

    // Cursor visibility
    void Show();
    void Hide();
    bool IsVisible() const { return visible_; }

    // Cursor position
    void SetPosition(int x, int y);
    void GetPosition(int& x, int& y) const;

    // Cursor shape
    void SetCursor(HCURSOR cursor);
    void SetArrow();
    void SetHand();
    void SetIBeam();
    void SetCross();
    void SetWait();
    void SetCustom(const uint8_t* bitmap, uint32_t width, uint32_t height, int hotX, int hotY);

    // Cursor clipping
    void ClipToRect(int x, int y, int w, int h);
    void Unclip();
    bool IsClipped() const { return clipped_; }

    // Cursor constraints
    void SetSpeed(float multiplier);
    float GetSpeed() const { return speed_; }
    void SetAcceleration(bool enabled);

    // Raw input
    void RegisterRawInput(void* windowHandle);
    void ProcessRawInput(const void* rawInputData);

private:
    bool visible_ = true;
    bool clipped_ = false;
    float speed_ = 1.0f;
    HCURSOR currentCursor_ = nullptr;
    int clipX_, clipY_, clipW_, clipH_;
};

// Raw Win32 window
class Win32Window {
public:
    Win32Window();
    ~Win32Window();

    // Window lifecycle
    bool Create(const WindowConfig& config);
    void Destroy();
    bool IsValid() const { return handle_ != nullptr; }

    // Window state
    void Show();
    void Hide();
    void Minimize();
    void Maximize();
    void Restore();
    void SetFullscreen(bool fullscreen);
    bool IsFullscreen() const { return fullscreen_; }

    // Window properties
    void SetTitle(const wchar_t* title);
    void SetSize(uint32_t width, uint32_t height);
    void SetPosition(int32_t x, int32_t y);
    void GetSize(uint32_t& width, uint32_t& height) const;
    void GetPosition(int32_t& x, int32_t& y) const;
    float GetDPIScale() const;

    // Message processing
    bool PumpMessage(WindowMessage& msg);
    void ProcessMessages();
    void SetMessageHandler(std::function<void(const WindowMessage&)> handler);

    // Input
    void SetInputHandler(std::function<void(const InputEvent&)> handler);
    CursorController& GetCursor() { return cursor_; }

    // DPI awareness
    void SetDPIAware();
    bool IsDPIAware() const { return dpiAware_; }

    // Window handle
    HWND GetHandle() const { return handle_; }
    HDC GetDC() const;
    void* GetNativeHandle() const { return handle_; }

    // Message loop
    static void MessageLoop();
    static void MessageLoopTimed(uint32_t intervalMs);

    // Statistics
    uint64_t GetFrameCount() const { return frameCount_; }
    double GetFPS() const;

private:
    HWND handle_ = nullptr;
    HDC dc_ = nullptr;
    bool fullscreen_ = false;
    bool dpiAware_ = false;
    uint64_t frameCount_ = 0;
    uint64_t lastFPSTime_ = 0;
    double fps_ = 0.0;
    
    WindowConfig config_;
    CursorController cursor_;
    
    std::function<void(const WindowMessage&)> messageHandler_;
    std::function<void(const InputEvent&)> inputHandler_;
    
    static LRESULT CALLBACK WindowProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    LRESULT HandleMessage(UINT msg, WPARAM wParam, LPARAM lParam);
    
    void RegisterWindowClass();
    void HandleInput(UINT msg, WPARAM wParam, LPARAM lParam);
};

} // namespace Sovereign
