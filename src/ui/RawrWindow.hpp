// ============================================================================
// RawrWindow.hpp — Native Window Manager
// HWND creation, window procedure, resize, input
// ============================================================================

#ifndef RAWR_WINDOW_HPP
#define RAWR_WINDOW_HPP

#include <cstdint>
#include <functional>

#ifdef _WIN32
#include <windows.h>
#endif

namespace rawr {

// ============================================================================
// Window Configuration
// ============================================================================
struct WindowConfig {
    const char* title = "RawrXD Sovereign Runtime";
    uint32_t width = 1280;
    uint32_t height = 800;
    uint32_t minWidth = 800;
    uint32_t minHeight = 600;
    bool resizable = true;
    bool maximized = false;
};

// ============================================================================
// Window Callbacks
// ============================================================================
using WindowResizeCallback = std::function<void(uint32_t width, uint32_t height)>;
using WindowCloseCallback = std::function<bool()>;

// ============================================================================
// RawrWindow — Main application window
// ============================================================================
class RawrWindow {
public:
    static RawrWindow& Get();

    bool Create(const WindowConfig& config);
    void Destroy();
    void* GetHandle() const { return m_hwnd; }

    // Message loop
    int Run();
    void RequestClose();
    bool IsRunning() const { return m_running; }

    // Sizing
    void GetSize(uint32_t& width, uint32_t& height) const;
    void SetSize(uint32_t width, uint32_t height);
    void SetTitle(const char* title);

    // Callbacks
    void SetOnResize(WindowResizeCallback cb) { m_onResize = std::move(cb); }
    void SetOnClose(WindowCloseCallback cb) { m_onClose = std::move(cb); }

    // Window procedure (public for WndProc)
    LRESULT HandleMessage(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);

private:
    RawrWindow() = default;
    ~RawrWindow() { Destroy(); }
    RawrWindow(const RawrWindow&) = delete;
    RawrWindow& operator=(const RawrWindow&) = delete;

    bool RegisterClass(void* hInstance);

    void* m_hwnd = nullptr;
    void* m_hInstance = nullptr;
    WindowConfig m_config;
    bool m_running = false;

    WindowResizeCallback m_onResize;
    WindowCloseCallback m_onClose;
};

} // namespace rawr

#endif // RAWR_WINDOW_HPP
