#pragma once

#include <windows.h>
#include <functional>
#include <cstdint>

namespace Sunshine {

struct WindowConfig {
    int width = 1280;
    int height = 720;
    const char* title = "Sunshine";
    bool fullscreen = false;
};

class Window {
public:
    bool initialize(const WindowConfig& config);
    void shutdown();
    bool processMessages();
    void present();

    HWND getHandle() const { return m_hwnd; }
    int getWidth() const { return m_width; }
    int getHeight() const { return m_height; }
    bool shouldClose() const { return m_shouldClose; }
    void requestClose() { m_shouldClose = true; }

    void setResizeCallback(std::function<void(int, int)> cb) { m_resizeCb = cb; }

private:
    static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    LRESULT handleMessage(UINT msg, WPARAM wParam, LPARAM lParam);

    HWND m_hwnd = nullptr;
    HINSTANCE m_hinst = nullptr;
    int m_width = 0;
    int m_height = 0;
    bool m_shouldClose = false;
    std::function<void(int, int)> m_resizeCb;
};

} // namespace Sunshine
