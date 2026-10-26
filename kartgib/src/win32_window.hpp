#pragma once

#define VK_USE_PLATFORM_WIN32_KHR
#include <vulkan/vulkan.h>
#include <windows.h>
#include <string>
#include <functional>

class Win32Window {
public:
    Win32Window(int width, int height, const std::string& title, bool fullscreen = false);
    ~Win32Window();

    Win32Window(const Win32Window&) = delete;
    Win32Window& operator=(const Win32Window&) = delete;

    VkSurfaceKHR createSurface(VkInstance instance);
    HWND getHandle() const { return hwnd_; }
    HINSTANCE getInstance() const { return hinstance_; }

    bool shouldClose() const { return shouldClose_; }
    void pollEvents();
    void swapBuffers() { /* Vulkan handles presentation */ }

    int getWidth() const { return width_; }
    int getHeight() const { return height_; }
    bool isMinimized() const { return minimized_; }
    bool isResized() const { return resized_; }
    void clearResized() { resized_ = false; }

    void setUserPointer(void* ptr) { userPointer_ = ptr; }
    void* getUserPointer() const { return userPointer_; }

    void setTitle(const std::string& title) { SetWindowTextA(hwnd_, title.c_str()); }

    void cleanup();

    // Keyboard state
    bool isKeyPressed(int virtualKey) const;

    void setKeyCallback(std::function<void(int, bool)> callback) {
        keyCallback_ = callback;
    }
    void noteMouse(int dx, int dy) { mouseDx_ += dx; mouseDy_ += dy; }
    void consumeMouse(int& dx, int& dy) { dx = mouseDx_; dy = mouseDy_; mouseDx_ = mouseDy_ = 0; }
    void consumePointer(int& x, int& y, int& downX, int& downY, bool& clicked, bool& released) {
        x = mouseX_; y = mouseY_; downX = mouseDownX_; downY = mouseDownY_;
        clicked = clickEdge_; released = releaseEdge_;
        clickEdge_ = false; releaseEdge_ = false;
    }

private:
    static LRESULT CALLBACK wndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);

    HWND hwnd_ = nullptr;
    HINSTANCE hinstance_ = nullptr;
    int width_;
    int height_;
    bool minimized_ = false;
    bool resized_ = false;
    bool shouldClose_ = false;
    void* userPointer_ = nullptr;
    std::function<void(int, bool)> keyCallback_;
    bool keyStates_[256] = { false };
    int mouseX_ = 0;
    int mouseY_ = 0;
    int mouseDx_ = 0;
    int mouseDy_ = 0;
    bool mouseSeen_ = false;
    int mouseDownX_ = 0;
    int mouseDownY_ = 0;
    bool clickEdge_ = false;
    bool releaseEdge_ = false;
};