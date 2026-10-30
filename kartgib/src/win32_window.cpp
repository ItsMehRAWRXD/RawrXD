#include "win32_window.hpp"
void inspectorLayout(int width, int height);
#include <iostream>

Win32Window::Win32Window(int width, int height, const std::string& title, bool fullscreen)
    : width_(width), height_(height) {

    hinstance_ = GetModuleHandle(nullptr);

    WNDCLASSEXA wc = {};
    wc.cbSize = sizeof(WNDCLASSEXA);
    wc.style = CS_HREDRAW | CS_VREDRAW | CS_OWNDC;
    wc.lpfnWndProc = wndProc;
    wc.hInstance = hinstance_;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = "KartGibWindowClass";

    if (!RegisterClassExA(&wc)) {
        throw std::runtime_error("Failed to register window class");
    }

    DWORD style = WS_OVERLAPPEDWINDOW;
    if (fullscreen) {
        style = WS_POPUP | WS_VISIBLE;
        width_ = GetSystemMetrics(SM_CXSCREEN);
        height_ = GetSystemMetrics(SM_CYSCREEN);
    }

    RECT rect = { 0, 0, width_, height_ };
    AdjustWindowRect(&rect, style, FALSE);

    hwnd_ = CreateWindowExA(
        0,
        "KartGibWindowClass",
        title.c_str(),
        style | WS_VISIBLE,
        CW_USEDEFAULT, CW_USEDEFAULT,
        rect.right - rect.left, rect.bottom - rect.top,
        nullptr, nullptr, hinstance_, this
    );

    if (!hwnd_) {
        throw std::runtime_error("Failed to create window");
    }

    ShowWindow(hwnd_, SW_SHOW);
    UpdateWindow(hwnd_);

    std::cout << "Window created: " << width_ << "x" << height_ << (fullscreen ? " (fullscreen)" : "") << std::endl;
}

Win32Window::~Win32Window() {
    cleanup();
}

VkSurfaceKHR Win32Window::createSurface(VkInstance instance) {
    std::cout << "[G03] surface: ENTER" << std::endl;
    std::cout << "[G03] calling vkCreateWin32SurfaceKHR directly..." << std::endl;
    
    if (instance == VK_NULL_HANDLE || hwnd_ == nullptr) {
        throw std::runtime_error("Invalid Vulkan instance or HWND");
    }

    VkWin32SurfaceCreateInfoKHR surfaceInfo{};
    surfaceInfo.sType = VK_STRUCTURE_TYPE_WIN32_SURFACE_CREATE_INFO_KHR;
    surfaceInfo.hinstance = hinstance_;
    surfaceInfo.hwnd = hwnd_;

    VkSurfaceKHR surface;
    std::cout << "[G03] vkCreateWin32SurfaceKHR: BEFORE" << std::endl;
    VkResult result = vkCreateWin32SurfaceKHR(instance, &surfaceInfo, nullptr, &surface);
    std::cout << "[G03] vkCreateWin32SurfaceKHR: AFTER result=" << static_cast<int>(result) << std::endl;

    if (result != VK_SUCCESS) {
        throw std::runtime_error("Failed to create Vulkan Win32 surface");
    }

    std::cout << "[G03] surface: PASS" << std::endl;
    return surface;
}

void Win32Window::pollEvents() {
    MSG msg = {};
    while (PeekMessageA(&msg, nullptr, 0, 0, PM_REMOVE)) {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }
}

bool Win32Window::isKeyPressed(int virtualKey) const {
    if (virtualKey < 0 || virtualKey >= 256) return false;
    return keyStates_[virtualKey];
}

void Win32Window::cleanup() {
    if (hwnd_) {
        DestroyWindow(hwnd_);
        hwnd_ = nullptr;
    }
}

LRESULT CALLBACK Win32Window::wndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    Win32Window* window = nullptr;

    if (msg == WM_NCCREATE) {
        CREATESTRUCT* cs = reinterpret_cast<CREATESTRUCT*>(lParam);
        window = static_cast<Win32Window*>(cs->lpCreateParams);
        SetWindowLongPtrA(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(window));
    } else {
        window = reinterpret_cast<Win32Window*>(GetWindowLongPtrA(hwnd, GWLP_USERDATA));
    }

    if (window) {
        switch (msg) {
            case WM_CLOSE:
                window->shouldClose_ = true;
                break;
            case WM_SIZE:
                window->width_ = LOWORD(lParam);
                window->height_ = HIWORD(lParam);
                window->minimized_ = (window->width_ == 0 || window->height_ == 0);
                window->resized_ = true;
                inspectorLayout(window->width_, window->height_);
                break;
            case WM_KEYDOWN:
                if (wParam < 256) {
                    window->keyStates_[wParam] = true;
                    if (window->keyCallback_) window->keyCallback_(wParam, true);
                }
                if (wParam == VK_ESCAPE) {
                    window->shouldClose_ = true;
                }
                break;
            case WM_LBUTTONDOWN: {
                int x = static_cast<short>(LOWORD(lParam));
                int y = static_cast<short>(HIWORD(lParam));
                window->mouseX_ = window->mouseDownX_ = x;
                window->mouseY_ = window->mouseDownY_ = y;
                window->clickEdge_ = true;
                window->mouseSeen_ = true;
                break;
            }
            case WM_LBUTTONUP: {
                window->mouseX_ = static_cast<short>(LOWORD(lParam));
                window->mouseY_ = static_cast<short>(HIWORD(lParam));
                window->releaseEdge_ = true;
                break;
            }
            case WM_MOUSEMOVE: {
                int x = static_cast<short>(LOWORD(lParam));
                int y = static_cast<short>(HIWORD(lParam));
                if (window->mouseSeen_) window->noteMouse(x - window->mouseX_, y - window->mouseY_);
                window->mouseX_ = x;
                window->mouseY_ = y;
                window->mouseSeen_ = true;
                break;
            }
            case WM_KEYUP:
                if (wParam < 256) {
                    window->keyStates_[wParam] = false;
                    if (window->keyCallback_) window->keyCallback_(wParam, false);
                }
                break;
        }
    }

    return DefWindowProcA(hwnd, msg, wParam, lParam);
}