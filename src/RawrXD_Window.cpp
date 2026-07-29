#include "RawrXD_Window.h"
#include <windowsx.h>

namespace RawrXD {

LRESULT CALLBACK Window::WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    Window* window = nullptr;
    
    if (msg == WM_NCCREATE) {
        CREATESTRUCT* cs = (CREATESTRUCT*)lParam;
        window = (Window*)cs->lpCreateParams;
        SetWindowLongPtr(hwnd, GWLP_USERDATA, (LONG_PTR)window);
        window->hwnd = hwnd;
    } else {
        window = (Window*)GetWindowLongPtr(hwnd, GWLP_USERDATA);
    }
    
    if (window) {
        return window->handleMessage(msg, wParam, lParam);
    }
    
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

Window::~Window() {
    if (hwnd) {
        // Remove from parent
        if (parent) {
            parent->removeChild(this);
        }
        // Destroy children?
        for (auto* child : children) {
            delete child; // Assumes ownership
        }
        DestroyWindow(hwnd);
    }
}

void Window::create(Window* parent_, const String& title, DWORD style, DWORD exStyle) {
    parent = parent_;
    if (parent) {
        parent->addChild(this);
        style |= WS_CHILD; // Force child style if parent exists
    }
    
    static const wchar_t* className = L"RawrXD_Window";
    static bool classRegistered = false;
    
    if (!classRegistered) {
        WNDCLASSEXW wc = {};
        wc.cbSize = sizeof(wc);
        wc.lpfnWndProc = WndProc;
        wc.hInstance = GetModuleHandleW(nullptr);
        wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
        wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
        wc.lpszClassName = className;
        RegisterClassExW(&wc);
        classRegistered = true;
    }
    
<<<<<<< HEAD
    HWND hwnd_ = CreateWindowExW(exStyle, className, title.c_str(), style,
                    CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
                    parentHwnd, nullptr, GetModuleHandleW(nullptr), this);
    
    if (hwnd_ && !hwnd) {
        hwnd = hwnd_;
        SetWindowLongPtr(hwnd, GWLP_USERDATA, (LONG_PTR)this);
    }
                    
    // hwnd is set in WndProc WM_NCCREATE or here as fallback
=======
    HWND parentHwnd = parent ? parent->nativeHandle() : nullptr;
    
    CreateWindowExW(exStyle, className, title.c_str(), style,
                    CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
                    parentHwnd, nullptr, GetModuleHandleW(nullptr), this);
                    
    // hwnd is set in WndProc WM_NCCREATE
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}


LRESULT Window::handleMessage(UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_PAINT: {
            PAINTSTRUCT ps;
            BeginPaint(hwnd, &ps);
            paintEvent(ps);
            EndPaint(hwnd, &ps);
            return 0;
        }
        case WM_SIZE:
            resizeEvent(LOWORD(lParam), HIWORD(lParam));
            return 0;
        case WM_LBUTTONDOWN:
        case WM_RBUTTONDOWN:
        case WM_MBUTTONDOWN: {
            int button = 0;
            if (msg == WM_LBUTTONDOWN) button = 1;
            else if (msg == WM_RBUTTONDOWN) button = 2;
            else if (msg == WM_MBUTTONDOWN) button = 3;
            mousePressEvent(GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam), button);
            return 0;
        }
        case WM_LBUTTONUP:
        case WM_RBUTTONUP:
        case WM_MBUTTONUP: {
            int button = 0;
            if (msg == WM_LBUTTONUP) button = 1;
            else if (msg == WM_RBUTTONUP) button = 2;
            else if (msg == WM_MBUTTONUP) button = 3;
            mouseReleaseEvent(GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam), button);
            return 0;
        }
<<<<<<< HEAD
        case WM_MOUSEMOVE: {
            // Extract modifier flags from wParam
            int modifiers = 0;
            if (wParam & MK_SHIFT)   modifiers |= 0x01; // Shift
            if (wParam & MK_CONTROL) modifiers |= 0x02; // Ctrl
            if (GetKeyState(VK_MENU) & 0x8000) modifiers |= 0x04; // Alt
            mouseMoveEvent(GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam), modifiers);
            return 0;
        }
        case WM_KEYDOWN: {
            // Extract keyboard modifiers from GetKeyState
            int modifiers = 0;
            if (GetKeyState(VK_SHIFT)   & 0x8000) modifiers |= 0x01; // Shift
            if (GetKeyState(VK_CONTROL) & 0x8000) modifiers |= 0x02; // Ctrl
            if (GetKeyState(VK_MENU)    & 0x8000) modifiers |= 0x04; // Alt
            if (GetKeyState(VK_LWIN) & 0x8000 || GetKeyState(VK_RWIN) & 0x8000)
                modifiers |= 0x08; // Win/Super
            keyPressEvent((int)wParam, modifiers);
            return 0;
        }
=======
        case WM_MOUSEMOVE:
             // Explicit Logic: Extract Modifiers
             {
                 int modifiers = 0;
                 if (wParam & MK_CONTROL) modifiers |= 1; // Control
                 if (wParam & MK_SHIFT)   modifiers |= 2; // Shift
                 mouseMoveEvent(GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam), modifiers);
             }
            return 0;
        case WM_KEYDOWN:
            {
                int modifiers = 0;
                if (GetKeyState(VK_CONTROL) & 0x8000) modifiers |= 1;
                if (GetKeyState(VK_SHIFT) & 0x8000)   modifiers |= 2;
                if (GetKeyState(VK_MENU) & 0x8000)    modifiers |= 4; // Alt
                keyPressEvent((int)wParam, modifiers);
            }
            return 0;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
        case WM_CHAR:
            charEvent((wchar_t)wParam);
            return 0;
        case WM_CLOSE:
            closeEvent();
            return 0;
        case WM_DESTROY:
<<<<<<< HEAD
             if (!parent) {
                 PostQuitMessage(0);
             }
=======
             // If this is the main window, we might want to post quit message, 
             // but 'Window' shouldn't decide that. Application should.
             // For now, doing nothing.
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
            return 0;
    }
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

void Window::paintEvent(PAINTSTRUCT& ps) {
    // Default: fill with background color?
    // Let DefWindowProc handle it via hbrBackground class style for now.
}

void Window::resizeEvent(int w, int h) {
    // Default: resize children?
}

<<<<<<< HEAD
void Window::mousePressEvent(int x, int y, int button) {
    // Track mouse button state
    if (button >= 0 && button < 3) {
        m_mouseButtons[button] = true;
    }
    m_lastMouseX = x;
    m_lastMouseY = y;
    
    // Notify any registered mouse press callbacks
    if (m_mousePressCallback) {
        m_mousePressCallback(x, y, button);
    }
}

void Window::mouseReleaseEvent(int x, int y, int button) {
    // Update button state
    if (button >= 0 && button < 3) {
        m_mouseButtons[button] = false;
    }
    m_lastMouseX = x;
    m_lastMouseY = y;
    
    // Notify any registered mouse release callbacks
    if (m_mouseReleaseCallback) {
        m_mouseReleaseCallback(x, y, button);
    }
}

void Window::mouseMoveEvent(int x, int y, int mods) {
    m_lastMouseX = x;
    m_lastMouseY = y;
    m_mouseModifiers = mods;
    
    // Notify any registered mouse move callbacks
    if (m_mouseMoveCallback) {
        m_mouseMoveCallback(x, y, mods);
    }
}

void Window::keyPressEvent(int key, int mods) {
    // Update key state
    if (key >= 0 && key < 256) {
        m_keyStates[key] = true;
    }
    m_keyModifiers = mods;
    
    // Notify any registered key press callbacks
    if (m_keyPressCallback) {
        m_keyPressCallback(key, mods);
    }
}

void Window::charEvent(wchar_t c) {
    // Handle character input (for text entry)
    if (m_charCallback) {
        m_charCallback(c);
    }
}
=======
void Window::mousePressEvent(int x, int y, int button) {}
void Window::mouseReleaseEvent(int x, int y, int button) {}
void Window::mouseMoveEvent(int x, int y, int mods) {}
void Window::keyPressEvent(int key, int mods) {}
void Window::charEvent(wchar_t c) {}
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

void Window::closeEvent() {
    DestroyWindow(hwnd);
}

void Window::show() { ShowWindow(hwnd, SW_SHOW); }
void Window::hide() { ShowWindow(hwnd, SW_HIDE); }

void Window::move(int x, int y) {
    SetWindowPos(hwnd, nullptr, x, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
}

void Window::resize(int w, int h) {
    SetWindowPos(hwnd, nullptr, 0, 0, w, h, SWP_NOMOVE | SWP_NOZORDER);
}

void Window::setGeometry(int x, int y, int w, int h) {
    SetWindowPos(hwnd, nullptr, x, y, w, h, SWP_NOZORDER);
}

void Window::setTitle(const String& s) {
    SetWindowTextW(hwnd, s.c_str());
}

String Window::title() const {
    int len = GetWindowTextLengthW(hwnd);
    if (len <= 0) return String();
    std::wstring s(len + 1, 0);
    GetWindowTextW(hwnd, s.data(), len + 1);
    s.resize(len);
    return String(s);
}

void Window::update() {
    InvalidateRect(hwnd, nullptr, FALSE);
}

int Window::width() const {
    RECT r;
    GetWindowRect(hwnd, &r);
    return r.right - r.left;
}

int Window::height() const {
    RECT r;
    GetWindowRect(hwnd, &r);
    return r.bottom - r.top; 
}

void Window::addChild(Window* child) {
    children.push_back(child);
}

void Window::removeChild(Window* child) {
    auto it = std::find(children.begin(), children.end(), child);
    if (it != children.end()) {
        children.erase(it);
    }
}

} // namespace RawrXD
