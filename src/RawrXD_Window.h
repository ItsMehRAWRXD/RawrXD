#pragma once
#include "RawrXD_SignalSlot.h"

namespace RawrXD {

class Window {
protected:
    HWND hwnd = nullptr;
    static LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);
    
    // Event handlers - mapped from Windows messages
    virtual LRESULT handleMessage(UINT msg, WPARAM wParam, LPARAM lParam);
    virtual void paintEvent(PAINTSTRUCT& ps);
    virtual void resizeEvent(int w, int h);
    virtual void mousePressEvent(int x, int y, int button);
    virtual void mouseReleaseEvent(int x, int y, int button);
    virtual void mouseMoveEvent(int x, int y, int mods);
    virtual void keyPressEvent(int key, int mods);
    virtual void charEvent(wchar_t c);
    virtual void closeEvent();

public:
    Window* parent = nullptr;
    std::vector<Window*> children;
    
<<<<<<< HEAD
    // Callback setters for event handling
    using MouseCallback = std::function<void(int, int, int)>;
    using KeyCallback = std::function<void(int, int)>;
    using CharCallback = std::function<void(wchar_t)>;
    
    void setMousePressCallback(MouseCallback cb) { m_mousePressCallback = cb; }
    void setMouseReleaseCallback(MouseCallback cb) { m_mouseReleaseCallback = cb; }
    void setMouseMoveCallback(std::function<void(int, int, int)> cb) { m_mouseMoveCallback = cb; }
    void setKeyPressCallback(KeyCallback cb) { m_keyPressCallback = cb; }
    void setCharCallback(CharCallback cb) { m_charCallback = cb; }
    
=======
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    Window() = default;
    Window(Window* p) : parent(p) {}
    virtual ~Window();
    
    void create(Window* parent, const String& title, DWORD style = WS_OVERLAPPEDWINDOW, DWORD exStyle = 0);
    
    void show();
    void hide();
    void move(int x, int y);
    void resize(int w, int h);
    void setGeometry(int x, int y, int w, int h);
    
    void setTitle(const String& s);
    String title() const;
    
    HWND nativeHandle() const { return hwnd; }
    void update(); // InvalidateRect
    
    int width() const;
    int height() const;
    
    // Child management
    void addChild(Window* child);
    void removeChild(Window* child);
<<<<<<< HEAD
    
private:
    // Input state tracking
    bool m_mouseButtons[3] = {false, false, false};
    bool m_keyStates[256] = {false};
    int m_lastMouseX = 0;
    int m_lastMouseY = 0;
    int m_mouseModifiers = 0;
    int m_keyModifiers = 0;
    
    // Callbacks
    MouseCallback m_mousePressCallback;
    MouseCallback m_mouseReleaseCallback;
    std::function<void(int, int, int)> m_mouseMoveCallback;
    KeyCallback m_keyPressCallback;
    CharCallback m_charCallback;
=======
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
};

} // namespace RawrXD
