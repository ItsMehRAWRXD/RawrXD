#pragma once

#include <stdint.h>
#include <windows.h>

namespace Sunshine {

class Input {
public:
    void update();
    bool keyDown(int vk) const;
    bool keyPressed(int vk) const;
    bool keyReleased(int vk) const;

    float mouseX() const { return m_mouseX; }
    float mouseY() const { return m_mouseY; }
    float mouseDeltaX() const { return m_mouseDX; }
    float mouseDeltaY() const { return m_mouseDY; }
    bool mouseButtonDown(int button) const; // 0=left,1=right,2=middle

    void setMousePosition(float x, float y);
    void setRawInput(HWND hwnd);

private:
    uint8_t m_keys[256] = {};
    uint8_t m_keysPrev[256] = {};
    float m_mouseX = 0.0f;
    float m_mouseY = 0.0f;
    float m_mouseDX = 0.0f;
    float m_mouseDY = 0.0f;
    uint8_t m_mouseButtons = 0;
    uint8_t m_mouseButtonsPrev = 0;
};

} // namespace Sunshine
