#include "Input.hpp"
#include <windows.h>

namespace Sunshine {

void Input::update() {
    for (int i = 0; i < 256; ++i) {
        m_keysPrev[i] = m_keys[i];
        m_keys[i] = (GetAsyncKeyState(i) & 0x8000) ? 1 : 0;
    }
    m_mouseButtonsPrev = m_mouseButtons;
    m_mouseButtons = 0;
    if (GetAsyncKeyState(VK_LBUTTON) & 0x8000) m_mouseButtons |= 1;
    if (GetAsyncKeyState(VK_RBUTTON) & 0x8000) m_mouseButtons |= 2;
    if (GetAsyncKeyState(VK_MBUTTON) & 0x8000) m_mouseButtons |= 4;

    POINT pt;
    GetCursorPos(&pt);
    float prevX = m_mouseX;
    float prevY = m_mouseY;
    m_mouseX = (float)pt.x;
    m_mouseY = (float)pt.y;
    m_mouseDX = m_mouseX - prevX;
    m_mouseDY = m_mouseY - prevY;
}

bool Input::keyDown(int vk) const {
    return m_keys[vk & 0xFF] != 0;
}

bool Input::keyPressed(int vk) const {
    return m_keys[vk & 0xFF] && !m_keysPrev[vk & 0xFF];
}

bool Input::keyReleased(int vk) const {
    return !m_keys[vk & 0xFF] && m_keysPrev[vk & 0xFF];
}

bool Input::mouseButtonDown(int button) const {
    if (button < 0 || button > 2) return false;
    return (m_mouseButtons & (1 << button)) != 0;
}

void Input::setMousePosition(float x, float y) {
    SetCursorPos((int)x, (int)y);
    m_mouseX = x;
    m_mouseY = y;
    m_mouseDX = 0.0f;
    m_mouseDY = 0.0f;
}

void Input::setRawInput(HWND hwnd) {
    RAWINPUTDEVICE rid = {};
    rid.usUsagePage = 0x01;
    rid.usUsage = 0x02;
    rid.dwFlags = RIDEV_INPUTSINK;
    rid.hwndTarget = hwnd;
    RegisterRawInputDevices(&rid, 1, sizeof(rid));
}

} // namespace Sunshine
