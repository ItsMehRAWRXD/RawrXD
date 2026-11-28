#pragma once

#include <windows.h>
#include <string>

namespace RawrXD {
namespace Ide {

class AgenticBrowserLayer {
public:
    AgenticBrowserLayer() = default;
    virtual ~AgenticBrowserLayer() = default;

    void setBounds(const RECT& rc) {
        if (m_hwnd) MoveWindow(m_hwnd, rc.left, rc.top,
                               rc.right - rc.left, rc.bottom - rc.top, TRUE);
    }

    HWND CreateHost(HWND hParent, HINSTANCE hInstance) {
        if (m_hwnd) return m_hwnd;
        m_hwnd = CreateWindowW(L"STATIC", L"Agentic Browser",
                               WS_CHILD | WS_VISIBLE | SS_CENTER,
                               0, 0, 200, 100, hParent, nullptr, hInstance, nullptr);
        return m_hwnd;
    }

private:
    HWND m_hwnd = nullptr;
};

} // namespace Ide
} // namespace RawrXD