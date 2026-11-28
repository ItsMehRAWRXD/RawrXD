#pragma once

#include <windows.h>
#include <string>

namespace RawrXD {
namespace Ide {

// Native browser host child window.
// A full IWebBrowser2 COM host is blocked by the project's NOINTERFACE/
// include-order constraints (exdisp.h does not declare the interfaces in this
// TU configuration). This is a real child HWND with bounds/focus, not a no-op.
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

    bool Focus() { if (m_hwnd) SetFocus(m_hwnd); return m_hwnd != nullptr; }

private:
    HWND m_hwnd = nullptr;
};

} // namespace Ide
} // namespace RawrXD