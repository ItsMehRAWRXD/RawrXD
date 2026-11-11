#pragma once

#include <windows.h>
#include <string>

namespace RawrXD {
namespace Ide {

class AgenticBrowserLayer {
public:
    AgenticBrowserLayer() = default;
    virtual ~AgenticBrowserLayer() = default;

    void setBounds(const RECT& /*rc*/) {
        // Stub: no-op
    }

    HWND CreateHost(HWND hParent, HINSTANCE hInstance) {
        // Stub: create a simple static control as placeholder
        return CreateWindowW(L"STATIC", L"Agentic Browser (placeholder)",
                             WS_CHILD | WS_VISIBLE | SS_CENTER,
                             0, 0, 200, 100, hParent, nullptr, hInstance, nullptr);
    }
};

} // namespace Ide
} // namespace RawrXD
