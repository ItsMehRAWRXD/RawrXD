#pragma once

#include <windows.h>
#include <string>

namespace RawrXD {
namespace Ide {

class AgenticBrowserLayer {
public:
    AgenticBrowserLayer();
    ~AgenticBrowserLayer();
    AgenticBrowserLayer(const AgenticBrowserLayer&) = delete;
    AgenticBrowserLayer& operator=(const AgenticBrowserLayer&) = delete;

    void setBounds(const RECT& rc);
    HWND CreateHost(HWND hParent, HINSTANCE hInstance);
    bool Navigate(const std::wstring& url);
    bool Back();
    bool Forward();
    bool Reload();
    bool Stop();
    bool Focus();
    std::wstring CurrentUrl();
    void Shutdown();

private:
    struct Impl;
    Impl* impl_ = nullptr;
};

} // namespace Ide
} // namespace RawrXD