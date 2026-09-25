// Win32IDE_logMessage.cpp — global logMessage sink
#include <windows.h>
#include <string>
#include <cstdio>
#include <functional>

namespace RawrXD::IDE {

static std::function<void(const std::string&)> g_logSink;
static HWND g_logHwnd = nullptr;

void logMessage_SetSink(std::function<void(const std::string&)> sink) { g_logSink = std::move(sink); }
void logMessage_SetHwnd(HWND hwnd) { g_logHwnd = hwnd; }

} // namespace RawrXD::IDE

// Global C-linkage logMessage used across the codebase
extern "C" void logMessage(const char* msg)
{
    if (!msg) return;
    OutputDebugStringA(msg);
    OutputDebugStringA("\n");
    if (RawrXD::IDE::g_logSink) RawrXD::IDE::g_logSink(msg);
    if (RawrXD::IDE::g_logHwnd) {
        // Append to log EDIT control if present
        int len = GetWindowTextLengthA(RawrXD::IDE::g_logHwnd);
        SendMessageA(RawrXD::IDE::g_logHwnd, EM_SETSEL, len, len);
        SendMessageA(RawrXD::IDE::g_logHwnd, EM_REPLACESEL, FALSE, (LPARAM)msg);
        SendMessageA(RawrXD::IDE::g_logHwnd, EM_REPLACESEL, FALSE, (LPARAM)"\r\n");
    }
}

void logMessageW(const wchar_t* msg)
{
    if (!msg) return;
    int n = WideCharToMultiByte(CP_UTF8, 0, msg, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 0) return;
    std::string s(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, msg, -1, s.data(), n, nullptr, nullptr);
    logMessage(s.c_str());
}
