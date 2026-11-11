// Request A control-lifetime diagnostic breadcrumbs only.
// DIAGNOSTIC_INSTRUMENTATION ≠ ACCEPTANCE_PASS. No intentional behavior change.
#pragma once
#include <windows.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace rawrxd {
namespace request_a_diag {

inline const char* logPath()
{
    static char path[MAX_PATH] = {};
    if (path[0]) return path;
    if (const char* env = std::getenv("RAWRXD_REQUEST_A_DIAG_LOG")) {
        if (env[0]) {
            std::snprintf(path, sizeof(path), "%s", env);
            return path;
        }
    }
    char base[MAX_PATH] = {};
    const DWORD n = GetEnvironmentVariableA("LOCALAPPDATA", base, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) {
        std::snprintf(path, sizeof(path), "request_a_ctrl_diag.log");
        return path;
    }
    std::snprintf(path, sizeof(path),
                  "%s\\RawrXD\\logs\\request_a_ctrl_diag.log", base);
    return path;
}

inline void ensureLogDirs()
{
    char base[MAX_PATH] = {};
    if (GetEnvironmentVariableA("LOCALAPPDATA", base, MAX_PATH) == 0) return;
    char rawr[MAX_PATH] = {};
    char logs[MAX_PATH] = {};
    std::snprintf(rawr, sizeof(rawr), "%s\\RawrXD", base);
    std::snprintf(logs, sizeof(logs), "%s\\logs", rawr);
    CreateDirectoryA(rawr, nullptr);
    CreateDirectoryA(logs, nullptr);
}

inline void writeLine(const char* line)
{
    ensureLogDirs();
    const char* path = logPath();
    HANDLE h = CreateFileA(path, FILE_APPEND_DATA,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                           OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    DWORD wrote = 0;
    WriteFile(h, line, static_cast<DWORD>(std::strlen(line)), &wrote, nullptr);
    WriteFile(h, "\r\n", 2, &wrote, nullptr);
    FlushFileBuffers(h);
    CloseHandle(h);
}

inline void describeHwnd(HWND hwnd, char* out, size_t outN)
{
    if (!out || outN < 8) return;
    if (!hwnd) {
        std::snprintf(out, outN, "hwnd=0 alive=0 class=- id=- wndproc=0");
        return;
    }
    char cls[64] = {};
    GetClassNameA(hwnd, cls, static_cast<int>(sizeof(cls)));
    const LONG id = GetWindowLongA(hwnd, GWL_ID);
    const BOOL alive = IsWindow(hwnd);
    const LONG_PTR proc = GetWindowLongPtrA(hwnd, GWLP_WNDPROC);
    std::snprintf(out, outN,
                  "hwnd=%p alive=%d class=%s id=%ld wndproc=%p",
                  reinterpret_cast<void*>(hwnd), alive ? 1 : 0,
                  cls[0] ? cls : "-", static_cast<long>(id),
                  reinterpret_cast<void*>(proc));
}

inline void event(const char* tag, HWND hwnd = nullptr,
                  UINT msg = 0, WPARAM wp = 0, LPARAM lp = 0)
{
    char desc[192] = {};
    describeHwnd(hwnd, desc, sizeof(desc));
    char line[384] = {};
    SYSTEMTIME st{};
    GetLocalTime(&st);
    std::snprintf(
        line, sizeof(line),
        "%04u-%02u-%02uT%02u:%02u:%02u.%03u tid=%lu %s %s msg=0x%X wp=0x%llX lp=0x%llX",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
        st.wMilliseconds, GetCurrentThreadId(), tag, desc,
        static_cast<unsigned>(msg),
        static_cast<unsigned long long>(wp),
        static_cast<unsigned long long>(lp));
    writeLine(line);
}

inline void noteCreate(const char* role, HWND hwnd)
{
    char tag[96] = {};
    std::snprintf(tag, sizeof(tag), "CTRL_CREATE role=%s", role);
    event(tag, hwnd);
}

inline void noteDestroy(const char* role, HWND hwnd)
{
    char tag[96] = {};
    std::snprintf(tag, sizeof(tag), "CTRL_DESTROY role=%s", role);
    event(tag, hwnd);
}

inline void noteSubclass(const char* op, HWND hwnd, void* proc)
{
    char tag[128] = {};
    std::snprintf(tag, sizeof(tag), "SUBCLASS_%s proc=%p", op, proc);
    event(tag, hwnd);
}

inline void noteDispatch(const MSG& msg)
{
    const bool interesting =
        msg.message == WM_COMMAND ||
        msg.message == WM_NOTIFY ||
        msg.message == WM_TIMER ||
        msg.message == (WM_APP + 106) ||
        msg.message == (WM_APP + 107);
    if (!interesting) return;
    event("MSG_DISPATCH", msg.hwnd, msg.message, msg.wParam, msg.lParam);
}

}  // namespace request_a_diag
}  // namespace rawrxd
