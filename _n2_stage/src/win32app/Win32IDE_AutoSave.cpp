// Win32IDE_AutoSave.cpp — auto-save: timer fires every N seconds, saves dirty files
#include <windows.h>
#include <string>
#include <functional>

namespace RawrXD::IDE {

static UINT_PTR g_timerId   = 0;
static HWND     g_timerWnd  = nullptr;
static uint32_t g_intervalMs = 30000;
static std::function<void()> g_saveCallback;

bool EditorEngine_IsModified();
bool EditorEngine_SaveFile(const std::string&);
const std::string& EditorEngine_FilePath();

static void CALLBACK AutoSaveTimerProc(HWND, UINT, UINT_PTR, DWORD)
{
    if (g_saveCallback) { g_saveCallback(); return; }
    if (EditorEngine_IsModified()) {
        const std::string& p = EditorEngine_FilePath();
        if (!p.empty()) EditorEngine_SaveFile(p);
    }
}

void AutoSave_Start(HWND hwnd, uint32_t intervalMs, std::function<void()> cb)
{
    g_timerWnd   = hwnd;
    g_intervalMs = intervalMs;
    g_saveCallback = std::move(cb);
    if (g_timerId) KillTimer(hwnd, g_timerId);
    g_timerId = SetTimer(hwnd, 0xA570, intervalMs, AutoSaveTimerProc);
}

void AutoSave_Stop()
{
    if (g_timerId && g_timerWnd) {
        KillTimer(g_timerWnd, g_timerId);
        g_timerId = 0;
    }
}

void AutoSave_SetInterval(uint32_t ms)
{
    g_intervalMs = ms;
    if (g_timerId && g_timerWnd) {
        KillTimer(g_timerWnd, g_timerId);
        g_timerId = SetTimer(g_timerWnd, 0xA570, ms, AutoSaveTimerProc);
    }
}

} // namespace RawrXD::IDE
