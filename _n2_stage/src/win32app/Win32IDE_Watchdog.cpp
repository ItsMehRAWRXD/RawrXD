// Win32IDE_Watchdog.cpp — UI watchdog: detects freeze via heartbeat timer
#include <windows.h>
#include <atomic>
#include <thread>
#include <chrono>

namespace RawrXD::IDE {

static std::atomic<bool>     g_running{false};
static std::atomic<uint64_t> g_heartbeat{0};
static std::thread           g_watchThread;
static HWND                  g_mainWnd = nullptr;
static uint32_t              g_thresholdMs = 5000;

void Watchdog_Heartbeat() { ++g_heartbeat; }

void Watchdog_Start(HWND mainWnd, uint32_t thresholdMs)
{
    g_mainWnd      = mainWnd;
    g_thresholdMs  = thresholdMs;
    g_running      = true;
    g_watchThread  = std::thread([]() {
        uint64_t last = g_heartbeat.load();
        while (g_running) {
            std::this_thread::sleep_for(std::chrono::milliseconds(g_thresholdMs));
            if (!g_running) break;
            uint64_t cur = g_heartbeat.load();
            if (cur == last) {
                OutputDebugStringA("[RawrXD][WATCHDOG] UI thread may be frozen\n");
            }
            last = cur;
        }
    });
}

void Watchdog_Stop()
{
    g_running = false;
    if (g_watchThread.joinable()) g_watchThread.join();
}

} // namespace RawrXD::IDE
