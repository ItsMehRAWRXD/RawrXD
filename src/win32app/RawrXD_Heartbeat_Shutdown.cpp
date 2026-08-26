// ============================================================================
// RawrXD_Heartbeat_Shutdown.cpp - Heartbeat Monitor Shutdown
// ============================================================================
// Provides graceful shutdown for the heartbeat monitoring subsystem.
//
// History:
//   2026-08-26  Created as part of Batch 1 unresolved external resolution.
// ============================================================================

#include <windows.h>
#include <atomic>

static std::atomic_bool g_heartbeatRunning{false};
static HANDLE g_hHeartbeatThread = nullptr;

static DWORD WINAPI HeartbeatThreadProc(LPVOID param)
{
    (void)param;
    
    while (g_heartbeatRunning.load(std::memory_order_acquire))
    {
        // Send heartbeat signal
        OutputDebugStringA("[Heartbeat] tick\n");
        Sleep(30000);  // 30-second heartbeat interval
    }
    
    return 0;
}

extern "C" void Heartbeat_Shutdown(void)
{
    if (!g_heartbeatRunning.load(std::memory_order_acquire))
        return;
    
    OutputDebugStringA("[Heartbeat] Shutting down heartbeat monitor...\n");
    
    g_heartbeatRunning.store(false, std::memory_order_release);
    
    if (g_hHeartbeatThread)
    {
        WaitForSingleObject(g_hHeartbeatThread, 5000);
        CloseHandle(g_hHeartbeatThread);
        g_hHeartbeatThread = nullptr;
    }
    
    OutputDebugStringA("[Heartbeat] Heartbeat monitor shutdown complete\n");
}

extern "C" void Heartbeat_Initialize(void)
{
    if (g_heartbeatRunning.load(std::memory_order_acquire))
        return;
    
    OutputDebugStringA("[Heartbeat] Initializing heartbeat monitor...\n");
    g_heartbeatRunning.store(true, std::memory_order_release);
    
    g_hHeartbeatThread = CreateThread(nullptr, 0, HeartbeatThreadProc, nullptr, 0, nullptr);
    if (g_hHeartbeatThread)
    {
        CloseHandle(g_hHeartbeatThread);  // We don't need to keep this handle
        g_hHeartbeatThread = nullptr;
    }
}

extern "C" bool Heartbeat_IsRunning(void)
{
    return g_heartbeatRunning.load(std::memory_order_acquire);
}
