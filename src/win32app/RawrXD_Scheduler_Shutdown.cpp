// ============================================================================
// RawrXD_Scheduler_Shutdown.cpp - Task Scheduler Shutdown
// ============================================================================
// Provides graceful shutdown for the task scheduler subsystem.
//
// History:
//   2026-08-26  Created as part of Batch 1 unresolved external resolution.
// ============================================================================

#include <windows.h>
#include <atomic>
#include <vector>
#include <mutex>

static std::atomic_bool g_schedulerRunning{false};
static std::vector<HANDLE> g_schedulerThreads;
static std::mutex g_schedulerMutex;

extern "C" void Scheduler_Shutdown(void)
{
    if (!g_schedulerRunning.load(std::memory_order_acquire))
        return;
    
    OutputDebugStringA("[Scheduler] Shutting down task scheduler...\n");
    
    g_schedulerRunning.store(false, std::memory_order_release);
    
    // Wait for all scheduler threads to finish
    std::vector<HANDLE> threads;
    {
        std::lock_guard<std::mutex> lock(g_schedulerMutex);
        threads = g_schedulerThreads;
        g_schedulerThreads.clear();
    }
    
    if (!threads.empty())
    {
        WaitForMultipleObjects(static_cast<DWORD>(threads.size()), threads.data(), TRUE, 5000);
        for (HANDLE h : threads)
        {
            CloseHandle(h);
        }
    }
    
    OutputDebugStringA("[Scheduler] Task scheduler shutdown complete\n");
}

extern "C" void Scheduler_Initialize(void)
{
    if (g_schedulerRunning.load(std::memory_order_acquire))
        return;
    
    OutputDebugStringA("[Scheduler] Initializing task scheduler...\n");
    g_schedulerRunning.store(true, std::memory_order_release);
}

extern "C" bool Scheduler_IsRunning(void)
{
    return g_schedulerRunning.load(std::memory_order_acquire);
}

extern "C" void Scheduler_RegisterThread(HANDLE hThread)
{
    if (!hThread || hThread == INVALID_HANDLE_VALUE)
        return;
    
    std::lock_guard<std::mutex> lock(g_schedulerMutex);
    g_schedulerThreads.push_back(hThread);
}
