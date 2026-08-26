// ============================================================================
// AICompletion_Shutdown.cpp - Implementation of ShutdownAICompletion (VAL-063)
// ============================================================================
// Provides graceful shutdown of the AI completion subsystem.
//
// History:
//   2026-08-26  Created as part of Batch 1 unresolved external resolution.
// ============================================================================

#include <windows.h>
#include <atomic>

static std::atomic_bool g_aiCompletionRunning{false};
static std::atomic_bool g_aiCompletionShutdownRequested{false};

extern "C" void ShutdownAICompletion()
{
    // Signal shutdown to any active completion threads
    g_aiCompletionShutdownRequested.store(true, std::memory_order_release);
    
    // Brief wait for in-flight completions to notice the flag
    for (int i = 0; i < 50; ++i)
    {
        if (!g_aiCompletionRunning.load(std::memory_order_acquire))
            break;
        Sleep(10);
    }
    
    OutputDebugStringA("[AICompletion] Shutdown complete\n");
}

extern "C" void AICompletion_SetRunning(bool running)
{
    g_aiCompletionRunning.store(running, std::memory_order_release);
}

extern "C" bool AICompletion_IsShutdownRequested()
{
    return g_aiCompletionShutdownRequested.load(std::memory_order_acquire);
}
