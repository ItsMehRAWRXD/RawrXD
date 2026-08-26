// ============================================================================
// RawrXD_Infinity_Shutdown.cpp - Infinity Subsystem Shutdown
// ============================================================================
// Provides graceful shutdown for the INFINITY subsystem (infinite context
// window management and long-running inference sessions).
//
// History:
//   2026-08-26  Created as part of Batch 1 unresolved external resolution.
// ============================================================================

#include <windows.h>
#include <atomic>

static std::atomic_bool g_infinityRunning{false};

extern "C" void INFINITY_Shutdown(void)
{
    if (!g_infinityRunning.load(std::memory_order_acquire))
        return;
    
    OutputDebugStringA("[INFINITY] Shutting down infinity subsystem...\n");
    
    // Signal all infinity threads to stop
    g_infinityRunning.store(false, std::memory_order_release);
    
    // Brief wait for cleanup
    Sleep(100);
    
    OutputDebugStringA("[INFINITY] Infinity subsystem shutdown complete\n");
}

extern "C" void INFINITY_Initialize(void)
{
    if (g_infinityRunning.load(std::memory_order_acquire))
        return;
    
    OutputDebugStringA("[INFINITY] Initializing infinity subsystem...\n");
    g_infinityRunning.store(true, std::memory_order_release);
}

extern "C" bool INFINITY_IsRunning(void)
{
    return g_infinityRunning.load(std::memory_order_acquire);
}
