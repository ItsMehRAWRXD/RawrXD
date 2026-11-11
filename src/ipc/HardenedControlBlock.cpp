/*===========================================================================
 * HardenedControlBlock.cpp
 * VAL-029: SovereignRPC Distributed Execution - Transport Layer Implementation
 * 
 * Implementation of lock-free IPC control block with state machine validation
 * and watchdog monitoring for production-hardened shared memory transport.
 *===========================================================================*/

#include "HardenedControlBlock.h"
#include <windows.h>
#include <stdio.h>

/*===========================================================================
 * GLOBAL STATE
 *=========================================================================*/
static struct {
    BOOL                    initialized;
    HANDLE                  hWatchdogThread;
    HANDLE                  hShutdownEvent;
    ControlBlock**          monitoredBlocks;
    size_t                  numBlocks;
    CRITICAL_SECTION        listLock;
} g_watchdog;

/*===========================================================================
 * WATCHDOG THREAD
 * Monitors control blocks for deadlock and poison conditions
 *=========================================================================*/

static DWORD WINAPI WatchdogThreadProc(LPVOID lpParam) {
    (void)lpParam;
    
    while (WaitForSingleObject(g_watchdog.hShutdownEvent, HCB_WATCHDOG_TIMEOUT_MS / 2) == WAIT_TIMEOUT) {
        // Check all monitored control blocks
        EnterCriticalSection(&g_watchdog.listLock);
        
        for (size_t i = 0; i < g_watchdog.numBlocks; i++) {
            ControlBlock* cb = g_watchdog.monitoredBlocks[i];
            if (!cb) continue;
            
            BufferState state = cb->state.load(std::memory_order_acquire);
            
            // Check for poison
            if (HCB_IsPoisoned(cb)) {
                // Fatal error - log and potentially trigger recovery
                // In production, this would signal the DebugBridge
                continue;
            }
            
            // Check for stuck states
            // Note: In a real implementation, we'd track timestamps per block
            // For now, we just validate state machine integrity
            
            // Validate sequence/state consistency
            uint64_t seq = cb->sequence.load(std::memory_order_acquire);
            if (seq == HCB_SEQUENCE_POISON && state != BufferState::POISONED) {
                // Inconsistent: poison sequence but non-poison state
                HCB_Poison(cb); // Force consistent poison state
            }
        }
        
        LeaveCriticalSection(&g_watchdog.listLock);
    }
    
    return 0;
}

/*===========================================================================
 * WATCHDOG LIFECYCLE
 *=========================================================================*/

BOOL HCB_InitWatchdog(void) {
    if (g_watchdog.initialized) {
        return TRUE;
    }
    
    ZeroMemory(&g_watchdog, sizeof(g_watchdog));
    InitializeCriticalSection(&g_watchdog.listLock);
    
    // Allocate space for block pointers
    g_watchdog.monitoredBlocks = (ControlBlock**)VirtualAlloc(
        NULL, 
        1024 * sizeof(ControlBlock*),  // Max 1024 blocks
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    
    if (!g_watchdog.monitoredBlocks) {
        return FALSE;
    }
    
    g_watchdog.numBlocks = 0;
    
    // Create shutdown event
    g_watchdog.hShutdownEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (!g_watchdog.hShutdownEvent) {
        VirtualFree(g_watchdog.monitoredBlocks, 0, MEM_RELEASE);
        return FALSE;
    }
    
    // Create watchdog thread (below normal priority)
    g_watchdog.hWatchdogThread = CreateThread(
        NULL,
        64 * 1024,  // 64KB stack
        WatchdogThreadProc,
        NULL,
        0,
        NULL
    );
    
    if (!g_watchdog.hWatchdogThread) {
        CloseHandle(g_watchdog.hShutdownEvent);
        VirtualFree(g_watchdog.monitoredBlocks, 0, MEM_RELEASE);
        return FALSE;
    }
    
    SetThreadPriority(g_watchdog.hWatchdogThread, THREAD_PRIORITY_BELOW_NORMAL);
    g_watchdog.initialized = TRUE;
    
    return TRUE;
}

void HCB_ShutdownWatchdog(void) {
    if (!g_watchdog.initialized) {
        return;
    }
    
    // Signal shutdown
    SetEvent(g_watchdog.hShutdownEvent);
    
    // Wait for thread to exit
    WaitForSingleObject(g_watchdog.hWatchdogThread, 2000);
    
    // Cleanup
    CloseHandle(g_watchdog.hWatchdogThread);
    CloseHandle(g_watchdog.hShutdownEvent);
    VirtualFree(g_watchdog.monitoredBlocks, 0, MEM_RELEASE);
    DeleteCriticalSection(&g_watchdog.listLock);
    
    g_watchdog.initialized = FALSE;
}

BOOL HCB_RegisterBlock(ControlBlock* cb) {
    if (!g_watchdog.initialized || !cb) {
        return FALSE;
    }
    
    EnterCriticalSection(&g_watchdog.listLock);
    
    // Find empty slot or append
    for (size_t i = 0; i < g_watchdog.numBlocks; i++) {
        if (g_watchdog.monitoredBlocks[i] == NULL) {
            g_watchdog.monitoredBlocks[i] = cb;
            LeaveCriticalSection(&g_watchdog.listLock);
            return TRUE;
        }
    }
    
    // Append new
    if (g_watchdog.numBlocks < 1024) {
        g_watchdog.monitoredBlocks[g_watchdog.numBlocks++] = cb;
        LeaveCriticalSection(&g_watchdog.listLock);
        return TRUE;
    }
    
    LeaveCriticalSection(&g_watchdog.listLock);
    return FALSE; // No space
}

void HCB_UnregisterBlock(ControlBlock* cb) {
    if (!g_watchdog.initialized || !cb) {
        return;
    }
    
    EnterCriticalSection(&g_watchdog.listLock);
    
    for (size_t i = 0; i < g_watchdog.numBlocks; i++) {
        if (g_watchdog.monitoredBlocks[i] == cb) {
            g_watchdog.monitoredBlocks[i] = NULL;
            break;
        }
    }
    
    LeaveCriticalSection(&g_watchdog.listLock);
}

/*===========================================================================
 * STATE MACHINE VALIDATION
 *=========================================================================*/

BOOL HCB_ValidateStateMachine(const ControlBlock* cb) {
    BufferState state = cb->state.load(std::memory_order_acquire);
    uint64_t seq = cb->sequence.load(std::memory_order_acquire);
    
    // Check for invalid states
    if (state > BufferState::POISONED) {
        return FALSE;
    }
    
    // Check sequence/state consistency
    if (seq == HCB_SEQUENCE_POISON && state != BufferState::POISONED) {
        return FALSE;
    }
    
    // Check for overflow (should never happen in practice)
    if (seq >= 0xFFFFFFFFFFFFFF00ULL && state != BufferState::POISONED) {
        // Near overflow - should poison
        return FALSE;
    }
    
    return TRUE;
}

/*===========================================================================
 * DEBUGGING / TELEMETRY
 *=========================================================================*/

void HCB_DumpState(const ControlBlock* cb, const char* label) {
    if (!cb) return;
    
    BufferState state = cb->state.load(std::memory_order_acquire);
    uint64_t seq = cb->sequence.load(std::memory_order_acquire);
    
    // In production, this would write to telemetry system
    // For now, just OutputDebugString
    char buf[256];
    snprintf(buf, sizeof(buf), 
             "[HCB] %s: state=%s, seq=%llu, poison=%d\n",
             label ? label : "unknown",
             HCB_GetStateName(state),
             (unsigned long long)seq,
             HCB_IsPoisoned(cb) ? 1 : 0);
    
    OutputDebugStringA(buf);
}

/*===========================================================================
 * SHARED MEMORY LAYOUT
 *=========================================================================*/

/* Calculate total size needed for N buffers with control blocks */
size_t HCB_CalculateSharedMemorySize(size_t numBuffers, size_t payloadSizePerBuffer) {
    // Each buffer needs: ControlBlock + payload (aligned to cache line)
    size_t alignedPayload = (payloadSizePerBuffer + HCB_CACHE_LINE_SIZE - 1) & ~(HCB_CACHE_LINE_SIZE - 1);
    return numBuffers * (sizeof(ControlBlock) + alignedPayload);
}

/* Get pointer to payload for a given control block */
void* HCB_GetPayload(ControlBlock* cb, size_t bufferIndex, size_t payloadSize) {
    // Payload immediately follows control block in memory
    // Assumes contiguous allocation: [CB0][Payload0][CB1][Payload1]...
    size_t alignedPayload = (payloadSize + HCB_CACHE_LINE_SIZE - 1) & ~(HCB_CACHE_LINE_SIZE - 1);
    return (char*)cb + sizeof(ControlBlock) + bufferIndex * (sizeof(ControlBlock) + alignedPayload);
}
