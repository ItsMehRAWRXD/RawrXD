/*===========================================================================
 * WarmupEngine.cpp
 * Pre-faults memory-mapped model pages to keep weights "hot" in RAM
 * Prevents cold-start latency during inference
 *===========================================================================*/

#include "WarmupEngine.h"
#include <windows.h>
#include <process.h>
#include <stdlib.h>

/* Global state */
static WarmupEngine g_WarmupEngine;
static CRITICAL_SECTION g_WarmupLock;
static BOOL g_WarmupInitialized = FALSE;

/*===========================================================================
 * INITIALIZATION
 *===========================================================================*/

WarmupStatus WarmupEngine_Init(void) {
    if (g_WarmupInitialized) {
        return WARMUP_OK;
    }
    
    InitializeCriticalSection(&g_WarmupLock);
    
    g_WarmupEngine.state = WARMUP_STATE_IDLE;
    g_WarmupEngine.progress = 0.0f;
    g_WarmupEngine.threadCount = 0;
    g_WarmupEngine.cancelRequested = FALSE;
    
    g_WarmupInitialized = TRUE;
    
    return WARMUP_OK;
}

void WarmupEngine_Shutdown(void) {
    if (!g_WarmupInitialized) {
        return;
    }
    
    EnterCriticalSection(&g_WarmupLock);
    
    /* Cancel any active warmup */
    g_WarmupEngine.cancelRequested = TRUE;
    
    /* Wait for threads to complete */
    for (int i = 0; i < g_WarmupEngine.threadCount; i++) {
        if (g_WarmupEngine.threads[i]) {
            WaitForSingleObject(g_WarmupEngine.threads[i], 5000);
            CloseHandle(g_WarmupEngine.threads[i]);
            g_WarmupEngine.threads[i] = NULL;
        }
    }
    
    g_WarmupEngine.threadCount = 0;
    
    LeaveCriticalSection(&g_WarmupLock);
    DeleteCriticalSection(&g_WarmupLock);
    
    g_WarmupInitialized = FALSE;
}

/*===========================================================================
 * WARMUP THREAD
 *===========================================================================*/

typedef struct {
    uint8_t* base;
    size_t offset;
    size_t size;
    int threadId;
} WarmupThreadParams;

static unsigned __stdcall WarmupThreadProc(void* param) {
    WarmupThreadParams* params = (WarmupThreadParams*)param;
    if (!params) return 1;
    
    uint8_t* base = params->base;
    size_t start = params->offset;
    size_t end = params->offset + params->size;
    
    /* Touch every page to force page-in */
    const size_t PAGE_SIZE = 4096;
    volatile uint8_t dummy;
    
    for (size_t addr = start; addr < end; addr += PAGE_SIZE) {
        /* Check for cancellation */
        if (g_WarmupEngine.cancelRequested) {
            break;
        }
        
        /* Read one byte from each page to fault it in */
        dummy = base[addr];
        
        /* Update progress periodically */
        if ((addr - start) % (PAGE_SIZE * 256) == 0) {
            EnterCriticalSection(&g_WarmupLock);
            g_WarmupEngine.pagesTouched += 256;
            if (g_WarmupEngine.totalPages > 0) {
                g_WarmupEngine.progress = (float)g_WarmupEngine.pagesTouched / g_WarmupEngine.totalPages;
            }
            LeaveCriticalSection(&g_WarmupLock);
        }
    }
    
    free(params);
    return 0;
}

/*===========================================================================
 * PUBLIC API
 *===========================================================================*/

WarmupStatus WarmupEngine_Queue(void* modelBase, size_t modelSize, int numThreads) {
    if (!g_WarmupInitialized) {
        return WARMUP_ERROR_NOT_INITIALIZED;
    }
    
    if (!modelBase || modelSize == 0) {
        return WARMUP_ERROR_INVALID_PARAM;
    }
    
    EnterCriticalSection(&g_WarmupLock);
    
    /* Cancel any existing warmup */
    g_WarmupEngine.cancelRequested = TRUE;
    for (int i = 0; i < g_WarmupEngine.threadCount; i++) {
        if (g_WarmupEngine.threads[i]) {
            WaitForSingleObject(g_WarmupEngine.threads[i], 1000);
            CloseHandle(g_WarmupEngine.threads[i]);
        }
    }
    
    /* Reset state */
    g_WarmupEngine.cancelRequested = FALSE;
    g_WarmupEngine.threadCount = 0;
    g_WarmupEngine.pagesTouched = 0;
    g_WarmupEngine.totalPages = (modelSize + 4095) / 4096;
    g_WarmupEngine.progress = 0.0f;
    g_WarmupEngine.state = WARMUP_STATE_RUNNING;
    
    /* Clamp thread count */
    if (numThreads <= 0 || numThreads > WARMUP_MAX_THREADS) {
        numThreads = 4;
    }
    
    /* Calculate chunk size per thread */
    size_t chunkSize = modelSize / numThreads;
    
    /* Launch warmup threads */
    for (int i = 0; i < numThreads; i++) {
        WarmupThreadParams* params = (WarmupThreadParams*)malloc(sizeof(WarmupThreadParams));
        if (!params) continue;
        
        params->base = (uint8_t*)modelBase;
        params->offset = i * chunkSize;
        params->size = (i == numThreads - 1) ? (modelSize - params->offset) : chunkSize;
        params->threadId = i;
        
        uintptr_t threadHandle = _beginthreadex(NULL, 0, WarmupThreadProc, params, 0, NULL);
        if (threadHandle != 0) {
            g_WarmupEngine.threads[g_WarmupEngine.threadCount++] = (HANDLE)threadHandle;
        } else {
            free(params);
        }
    }
    
    LeaveCriticalSection(&g_WarmupLock);
    
    return WARMUP_OK;
}

WarmupStatus WarmupEngine_Wait(float timeoutSeconds) {
    if (!g_WarmupInitialized) {
        return WARMUP_ERROR_NOT_INITIALIZED;
    }
    
    DWORD timeoutMs = (timeoutSeconds > 0) ? (DWORD)(timeoutSeconds * 1000) : INFINITE;
    
    EnterCriticalSection(&g_WarmupLock);
    int threadCount = g_WarmupEngine.threadCount;
    LeaveCriticalSection(&g_WarmupLock);
    
    /* Wait for all threads */
    for (int i = 0; i < threadCount; i++) {
        HANDLE hThread;
        EnterCriticalSection(&g_WarmupLock);
        hThread = g_WarmupEngine.threads[i];
        LeaveCriticalSection(&g_WarmupLock);
        
        if (hThread) {
            DWORD result = WaitForSingleObject(hThread, timeoutMs);
            if (result == WAIT_TIMEOUT) {
                return WARMUP_ERROR_TIMEOUT;
            }
        }
    }
    
    EnterCriticalSection(&g_WarmupLock);
    g_WarmupEngine.state = WARMUP_STATE_COMPLETE;
    g_WarmupEngine.progress = 1.0f;
    LeaveCriticalSection(&g_WarmupLock);
    
    return WARMUP_OK;
}

void WarmupEngine_Cancel(void) {
    if (!g_WarmupInitialized) {
        return;
    }
    
    EnterCriticalSection(&g_WarmupLock);
    g_WarmupEngine.cancelRequested = TRUE;
    g_WarmupEngine.state = WARMUP_STATE_CANCELLED;
    LeaveCriticalSection(&g_WarmupLock);
}

float WarmupEngine_GetProgress(void) {
    if (!g_WarmupInitialized) {
        return 0.0f;
    }
    
    EnterCriticalSection(&g_WarmupLock);
    float progress = g_WarmupEngine.progress;
    LeaveCriticalSection(&g_WarmupLock);
    
    return progress;
}

WarmupState WarmupEngine_GetState(void) {
    if (!g_WarmupInitialized) {
        return WARMUP_STATE_IDLE;
    }
    
    EnterCriticalSection(&g_WarmupLock);
    WarmupState state = g_WarmupEngine.state;
    LeaveCriticalSection(&g_WarmupLock);
    
    return state;
}

const char* WarmupEngine_GetLastError(void) {
    return "WarmupEngine: No error";
}

/* E> End of WarmupEngine.cpp <3 */
