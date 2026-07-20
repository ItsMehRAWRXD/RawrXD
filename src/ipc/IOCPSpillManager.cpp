/*===========================================================================
 * IOCPSpillManager.cpp
 * VAL-028.2: IOCP Spill Manager - Implementation
 * 
 * Asynchronous I/O with lock-free spill queue and backpressure.
 *===========================================================================*/

#include "IOCPSpillManager.h"
#include <stdio.h>
#include <stdlib.h>

/*===========================================================================
 * LIFECYCLE
 *===========================================================================

BOOL IOCP_Initialize(
    IOCPSpillManager* mgr,
    const WCHAR* spillFilePath,
    uint32_t bufferCount,
    void (*backpressureCb)(bool enable)
) {
    if (!mgr || !spillFilePath || bufferCount == 0) {
        return FALSE;
    }
    
    ZeroMemory(mgr, sizeof(IOCPSpillManager));
    
    // Copy spill file path
    wcsncpy_s(mgr->spillFilePath, MAX_PATH, spillFilePath, MAX_PATH - 1);
    
    // Create spill file with NO_BUFFERING for predictable I/O
    mgr->hSpillFile = CreateFileW(
        spillFilePath,
        GENERIC_READ | GENERIC_WRITE,
        0,                          // No sharing
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_NO_BUFFERING | FILE_FLAG_OVERLAPPED,
        nullptr
    );
    
    if (mgr->hSpillFile == INVALID_HANDLE_VALUE) {
        return FALSE;
    }
    
    // Pre-allocate spill file (1 GB default)
    mgr->spillFileMaxSize = 1ULL * 1024 * 1024 * 1024;
    LARGE_INTEGER fileSize;
    fileSize.QuadPart = mgr->spillFileMaxSize;
    SetFilePointerEx(mgr->hSpillFile, fileSize, nullptr, FILE_BEGIN);
    SetEndOfFile(mgr->hSpillFile);
    SetFilePointerEx(mgr->hSpillFile, {0}, nullptr, FILE_BEGIN);
    
    // Create IOCP
    mgr->hIOCP = CreateIoCompletionPort(
        INVALID_HANDLE_VALUE,   // Not associated with file yet
        nullptr,                // Create new IOCP
        0,                      // Completion key
        1                       // Concurrent threads (1 for serialized)
    );
    
    if (!mgr->hIOCP) {
        CloseHandle(mgr->hSpillFile);
        return FALSE;
    }
    
    // Associate spill file with IOCP
    if (!CreateIoCompletionPort(mgr->hSpillFile, mgr->hIOCP, 0, 0)) {
        CloseHandle(mgr->hIOCP);
        CloseHandle(mgr->hSpillFile);
        return FALSE;
    }
    
    // Allocate buffer pool (sector-aligned)
    size_t poolSize = (size_t)bufferCount * IOCP_SECTOR_SIZE;
    mgr->bufferPool = (SpillBuffer*)VirtualAlloc(
        nullptr,
        poolSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    
    if (!mgr->bufferPool) {
        CloseHandle(mgr->hIOCP);
        CloseHandle(mgr->hSpillFile);
        return FALSE;
    }
    
    // Initialize buffer pool
    mgr->bufferCount = bufferCount;
    for (uint32_t i = 0; i < bufferCount; i++) {
        SpillBuffer* buf = &mgr->bufferPool[i];
        buf->state.store(SpillBufferState::AVAILABLE, std::memory_order_relaxed);
        buf->sequence = 0;
        buf->dataSize = 0;
        buf->bufferIndex = i;
        ZeroMemory(&buf->overlapped, sizeof(OVERLAPPED));
    }
    
    // Allocate spill queue
    mgr->spillQueue = (SpillQueue*)VirtualAlloc(
        nullptr,
        sizeof(SpillQueue),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    
    if (!mgr->spillQueue) {
        VirtualFree(mgr->bufferPool, 0, MEM_RELEASE);
        CloseHandle(mgr->hIOCP);
        CloseHandle(mgr->hSpillFile);
        return FALSE;
    }
    
    // Initialize spill queue (lock-free ring)
    mgr->spillQueue->head.store(0, std::memory_order_relaxed);
    mgr->spillQueue->tail.store(0, std::memory_order_relaxed);
    mgr->spillQueue->depth.store(0, std::memory_order_relaxed);
    mgr->spillQueue->maxDepth.store(0, std::memory_order_relaxed);
    
    // Set backpressure callback
    mgr->backpressureCallback = backpressureCb;
    
    // Create worker thread
    mgr->shutdownRequested.store(false, std::memory_order_relaxed);
    mgr->hWorkerThread = CreateThread(
        nullptr,
        64 * 1024,              // 64KB stack
        IOCP_WorkerThreadProc,
        mgr,
        0,
        nullptr
    );
    
    if (!mgr->hWorkerThread) {
        VirtualFree(mgr->spillQueue, 0, MEM_RELEASE);
        VirtualFree(mgr->bufferPool, 0, MEM_RELEASE);
        CloseHandle(mgr->hIOCP);
        CloseHandle(mgr->hSpillFile);
        return FALSE;
    }
    
    // Set below-normal priority (don't interfere with inference)
    SetThreadPriority(mgr->hWorkerThread, THREAD_PRIORITY_BELOW_NORMAL);
    
    return TRUE;
}

void IOCP_Shutdown(IOCPSpillManager* mgr) {
    if (!mgr || !mgr->hIOCP) {
        return;
    }
    
    // Signal shutdown
    mgr->shutdownRequested.store(true, std::memory_order_release);
    
    // Post completion to wake worker thread
    PostQueuedCompletionStatus(mgr->hIOCP, 0, 0, nullptr);
    
    // Wait for worker thread (up to timeout)
    WaitForSingleObject(mgr->hWorkerThread, IOCP_FLUSH_TIMEOUT_MS);
    CloseHandle(mgr->hWorkerThread);
    
    // Cleanup handles
    CloseHandle(mgr->hIOCP);
    CloseHandle(mgr->hSpillFile);
    
    // Free memory
    if (mgr->spillQueue) {
        VirtualFree(mgr->spillQueue, 0, MEM_RELEASE);
    }
    if (mgr->bufferPool) {
        VirtualFree(mgr->bufferPool, 0, MEM_RELEASE);
    }
    
    ZeroMemory(mgr, sizeof(IOCPSpillManager));
}

BOOL IOCP_IsActive(const IOCPSpillManager* mgr) {
    return mgr && mgr->hIOCP && !mgr->shutdownRequested.load(std::memory_order_acquire);
}

/*===========================================================================
 * SPILL OPERATIONS
 *===========================================================================

BOOL IOCP_SpillBuffer(
    IOCPSpillManager* mgr,
    const void* data,
    uint32_t size,
    uint64_t sequence
) {
    if (!mgr || !data || size == 0 || size > IOCP_SECTOR_SIZE) {
        return FALSE;
    }
    
    // Find available buffer
    SpillBuffer* buf = nullptr;
    for (uint32_t i = 0; i < mgr->bufferCount; i++) {
        SpillBufferState expected = SpillBufferState::AVAILABLE;
        if (mgr->bufferPool[i].state.compare_exchange_strong(
            expected,
            SpillBufferState::QUEUED,
            std::memory_order_acquire,
            std::memory_order_relaxed
        )) {
            buf = &mgr->bufferPool[i];
            break;
        }
    }
    
    if (!buf) {
        // No buffers available - trigger backpressure
        IOCP_SignalBackpressure(mgr, true);
        return FALSE;
    }
    
    // Copy data to buffer (sector-aligned)
    uint8_t* bufferData = (uint8_t*)buf + sizeof(SpillBuffer);
    memcpy(bufferData, data, size);
    
    // Set up buffer metadata
    buf->sequence = sequence;
    buf->dataSize = size;
    buf->state.store(SpillBufferState::IN_FLIGHT, std::memory_order_release);
    
    // Set up OVERLAPPED
    ZeroMemory(&buf->overlapped, sizeof(OVERLAPPED));
    buf->overlapped.Offset = (DWORD)(mgr->spillFileCurrentOffset & 0xFFFFFFFF);
    buf->overlapped.OffsetHigh = (DWORD)(mgr->spillFileCurrentOffset >> 32);
    
    // Update file offset
    mgr->spillFileCurrentOffset += IOCP_SECTOR_SIZE;
    if (mgr->spillFileCurrentOffset >= mgr->spillFileMaxSize) {
        mgr->spillFileCurrentOffset = 0; // Wrap around (circular file)
    }
    
    // Issue async write
    uint8_t* writePtr = (uint8_t*)buf; // Write entire sector
    BOOL result = WriteFile(
        mgr->hSpillFile,
        writePtr,
        IOCP_SECTOR_SIZE,
        nullptr,
        &buf->overlapped
    );
    
    if (!result && GetLastError() != ERROR_IO_PENDING) {
        // Immediate error
        buf->state.store(SpillBufferState::ERROR, std::memory_order_release);
        InterlockedIncrement64((LONG64*)&mgr->stats.totalErrors);
        return FALSE;
    }
    
    // Update stats
    InterlockedIncrement64((LONG64*)&mgr->stats.totalSpilled);
    InterlockedIncrement((LONG*)&mgr->stats.pendingIOCount);
    
    // Check backpressure
    float pressure = IOCP_GetQueuePressure(mgr);
    if (pressure > IOCP_BACKPRESSURE_THRESHOLD) {
        IOCP_SignalBackpressure(mgr, true);
    }
    
    return TRUE;
}

BOOL IOCP_ShouldSpill(const IOCPSpillManager* mgr) {
    if (!mgr) return FALSE;
    return IOCP_GetQueuePressure(mgr) > IOCP_BACKPRESSURE_THRESHOLD;
}

float IOCP_GetQueuePressure(const IOCPSpillManager* mgr) {
    if (!mgr || !mgr->spillQueue) return 0.0f;
    
    uint32_t depth = mgr->spillQueue->depth.load(std::memory_order_acquire);
    return (float)depth / (float)IOCP_QUEUE_SIZE;
}

/*===========================================================================
 * WORKER THREAD
 *===========================================================================

DWORD WINAPI IOCP_WorkerThreadProc(LPVOID lpParam) {
    IOCPSpillManager* mgr = (IOCPSpillManager*)lpParam;
    if (!mgr) return 1;
    
    while (!mgr->shutdownRequested.load(std::memory_order_acquire)) {
        DWORD bytesTransferred = 0;
        ULONG_PTR completionKey = 0;
        OVERLAPPED* overlapped = nullptr;
        
        // Wait for completion
        BOOL result = GetQueuedCompletionStatus(
            mgr->hIOCP,
            &bytesTransferred,
            &completionKey,
            &overlapped,
            IOCP_COMPLETION_TIMEOUT_MS
        );
        
        if (!result) {
            DWORD error = GetLastError();
            if (error == WAIT_TIMEOUT) {
                // Timeout - check for shutdown
                continue;
            }
            
            // Handle error
            if (overlapped) {
                SpillBuffer* buf = CONTAINING_RECORD(overlapped, SpillBuffer, overlapped);
                IOCP_HandleIOError(mgr, buf, error);
            }
            continue;
        }
        
        // Shutdown signal
        if (bytesTransferred == 0 && completionKey == 0 && overlapped == nullptr) {
            break;
        }
        
        // Process completion
        if (overlapped) {
            IOCP_ProcessCompletion(mgr, bytesTransferred, completionKey, overlapped);
        }
    }
    
    return 0;
}

void IOCP_ProcessCompletion(
    IOCPSpillManager* mgr,
    DWORD bytesTransferred,
    ULONG_PTR completionKey,
    OVERLAPPED* overlapped
) {
    (void)completionKey;
    
    if (!overlapped) return;
    
    // Get buffer from OVERLAPPED
    SpillBuffer* buf = CONTAINING_RECORD(overlapped, SpillBuffer, overlapped);
    
    // Update state
    buf->state.store(SpillBufferState::COMPLETED, std::memory_order_release);
    
    // Update stats
    InterlockedDecrement((LONG*)&mgr->stats.pendingIOCount);
    
    // Recycle buffer (make available again)
    buf->state.store(SpillBufferState::AVAILABLE, std::memory_order_release);
    
    // Check if we can release backpressure
    float pressure = IOCP_GetQueuePressure(mgr);
    if (pressure < IOCP_BACKPRESSURE_THRESHOLD * 0.5f) {
        IOCP_SignalBackpressure(mgr, false);
    }
}

void IOCP_HandleIOError(IOCPSpillManager* mgr, SpillBuffer* buffer, DWORD errorCode) {
    (void)errorCode;
    
    if (!buffer) return;
    
    buffer->state.store(SpillBufferState::ERROR, std::memory_order_release);
    InterlockedIncrement64((LONG64*)&mgr->stats.totalErrors);
    InterlockedDecrement((LONG*)&mgr->stats.pendingIOCount);
    
    // Make available again (data lost, but system continues)
    buffer->state.store(SpillBufferState::AVAILABLE, std::memory_order_release);
}

/*===========================================================================
 * BACKPRESSURE
 *===========================================================================

void IOCP_SignalBackpressure(IOCPSpillManager* mgr, bool enable) {
    if (!mgr || !mgr->backpressureCallback) return;
    
    static std::atomic<bool> currentState{false};
    bool expected = !enable;
    
    if (currentState.compare_exchange_strong(expected, enable)) {
        mgr->backpressureCallback(enable);
        
        if (enable) {
            InterlockedIncrement64((LONG64*)&mgr->stats.backpressureEvents);
        }
    }
}

void IOCP_SetBackpressure(IOCPSpillManager* mgr, bool enable) {
    IOCP_SignalBackpressure(mgr, enable);
}

BOOL IOCP_IsBackpressureActive(const IOCPSpillManager* mgr) {
    if (!mgr) return FALSE;
    return IOCP_GetQueuePressure(mgr) > IOCP_BACKPRESSURE_THRESHOLD;
}

/*===========================================================================
 * STATISTICS
 *===========================================================================

void IOCP_GetStats(const IOCPSpillManager* mgr, IOCPStats* outStats) {
    if (!mgr || !outStats) return;
    
    memcpy(outStats, &mgr->stats, sizeof(IOCPStats));
    
    // Update current values
    outStats->currentQueueDepth = mgr->spillQueue->depth.load(std::memory_order_acquire);
    outStats->pendingIOCount = 0; // Calculated from buffer states
    
    for (uint32_t i = 0; i < mgr->bufferCount; i++) {
        if (mgr->bufferPool[i].state.load(std::memory_order_acquire) == SpillBufferState::IN_FLIGHT) {
            outStats->pendingIOCount++;
        }
    }
}

void IOCP_ResetStats(IOCPSpillManager* mgr) {
    if (!mgr) return;
    ZeroMemory(&mgr->stats, sizeof(IOCPStats));
}

void IOCP_GetStatusString(const IOCPSpillManager* mgr, WCHAR* outBuffer, size_t bufferSize) {
    if (!mgr || !outBuffer || bufferSize == 0) return;
    
    IOCPStats stats;
    IOCP_GetStats(mgr, &stats);
    
    float pressure = IOCP_GetQueuePressure(mgr);
    
    swprintf_s(outBuffer, bufferSize,
        L"IOCP: %llu spilled, %llu errors, %.1f%% pressure, %u pending",
        stats.totalSpilled,
        stats.totalErrors,
        pressure * 100.0f,
        stats.pendingIOCount
    );
}
