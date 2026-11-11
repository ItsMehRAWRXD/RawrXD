/*===========================================================================
 * SovereignSharedMemoryServer.cpp
 * VAL-028.3: Integration Layer - Implementation
 * 
 * Unified fast/cold path with dynamic scheduling and backpressure.
 *===========================================================================*/

#include "SovereignSharedMemoryServer.h"
#include <stdio.h>
#include <string.h>

/*===========================================================================
 * LIFECYCLE
 *===========================================================================*/

BOOL SSM_Initialize(
    SovereignSharedMemoryServer* srv,
    uint32_t fastBufferCount,
    const WCHAR* spillFilePath,
    void (*backpressureCb)(bool enable, float pressure)
) {
    if (!srv || fastBufferCount == 0) {
        return FALSE;
    }
    
    ZeroMemory(srv, sizeof(SovereignSharedMemoryServer));
    
    // Magic and version
    srv->magic = SSM_MAGIC;
    srv->version = SSM_VERSION;
    
    // Configuration
    srv->spillThreshold = SSM_SPILL_THRESHOLD;
    srv->emergencyThreshold = SSM_EMERGENCY_THRESHOLD;
    srv->backpressureCallback = backpressureCb;
    
    // Allocate ControlBlock array (fast path)
    srv->controlBlockCount = fastBufferCount;
    srv->controlBlocks = (ControlBlock*)VirtualAlloc(
        nullptr,
        fastBufferCount * sizeof(ControlBlock),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    
    if (!srv->controlBlocks) {
        return FALSE;
    }
    
    // Initialize ControlBlocks
    for (uint32_t i = 0; i < fastBufferCount; i++) {
        CB_Initialize(&srv->controlBlocks[i]);
    }
    
    // Allocate fast payload buffer
    size_t payloadSize = (size_t)fastBufferCount * SSM_PAYLOAD_SIZE;
    srv->fastPayloadBuffer = (uint8_t*)VirtualAlloc(
        nullptr,
        payloadSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    
    if (!srv->fastPayloadBuffer) {
        VirtualFree(srv->controlBlocks, 0, MEM_RELEASE);
        return FALSE;
    }
    
    // Initialize IOCP Spill Manager (cold path)
    srv->spillManager = (IOCPSpillManager*)malloc(sizeof(IOCPSpillManager));
    if (!srv->spillManager) {
        VirtualFree(srv->fastPayloadBuffer, 0, MEM_RELEASE);
        VirtualFree(srv->controlBlocks, 0, MEM_RELEASE);
        return FALSE;
    }
    
    // Create backpressure wrapper for IOCP
    auto ioBackpressure = [srv](bool enable) {
        float pressure = IOCP_GetQueuePressure(srv->spillManager);
        SSM_SignalBackpressure(srv, enable, pressure);
    };
    
    if (!IOCP_Initialize(srv->spillManager, spillFilePath, 
                         SSM_COLD_BUFFER_COUNT, ioBackpressure)) {
        free(srv->spillManager);
        VirtualFree(srv->fastPayloadBuffer, 0, MEM_RELEASE);
        VirtualFree(srv->controlBlocks, 0, MEM_RELEASE);
        return FALSE;
    }
    
    srv->spillManagerActive = TRUE;
    
    // Allocate buffer descriptor pool
    srv->bufferPoolSize = fastBufferCount + SSM_COLD_BUFFER_COUNT;
    srv->bufferPool = (BufferDescriptor*)malloc(
        srv->bufferPoolSize * sizeof(BufferDescriptor)
    );
    
    if (!srv->bufferPool) {
        IOCP_Shutdown(srv->spillManager);
        free(srv->spillManager);
        VirtualFree(srv->fastPayloadBuffer, 0, MEM_RELEASE);
        VirtualFree(srv->controlBlocks, 0, MEM_RELEASE);
        return FALSE;
    }
    
    ZeroMemory(srv->bufferPool, srv->bufferPoolSize * sizeof(BufferDescriptor));
    
    // Initialize sequence counter
    srv->globalSequence.store(1, std::memory_order_relaxed);
    
    // Set default decision function
    srv->decisionFunction = SSM_DefaultDecision;
    
    // Initialize backpressure state
    srv->backpressure.active.store(false, std::memory_order_relaxed);
    srv->backpressure.currentPressure = 0.0f;
    srv->backpressure.lastSignalTime = 0;
    srv->backpressure.consecutiveHits = 0;
    
    // Create monitor thread
    srv->shutdownRequested.store(false, std::memory_order_relaxed);
    srv->hMonitorThread = CreateThread(
        nullptr,
        64 * 1024,
        SSM_MonitorThreadProc,
        srv,
        0,
        nullptr
    );
    
    if (!srv->hMonitorThread) {
        free(srv->bufferPool);
        IOCP_Shutdown(srv->spillManager);
        free(srv->spillManager);
        VirtualFree(srv->fastPayloadBuffer, 0, MEM_RELEASE);
        VirtualFree(srv->controlBlocks, 0, MEM_RELEASE);
        return FALSE;
    }
    
    SetThreadPriority(srv->hMonitorThread, THREAD_PRIORITY_BELOW_NORMAL);
    
    return TRUE;
}

void SSM_Shutdown(SovereignSharedMemoryServer* srv) {
    if (!srv) return;
    
    // Signal shutdown
    srv->shutdownRequested.store(true, std::memory_order_release);
    
    // Wait for monitor thread
    if (srv->hMonitorThread) {
        WaitForSingleObject(srv->hMonitorThread, 5000);
        CloseHandle(srv->hMonitorThread);
    }
    
    // Shutdown IOCP
    if (srv->spillManagerActive && srv->spillManager) {
        IOCP_Shutdown(srv->spillManager);
        free(srv->spillManager);
    }
    
    // Free memory
    if (srv->bufferPool) {
        free(srv->bufferPool);
    }
    if (srv->fastPayloadBuffer) {
        VirtualFree(srv->fastPayloadBuffer, 0, MEM_RELEASE);
    }
    if (srv->controlBlocks) {
        VirtualFree(srv->controlBlocks, 0, MEM_RELEASE);
    }
    
    ZeroMemory(srv, sizeof(SovereignSharedMemoryServer));
}

BOOL SSM_IsActive(const SovereignSharedMemoryServer* srv) {
    return srv && 
           srv->magic == SSM_MAGIC && 
           !srv->shutdownRequested.load(std::memory_order_acquire);
}

/*===========================================================================
 * WRITE OPERATIONS
 *===========================================================================*/

BOOL SSM_Write(
    SovereignSharedMemoryServer* srv,
    const void* data,
    uint32_t size,
    BufferDescriptor* outDescriptor
) {
    if (!SSM_IsActive(srv) || !data || size == 0) {
        return FALSE;
    }
    
    // Get write decision
    WriteDecision decision = SSM_GetWriteDecision(srv, size);
    
    // Execute based on decision
    switch (decision) {
        case WriteDecision::WRITE_FAST:
            return SSM_WriteFast(srv, data, size, outDescriptor);
            
        case WriteDecision::WRITE_COLD:
            return SSM_WriteCold(srv, data, size, outDescriptor);
            
        case WriteDecision::WRITE_EMERGENCY:
            // In emergency, try fast first, then cold, then drop
            if (SSM_WriteFast(srv, data, size, outDescriptor)) {
                return TRUE;
            }
            if (SSM_WriteCold(srv, data, size, outDescriptor)) {
                return TRUE;
            }
            // Drop data (emergency)
            InterlockedIncrement64((LONG64*)&srv->stats.emergencyDrops);
            return FALSE;
    }
    
    return FALSE;
}

BOOL SSM_WriteFast(
    SovereignSharedMemoryServer* srv,
    const void* data,
    uint32_t size,
    BufferDescriptor* outDescriptor
) {
    if (!SSM_IsActive(srv) || !data || size > SSM_PAYLOAD_SIZE) {
        return FALSE;
    }
    
    // Find available ControlBlock
    ControlBlock* cb = SSM_FindAvailableControlBlock(srv);
    if (!cb) {
        return FALSE; // No fast buffers available
    }
    
    // Get buffer index
    uint32_t index = (uint32_t)(cb - srv->controlBlocks);
    
    // Copy data to payload buffer
    uint8_t* payload = srv->fastPayloadBuffer + (index * SSM_PAYLOAD_SIZE);
    memcpy(payload, data, size);
    
    // Commit ControlBlock
    if (!CB_Commit(cb, size, 0)) {
        return FALSE;
    }
    
    // Fill descriptor
    if (outDescriptor) {
        outDescriptor->location = BufferLocation::FAST;
        outDescriptor->index = index;
        outDescriptor->sequence = srv->globalSequence.fetch_add(1, std::memory_order_acq_rel);
        outDescriptor->dataSize = size;
        outDescriptor->timestamp = GetTickCount64();
    }
    
    // Update stats
    InterlockedIncrement64((LONG64*)&srv->stats.fastWrites);
    
    return TRUE;
}

BOOL SSM_WriteCold(
    SovereignSharedMemoryServer* srv,
    const void* data,
    uint32_t size,
    BufferDescriptor* outDescriptor
) {
    if (!SSM_IsActive(srv) || !data || size > IOCP_SECTOR_SIZE) {
        return FALSE;
    }
    
    // Get sequence number first
    uint64_t sequence = srv->globalSequence.fetch_add(1, std::memory_order_acq_rel);
    
    // Spill to IOCP
    if (!IOCP_SpillBuffer(srv->spillManager, data, size, sequence)) {
        return FALSE;
    }
    
    // Fill descriptor
    if (outDescriptor) {
        outDescriptor->location = BufferLocation::COLD;
        outDescriptor->index = 0; // Managed by IOCP
        outDescriptor->sequence = sequence;
        outDescriptor->dataSize = size;
        outDescriptor->timestamp = GetTickCount64();
    }
    
    // Update stats
    InterlockedIncrement64((LONG64*)&srv->stats.coldWrites);
    
    return TRUE;
}

WriteDecision SSM_GetWriteDecision(
    const SovereignSharedMemoryServer* srv,
    uint32_t dataSize
) {
    if (!srv || !srv->decisionFunction) {
        return WriteDecision::WRITE_EMERGENCY;
    }
    
    return srv->decisionFunction(const_cast<SovereignSharedMemoryServer*>(srv), dataSize);
}

/*===========================================================================
 * READ OPERATIONS
 *===========================================================================*/

uint32_t SSM_Read(
    SovereignSharedMemoryServer* srv,
    BufferDescriptor* outDescriptor,
    void* outData,
    uint32_t maxSize
) {
    if (!SSM_IsActive(srv) || !outData || maxSize == 0) {
        return 0;
    }
    
    // Try fast path first (ControlBlock)
    for (uint32_t i = 0; i < srv->controlBlockCount; i++) {
        ControlBlock* cb = &srv->controlBlocks[i];
        
        if (CB_Acquire(cb)) {
            // Got a fast buffer
            uint32_t size = min(maxSize, SSM_PAYLOAD_SIZE);
            uint8_t* payload = srv->fastPayloadBuffer + (i * SSM_PAYLOAD_SIZE);
            memcpy(outData, payload, size);
            
            if (outDescriptor) {
                outDescriptor->location = BufferLocation::FAST;
                outDescriptor->index = i;
                CB_GetPayloadInfo(cb, &outDescriptor->dataSize, nullptr, &outDescriptor->timestamp);
            }
            
            InterlockedIncrement64((LONG64*)&srv->stats.fastReads);
            return size;
        }
    }
    
    // Try cold path (IOCP recovery)
    // TODO: Implement cold read from spill file
    // For now, return 0 (no data available)
    
    return 0;
}

void SSM_Release(
    SovereignSharedMemoryServer* srv,
    const BufferDescriptor* descriptor
) {
    if (!SSM_IsActive(srv) || !descriptor) {
        return;
    }
    
    switch (descriptor->location) {
        case BufferLocation::FAST:
            if (descriptor->index < srv->controlBlockCount) {
                ControlBlock* cb = &srv->controlBlocks[descriptor->index];
                CB_Release(cb);
                CB_Recycle(cb);
            }
            break;
            
        case BufferLocation::COLD:
            // IOCP buffers auto-recycle on completion
            break;
    }
}

uint64_t SSM_PeekNextSequence(const SovereignSharedMemoryServer* srv) {
    if (!srv) return 0;
    return srv->globalSequence.load(std::memory_order_acquire);
}

/*===========================================================================
 * DECISION LOGIC
 *===========================================================================*/

WriteDecision SSM_DefaultDecision(
    SovereignSharedMemoryServer* srv,
    uint32_t dataSize
) {
    (void)dataSize;
    
    if (!srv) {
        return WriteDecision::WRITE_EMERGENCY;
    }
    
    float pressure = SSM_GetPressure(srv);
    
    // Emergency: 98%+ full
    if (pressure >= srv->emergencyThreshold) {
        return WriteDecision::WRITE_EMERGENCY;
    }
    
    // Spill threshold: 90%+ full
    if (pressure >= srv->spillThreshold) {
        return WriteDecision::WRITE_COLD;
    }
    
    // Try fast path first
    ControlBlock* cb = SSM_FindAvailableControlBlock(srv);
    if (cb) {
        return WriteDecision::WRITE_FAST;
    }
    
    // No fast buffers, use cold
    return WriteDecision::WRITE_COLD;
}

float SSM_GetPressure(const SovereignSharedMemoryServer* srv) {
    if (!srv) return 1.0f;
    
    // Calculate pressure from fast buffer usage
    uint32_t inUse = 0;
    for (uint32_t i = 0; i < srv->controlBlockCount; i++) {
        BufferState state = srv->controlBlocks[i].state.load(std::memory_order_acquire);
        if (state != BufferState::AVAILABLE) {
            inUse++;
        }
    }
    
    float fastPressure = (float)inUse / (float)srv->controlBlockCount;
    
    // Blend with IOCP pressure
    float coldPressure = IOCP_GetQueuePressure(srv->spillManager);
    
    // Weighted: fast is more critical
    return (fastPressure * 0.7f) + (coldPressure * 0.3f);
}

/*===========================================================================
 * BACKPRESSURE
 *===========================================================================*/

BOOL SSM_IsBackpressureActive(const SovereignSharedMemoryServer* srv) {
    if (!srv) return FALSE;
    return srv->backpressure.active.load(std::memory_order_acquire);
}

void SSM_SignalBackpressure(
    SovereignSharedMemoryServer* srv,
    bool enable,
    float pressure
) {
    if (!srv) return;
    
    bool current = srv->backpressure.active.load(std::memory_order_relaxed);
    if (current != enable) {
        srv->backpressure.active.store(enable, std::memory_order_release);
        srv->backpressure.currentPressure = pressure;
        srv->backpressure.lastSignalTime = GetTickCount64();
        
        if (enable) {
            srv->backpressure.consecutiveHits++;
            InterlockedIncrement64((LONG64*)&srv->stats.backpressureSignals);
        } else {
            srv->backpressure.consecutiveHits = 0;
        }
        
        // Call user callback
        if (srv->backpressureCallback) {
            srv->backpressureCallback(enable, pressure);
        }
    }
}

/*===========================================================================
 * INTERNAL API
 *===========================================================================*/

DWORD WINAPI SSM_MonitorThreadProc(LPVOID lpParam) {
    SovereignSharedMemoryServer* srv = (SovereignSharedMemoryServer*)lpParam;
    if (!srv) return 1;
    
    while (!srv->shutdownRequested.load(std::memory_order_acquire)) {
        // Check pressure and signal backpressure if needed
        float pressure = SSM_GetPressure(srv);
        
        if (pressure > srv->spillThreshold) {
            SSM_SignalBackpressure(srv, true, pressure);
        } else if (pressure < srv->spillThreshold * 0.5f) {
            SSM_SignalBackpressure(srv, false, pressure);
        }
        
        // Sleep to avoid busy-waiting
        Sleep(100);
    }
    
    return 0;
}

ControlBlock* SSM_FindAvailableControlBlock(SovereignSharedMemoryServer* srv) {
    if (!srv) return nullptr;
    
    for (uint32_t i = 0; i < srv->controlBlockCount; i++) {
        ControlBlock* cb = &srv->controlBlocks[i];
        BufferState state = cb->state.load(std::memory_order_acquire);
        if (state == BufferState::AVAILABLE) {
            return cb;
        }
    }
    
    return nullptr;
}

void SSM_SetDecisionFunction(
    SovereignSharedMemoryServer* srv,
    WriteDecision (*func)(SovereignSharedMemoryServer*, uint32_t)
) {
    if (srv) {
        srv->decisionFunction = func;
    }
}
