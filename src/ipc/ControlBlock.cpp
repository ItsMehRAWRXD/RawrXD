/*===========================================================================
 * ControlBlock.cpp
 * RawrXD IPC Transport Layer - Implementation
 * 
 * Lock-free state machine with strict memory ordering guarantees.
 *===========================================================================*/

#include "ControlBlock.h"
#include <windows.h>
#include <intrin.h>

/*===========================================================================
 * LIFECYCLE
 *=========================================================================*/

void CB_Initialize(ControlBlock* cb) {
    if (!cb) return;
    
    // Initialize sequence to 0 (even = stable)
    cb->sequence.store(0, std::memory_order_relaxed);
    
    // Start in AVAILABLE state
    cb->state.store(BufferState::AVAILABLE, std::memory_order_relaxed);
    
    // Clear metadata
    cb->payloadSize = 0;
    cb->tokenCount = 0;
    cb->timestampMicros = 0;
    
    // Set magic and version
    cb->magic = CONTROL_BLOCK_MAGIC;
    cb->version = CONTROL_BLOCK_VERSION;
    
    // Clear padding (for cleanliness)
    ZeroMemory(cb->_reserved, sizeof(cb->_reserved));
}

BOOL CB_Validate(const ControlBlock* cb) {
    if (!cb) return FALSE;
    
    // Check magic number
    if (cb->magic != CONTROL_BLOCK_MAGIC) {
        return FALSE;
    }
    
    // Check version
    if (cb->version != CONTROL_BLOCK_VERSION) {
        return FALSE;
    }
    
    // Check state is valid
    BufferState state = cb->state.load(std::memory_order_relaxed);
    if (state != BufferState::AVAILABLE &&
        state != BufferState::READY &&
        state != BufferState::CONSUMING &&
        state != BufferState::FLUSHING) {
        return FALSE;
    }
    
    return TRUE;
}

BOOL CB_IsPoisoned(const ControlBlock* cb) {
    if (!cb) return FALSE;
    return cb->state.load(std::memory_order_relaxed) == BufferState::POISONED;
}

void CB_SetPoisoned(ControlBlock* cb) {
    if (!cb) return;
    
    // Set poison state with release semantics
    cb->state.store(BufferState::POISONED, std::memory_order_release);
    
    // Increment sequence to signal change
    cb->sequence.fetch_add(1, std::memory_order_acq_rel);
}

/*===========================================================================
 * STATE MACHINE TRANSITIONS
 *=========================================================================*/

BOOL CB_Commit(ControlBlock* cb, uint32_t payloadSize, uint32_t tokenCount) {
    if (!cb) return FALSE;
    
    // Must be in AVAILABLE state
    BufferState expected = BufferState::AVAILABLE;
    if (!cb->state.compare_exchange_strong(expected, BufferState::READY,
                                              std::memory_order_release,
                                              std::memory_order_relaxed)) {
        return FALSE; // Not in AVAILABLE state
    }
    
    // Write metadata (now safe, state is READY but consumer hasn't acquired)
    cb->payloadSize = payloadSize;
    cb->tokenCount = tokenCount;
    cb->timestampMicros = GetTickCount64() * 1000; // Approximate microseconds
    
    // Increment sequence (odd -> even, signals stable)
    cb->sequence.fetch_add(1, std::memory_order_release);
    
    return TRUE;
}

BOOL CB_Acquire(ControlBlock* cb) {
    if (!cb) return FALSE;
    
    // Must be in READY state
    BufferState expected = BufferState::READY;
    if (!cb->state.compare_exchange_strong(expected, BufferState::CONSUMING,
                                              std::memory_order_acquire,
                                              std::memory_order_relaxed)) {
        return FALSE; // Not in READY state
    }
    
    // Memory barrier ensures we see all data written by producer
    std::atomic_thread_fence(std::memory_order_acquire);
    
    return TRUE;
}

BOOL CB_Release(ControlBlock* cb) {
    if (!cb) return FALSE;
    
    // Must be in CONSUMING state
    BufferState expected = BufferState::CONSUMING;
    if (!cb->state.compare_exchange_strong(expected, BufferState::FLUSHING,
                                              std::memory_order_release,
                                              std::memory_order_relaxed)) {
        return FALSE; // Not in CONSUMING state
    }
    
    // Increment sequence
    cb->sequence.fetch_add(1, std::memory_order_release);
    
    return TRUE;
}

BOOL CB_Recycle(ControlBlock* cb) {
    if (!cb) return FALSE;
    
    // Must be in FLUSHING state
    BufferState expected = BufferState::FLUSHING;
    if (!cb->state.compare_exchange_strong(expected, BufferState::AVAILABLE,
                                              std::memory_order_release,
                                              std::memory_order_relaxed)) {
        return FALSE; // Not in FLUSHING state
    }
    
    // Clear metadata
    cb->payloadSize = 0;
    cb->tokenCount = 0;
    cb->timestampMicros = 0;
    
    // Increment sequence
    cb->sequence.fetch_add(1, std::memory_order_release);
    
    return TRUE;
}

/*===========================================================================
 * SYNCHRONIZATION PRIMITIVES
 *=========================================================================*/

void CB_SpinWaitForState(const ControlBlock* cb, BufferState expected) {
    if (!cb) return;
    
    // Spin with PAUSE hint to reduce power consumption
    while (cb->state.load(std::memory_order_acquire) != expected) {
        _mm_pause(); // x86 PAUSE instruction
    }
}

BOOL CB_TryAcquireWithTimeout(ControlBlock* cb, uint32_t timeoutMs) {
    if (!cb) return FALSE;
    
    uint64_t startTime = GetTickCount64();
    
    while (TRUE) {
        BufferState current = cb->state.load(std::memory_order_acquire);
        
        if (current == BufferState::READY) {
            // Try to acquire
            if (CB_Acquire(cb)) {
                return TRUE;
            }
        }
        
        // Check for poison
        if (current == BufferState::POISONED) {
            return FALSE;
        }
        
        // Check timeout
        if ((GetTickCount64() - startTime) > timeoutMs) {
            return FALSE;
        }
        
        _mm_pause();
    }
}

uint64_t CB_GetSequence(const ControlBlock* cb) {
    if (!cb) return 0;
    return cb->sequence.load(std::memory_order_acquire);
}

BOOL CB_VerifySequence(const ControlBlock* cb, uint64_t expectedSeq) {
    if (!cb) return FALSE;
    
    uint64_t currentSeq = cb->sequence.load(std::memory_order_acquire);
    return currentSeq == expectedSeq;
}

/*===========================================================================
 * WATCHDOG & RESILIENCE
 *===========================================================================*/

BOOL CB_IsStalled(const ControlBlock* cb, uint32_t thresholdMs) {
    if (!cb) return FALSE;
    
    // Only check if in CONSUMING state
    if (cb->state.load(std::memory_order_relaxed) != BufferState::CONSUMING) {
        return FALSE;
    }
    
    // Check if timestamp is old
    uint64_t nowMicros = GetTickCount64() * 1000;
    uint64_t elapsedMs = (nowMicros - cb->timestampMicros) / 1000;
    
    return elapsedMs > thresholdMs;
}

const char* CB_GetStateName(BufferState state) {
    switch (state) {
        case BufferState::AVAILABLE: return "AVAILABLE";
        case BufferState::READY:     return "READY";
        case BufferState::CONSUMING: return "CONSUMING";
        case BufferState::FLUSHING:  return "FLUSHING";
        case BufferState::POISONED:  return "POISONED";
        default:                     return "UNKNOWN";
    }
}

void CB_GetPayloadInfo(const ControlBlock* cb, uint32_t* outSize, 
                       uint32_t* outTokens, uint64_t* outTimestamp) {
    if (!cb) return;
    
    if (outSize) *outSize = cb->payloadSize;
    if (outTokens) *outTokens = cb->tokenCount;
    if (outTimestamp) *outTimestamp = cb->timestampMicros;
}
