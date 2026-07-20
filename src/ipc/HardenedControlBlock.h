/*===========================================================================
 * HardenedControlBlock.h
 * VAL-029: SovereignRPC Distributed Execution - Transport Layer
 * 
 * Cache-line aligned, lock-free IPC control block for shared memory
 * Zero-dependency, bare-metal implementation using C++11 atomics
 *
 * Architecture:
 *   - 64-byte cache-line alignment prevents false sharing
 *   - Atomic sequence counter for versioned consistency
 *   - State machine for buffer lifecycle management
 *   - Memory ordering guarantees for acquire-release semantics
 *===========================================================================*/

#pragma once

#include <atomic>
#include <cstdint>
#include <type_traits>

#ifdef __cplusplus
extern "C" {
#endif

/*===========================================================================
 * CONSTANTS
 *=========================================================================*/
#define HCB_VERSION                     1
#define HCB_CACHE_LINE_SIZE             64
#define HCB_SEQUENCE_POISON             0xFFFFFFFFFFFFFFFFULL
#define HCB_STATE_POISON                0xFFFFFFFFU
#define HCB_WATCHDOG_TIMEOUT_MS         500

/*===========================================================================
 * BUFFER STATE MACHINE
 * 
 * State transitions (Server = Producer, Client = Consumer):
 *   Server: AVAILABLE -> READY (write data, publish)
 *   Client: READY -> CONSUMING (acquire, read data)
 *   Client: CONSUMING -> FLUSHING (done reading, signal flush)
 *   Server: FLUSHING -> AVAILABLE (I/O complete, recycle)
 *=========================================================================*/
enum class BufferState : uint32_t {
    AVAILABLE = 0,      // Buffer free for server to write
    READY       = 1,      // Data written, ready for client
    CONSUMING   = 2,      // Client currently reading
    FLUSHING    = 3,      // Async I/O in progress
    POISONED    = 0xFFFFFFFF // Fatal error sentinel
};

/*===========================================================================
 * CONTROL BLOCK
 * Cache-line aligned to prevent false sharing between producer/consumer
 *===========================================================================*/
struct alignas(HCB_CACHE_LINE_SIZE) ControlBlock {
    // Primary synchronization primitive
    // Incremented by server after each successful write
    std::atomic<uint64_t> sequence;
    
    // State machine for buffer lifecycle
    std::atomic<BufferState> state;
    
    // Reserved padding to fill 64-byte cache line
    // 8 bytes (sequence) + 4 bytes (state) = 12 bytes used
    // 64 - 12 = 52 bytes padding
    uint8_t _reserved[52];
};

// Compile-time verification of size and alignment
static_assert(sizeof(ControlBlock) == HCB_CACHE_LINE_SIZE, 
              "ControlBlock must be exactly 64 bytes");
static_assert(alignof(ControlBlock) == HCB_CACHE_LINE_SIZE,
              "ControlBlock must be 64-byte aligned");
static_assert(std::is_trivially_copyable<ControlBlock>::value,
              "ControlBlock must be trivially copyable for shared memory");

/*===========================================================================
 * LIFECYCLE FUNCTIONS
 *===========================================================================*/

/* Initialize a control block to AVAILABLE state with sequence 0 */
inline void HCB_Init(ControlBlock* cb) {
    cb->sequence.store(0, std::memory_order_relaxed);
    cb->state.store(BufferState::AVAILABLE, std::memory_order_relaxed);
}

/* Mark control block as poisoned (fatal error) */
inline void HCB_Poison(ControlBlock* cb) {
    cb->sequence.store(HCB_SEQUENCE_POISON, std::memory_order_release);
    cb->state.store(BufferState::POISONED, std::memory_order_release);
}

/* Check if control block is poisoned */
inline bool HCB_IsPoisoned(const ControlBlock* cb) {
    return cb->sequence.load(std::memory_order_acquire) == HCB_SEQUENCE_POISON ||
           cb->state.load(std::memory_order_acquire) == BufferState::POISONED;
}

/*===========================================================================
 * SERVER (PRODUCER) OPERATIONS
 *===========================================================================*/

/* Attempt to acquire buffer for writing
 * Returns: true if buffer was AVAILABLE and is now locked for server */
inline bool HCB_ServerTryAcquire(ControlBlock* cb) {
    BufferState expected = BufferState::AVAILABLE;
    return cb->state.compare_exchange_strong(
        expected, 
        BufferState::AVAILABLE,  // Spurious failure ok
        std::memory_order_relaxed,
        std::memory_order_relaxed
    );
}

/* Publish data to buffer (Server -> Client handoff)
 * Precondition: Server has written data to buffer
 * Postcondition: Buffer is READY, sequence incremented */
inline void HCB_ServerPublish(ControlBlock* cb) {
    // Release semantics: ensure all writes to buffer are visible
    // before the state change is visible
    cb->state.store(BufferState::READY, std::memory_order_release);
    cb->sequence.fetch_add(1, std::memory_order_acq_rel);
}

/* Mark buffer as available after flush completes
 * Returns: true if state transition succeeded */
inline bool HCB_ServerRecycle(ControlBlock* cb) {
    BufferState expected = BufferState::FLUSHING;
    return cb->state.compare_exchange_strong(
        expected,
        BufferState::AVAILABLE,
        std::memory_order_release,
        std::memory_order_relaxed
    );
}

/*===========================================================================
 * CLIENT (CONSUMER) OPERATIONS
 *===========================================================================*/

/* Attempt to read from buffer
 * Returns: true if buffer was READY and is now locked for reading */
inline bool HCB_ClientTryAcquire(ControlBlock* cb) {
    BufferState expected = BufferState::READY;
    return cb->state.compare_exchange_strong(
        expected,
        BufferState::CONSUMING,
        std::memory_order_acquire,  // Acquire: see all server writes
        std::memory_order_relaxed
    );
}

/* Release buffer after reading (signal flush needed)
 * Precondition: Client has finished reading
 * Postcondition: Buffer is FLUSHING, ready for async I/O */
inline void HCB_ClientRelease(ControlBlock* cb) {
    cb->state.store(BufferState::FLUSHING, std::memory_order_release);
}

/* Check if new data is available without acquiring
 * Returns: true if buffer is in READY state */
inline bool HCB_ClientPeek(const ControlBlock* cb) {
    return cb->state.load(std::memory_order_acquire) == BufferState::READY;
}

/*===========================================================================
 * SEQUENCE NUMBER OPERATIONS
 *===========================================================================*/

/* Get current sequence number */
inline uint64_t HCB_GetSequence(const ControlBlock* cb) {
    return cb->sequence.load(std::memory_order_acquire);
}

/* Check if sequence has advanced since last check
 * Returns: true if sequence > lastSequence */
inline bool HCB_HasNewData(const ControlBlock* cb, uint64_t lastSequence) {
    return HCB_GetSequence(cb) > lastSequence;
}

/* Wait for specific sequence number (spin with pause hint) */
inline void HCB_SpinWaitForSequence(const ControlBlock* cb, uint64_t targetSeq) {
    while (cb->sequence.load(std::memory_order_relaxed) < targetSeq) {
        #if defined(_MSC_VER)
            __nop();  // MSVC pause hint
        #elif defined(__x86_64__)
            __asm__ volatile("pause" ::: "memory");
        #endif
    }
    // Final acquire to ensure visibility
    std::atomic_thread_fence(std::memory_order_acquire);
}

/*===========================================================================
 * WATCHDOG / DEBUGGING
 *===========================================================================*/

/* Get human-readable state name */
inline const char* HCB_GetStateName(BufferState state) {
    switch (state) {
        case BufferState::AVAILABLE: return "AVAILABLE";
        case BufferState::READY:     return "READY";
        case BufferState::CONSUMING: return "CONSUMING";
        case BufferState::FLUSHING:  return "FLUSHING";
        case BufferState::POISONED:  return "POISONED";
        default:                     return "UNKNOWN";
    }
}

/* Validate state transition is legal
 * Returns: true if transition from -> to is valid */
inline bool HCB_IsValidTransition(BufferState from, BufferState to) {
    switch (from) {
        case BufferState::AVAILABLE:
            return to == BufferState::READY || to == BufferState::POISONED;
        case BufferState::READY:
            return to == BufferState::CONSUMING || to == BufferState::POISONED;
        case BufferState::CONSUMING:
            return to == BufferState::FLUSHING || to == BufferState::POISONED;
        case BufferState::FLUSHING:
            return to == BufferState::AVAILABLE || to == BufferState::POISONED;
        case BufferState::POISONED:
            return false; // Terminal state
        default:
            return false;
    }
}

#ifdef __cplusplus
}
#endif
