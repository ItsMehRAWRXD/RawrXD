/*===========================================================================
 * ControlBlock.h
 * RawrXD IPC Transport Layer - Hardened Control Block
 * 
 * Cache-line aligned atomic state machine for lock-free IPC.
 * Ensures "Ghost Text Never Blocks" invariant through strict memory ordering.
 *
 * Architecture:
 *   - 64-byte cache-line alignment prevents false sharing
 *   - Atomic sequence counter for versioned transactions
 *   - State machine: AVAILABLE -> READY -> CONSUMING -> FLUSHING -> AVAILABLE
 *   - Memory ordering: acquire/release for synchronization
 *===========================================================================*/

#pragma once

#include <atomic>
#include <cstdint>
#include <cstddef>

#ifdef __cplusplus
extern "C" {
#endif

/*===========================================================================
 * CONSTANTS
 *=========================================================================*/
#define CONTROL_BLOCK_VERSION       1
#define CONTROL_BLOCK_MAGIC         0x524157524344424CULL  // "RAWRCDBL"

// Cache line size (x64 standard)
#define CACHE_LINE_SIZE             64

// Timeout constants (milliseconds)
#define WATCHDOG_TIMEOUT_MS         500
#define POISON_STATE_VALUE          0xFFFFFFFFU

/*===========================================================================
 * BUFFER STATE MACHINE
 * 
 * Transitions:
 *   Server: AVAILABLE -> READY (memory_order_release)
 *   Client: READY -> CONSUMING (memory_order_acquire)
 *   Client: CONSUMING -> FLUSHING (memory_order_release)
 *   Server: FLUSHING -> AVAILABLE (memory_order_release)
 *=========================================================================*/
enum class BufferState : uint32_t {
    AVAILABLE   = 0,    // Buffer free for server to write
    READY       = 1,    // Data ready for client to read
    CONSUMING   = 2,    // Client actively reading
    FLUSHING    = 3,    // Async flush to disk in progress
    POISONED    = 0xFFFFFFFF  // Fatal error sentinel
};

/*===========================================================================
 * CONTROL BLOCK STRUCTURE
 * 
 * Aligned to 64 bytes to prevent false sharing between producer/consumer.
 * All atomic operations use explicit memory ordering.
 *=========================================================================*/
struct alignas(CACHE_LINE_SIZE) ControlBlock {
    // Primary synchronization: versioned sequence counter
    // Incremented on every state change (odd = write in progress, even = stable)
    std::atomic<uint64_t> sequence;
    
    // State machine status
    std::atomic<BufferState> state;
    
    // Payload metadata (read-only after READY)
    uint32_t payloadSize;       // Size of data in bytes
    uint32_t tokenCount;        // Number of tokens in response
    uint64_t timestampMicros;   // Server timestamp
    
    // Validation
    uint64_t magic;             // CONTROL_BLOCK_MAGIC
    uint32_t version;           // CONTROL_BLOCK_VERSION
    
    // Reserved padding to fill cache line
    // Current used: 8 + 4 + 4 + 4 + 8 + 4 = 32 bytes
    // Padding: 64 - 32 = 32 bytes
    uint8_t _reserved[32];
};

// Static assertions for ABI compatibility
static_assert(sizeof(ControlBlock) == CACHE_LINE_SIZE, 
              "ControlBlock must be exactly 64 bytes");
static_assert(alignof(ControlBlock) == CACHE_LINE_SIZE,
              "ControlBlock must be 64-byte aligned");
static_assert(offsetof(ControlBlock, sequence) == 0,
              "Sequence must be at offset 0 for atomic efficiency");

/*===========================================================================
 * LIFECYCLE
 *=========================================================================*/

/* Initialize control block to AVAILABLE state */
void CB_Initialize(ControlBlock* cb);

/* Validate control block magic and version */
BOOL CB_Validate(const ControlBlock* cb);

/* Check if control block is in poisoned state */
BOOL CB_IsPoisoned(const ControlBlock* cb);

/* Set poisoned state (fatal error) */
void CB_SetPoisoned(ControlBlock* cb);

/*===========================================================================
 * STATE MACHINE TRANSITIONS
 * 
 * All transitions return TRUE on success, FALSE if preconditions not met.
 *=========================================================================*/

/* Server: Transition AVAILABLE -> READY
 * Releases data to client */
BOOL CB_Commit(ControlBlock* cb, uint32_t payloadSize, uint32_t tokenCount);

/* Client: Transition READY -> CONSUMING
 * Acquires data for reading */
BOOL CB_Acquire(ControlBlock* cb);

/* Client: Transition CONSUMING -> FLUSHING
 * Signals read complete, ready for flush */
BOOL CB_Release(ControlBlock* cb);

/* Server: Transition FLUSHING -> AVAILABLE
 * Recycles buffer for next write */
BOOL CB_Recycle(ControlBlock* cb);

/*===========================================================================
 * SYNCHRONIZATION PRIMITIVES
 *=========================================================================*/

/* Spin-wait for state with PAUSE hint (reduces power consumption) */
void CB_SpinWaitForState(const ControlBlock* cb, BufferState expected);

/* Try to acquire with timeout (for watchdog implementation) */
BOOL CB_TryAcquireWithTimeout(ControlBlock* cb, uint32_t timeoutMs);

/* Get current sequence number (for torn-read detection) */
uint64_t CB_GetSequence(const ControlBlock* cb);

/* Verify sequence hasn't changed during read (call before/after read) */
BOOL CB_VerifySequence(const ControlBlock* cb, uint64_t expectedSeq);

/*===========================================================================
 * WATCHDOG & RESILIENCE
 *=========================================================================*/

/* Check if buffer has been in CONSUMING state too long (watchdog) */
BOOL CB_IsStalled(const ControlBlock* cb, uint32_t thresholdMs);

/* Get human-readable state name */
const char* CB_GetStateName(BufferState state);

/* Get payload metadata (only valid after ACQUIRE) */
void CB_GetPayloadInfo(const ControlBlock* cb, uint32_t* outSize, 
                       uint32_t* outTokens, uint64_t* outTimestamp);

#ifdef __cplusplus
}
#endif
