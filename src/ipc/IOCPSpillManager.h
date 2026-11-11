/*===========================================================================
 * IOCPSpillManager.h
 * VAL-028.2: IOCP Spill Manager
 * 
 * Asynchronous I/O management for tiered memory architecture.
 * Handles overflow from fast IPC buffer to disk with zero blocking.
 *
 * Architecture:
 *   ControlBlock (Fast Path) --overflow--> SpillQueue --async--> IOCP --disk
 *                                        |
 *   AdmissionController <--backpressure---+
 * 
 * Design Decisions:
 *   1. Overlap Batching: Batched OVERLAPPED structures (16 per batch)
 *   2. Backpressure: Signals AdmissionController at 80% queue depth
 *   3. Lock-Free: Single-producer ring buffer for spill queue
 *===========================================================================*/

#pragma once

#include <windows.h>
#include <atomic>
#include <cstdint>
#include "ControlBlock.h"

#ifdef __cplusplus
extern "C" {
#endif

/*===========================================================================
 * CONSTANTS
 *=========================================================================*/
#define IOCP_VERSION                    1
#define IOCP_MAGIC                      0x52415752494F4350ULL  // "RAWRIOSP"

// Spill queue configuration
#define IOCP_QUEUE_SIZE                 256     // Must be power of 2
#define IOCP_BATCH_SIZE                 16      // OVERLAPPEDs per batch
#define IOCP_MAX_PENDING_IO             64      // Max outstanding I/O ops
#define IOCP_BACKPRESSURE_THRESHOLD     0.80f   // 80% full = throttle
#define IOCP_SECTOR_SIZE                4096    // For FILE_FLAG_NO_BUFFERING

// Timeout constants
#define IOCP_COMPLETION_TIMEOUT_MS      100
#define IOCP_FLUSH_TIMEOUT_MS           5000

/*===========================================================================
 * SPILL BUFFER STATE
 *=========================================================================*/
enum class SpillBufferState : uint32_t {
    AVAILABLE   = 0,    // Ready for data
    QUEUED      = 1,    // In spill queue, waiting for I/O
    IN_FLIGHT   = 2,    // I/O operation in progress
    COMPLETED   = 3,    // I/O complete, ready for recycle
    ERROR       = 4     // I/O error occurred
};

/*===========================================================================
 * SPILL BUFFER
 * Individual buffer unit for async I/O
 *=========================================================================*/
struct alignas(IOCP_SECTOR_SIZE) SpillBuffer {
    // State
    std::atomic<SpillBufferState> state;
    
    // Metadata
    uint64_t sequence;          // Matches ControlBlock sequence
    uint32_t dataSize;          // Actual data bytes (<= buffer size)
    uint32_t bufferIndex;       // Index in buffer pool
    
    // OVERLAPPED for async I/O
    OVERLAPPED overlapped;
    
    // Data follows (sector-aligned)
    // uint8_t data[IOCP_SECTOR_SIZE - sizeof(header)];
};

// Static assertions
static_assert(sizeof(SpillBuffer) <= IOCP_SECTOR_SIZE, 
              "SpillBuffer header must fit in sector");

/*===========================================================================
 * SPILL QUEUE
 * Lock-free single-producer ring buffer
 *=========================================================================*/
struct SpillQueue {
    // Head/Tail indices (atomic for lock-free operation)
    std::atomic<uint32_t> head;     // Producer writes here
    std::atomic<uint32_t> tail;     // Consumer (IOCP thread) reads here
    
    // Queue depth tracking
    std::atomic<uint32_t> depth;
    std::atomic<uint32_t> maxDepth;
    
    // Buffer indices (circular)
    uint32_t bufferIndices[IOCP_QUEUE_SIZE];
};

/*===========================================================================
 * IOCP STATISTICS
 *=========================================================================*/
struct IOCPStats {
    uint64_t totalSpilled;          // Total buffers spilled to disk
    uint64_t totalRecovered;        // Total buffers recovered from disk
    uint64_t totalErrors;           // I/O errors encountered
    uint64_t backpressureEvents;    // Times backpressure was triggered
    
    uint32_t currentQueueDepth;     // Current spill queue depth
    uint32_t maxQueueDepth;         // Maximum observed depth
    uint32_t pendingIOCount;        // Current in-flight I/O operations
    
    float avgIOLatencyMs;           // Average I/O latency
    float maxIOLatencyMs;           // Maximum observed latency
};

/*===========================================================================
 * IOCP SPILL MANAGER
 *=========================================================================*/
typedef struct IOCPSpillManager {
    // IOCP handle
    HANDLE hIOCP;
    
    // Spill file handle
    HANDLE hSpillFile;
    WCHAR spillFilePath[MAX_PATH];
    
    // Buffer pool
    SpillBuffer* bufferPool;
    uint32_t bufferCount;
    
    // Spill queue
    SpillQueue* spillQueue;
    
    // Threading
    HANDLE hWorkerThread;
    std::atomic<bool> shutdownRequested;
    
    // Backpressure callback
    void (*backpressureCallback)(bool enable);
    
    // Statistics
    IOCPStats stats;
    
    // Configuration
    size_t spillFileMaxSize;
    size_t spillFileCurrentOffset;
    
} IOCPSpillManager;

/*===========================================================================
 * LIFECYCLE
 *=========================================================================*/

/* Initialize IOCP spill manager
 * spillFilePath: Path to spill file (created/truncated)
 * bufferCount: Number of spill buffers to allocate
 * backpressureCb: Called when queue depth exceeds threshold
 * Returns: TRUE on success */
BOOL IOCP_Initialize(
    IOCPSpillManager* mgr,
    const WCHAR* spillFilePath,
    uint32_t bufferCount,
    void (*backpressureCb)(bool enable)
);

/* Shutdown and cleanup
 * Waits for pending I/O to complete (up to FLUSH_TIMEOUT_MS) */
void IOCP_Shutdown(IOCPSpillManager* mgr);

/* Check if manager is active */
BOOL IOCP_IsActive(const IOCPSpillManager* mgr);

/*===========================================================================
 * SPILL OPERATIONS
 *=========================================================================*/

/* Queue buffer for async spill to disk
 * data: Data to spill (must be sector-aligned)
 * size: Data size (must be <= sector size, multiple of sector size)
 * sequence: ControlBlock sequence for correlation
 * Returns: TRUE if queued, FALSE if queue full (backpressure) */
BOOL IOCP_SpillBuffer(
    IOCPSpillManager* mgr,
    const void* data,
    uint32_t size,
    uint64_t sequence
);

/* Check if spill is needed (queue depth > threshold) */
BOOL IOCP_ShouldSpill(const IOCPSpillManager* mgr);

/* Get current queue depth (0-100%) */
float IOCP_GetQueuePressure(const IOCPSpillManager* mgr);

/*===========================================================================
 * RECOVERY OPERATIONS
 *=========================================================================*/

/* Recover spilled data from disk
 * sequence: Sequence number to recover
 * outBuffer: Output buffer (must be sector-aligned)
 * maxSize: Maximum bytes to read
 * Returns: Bytes read, or 0 if not found/error */
uint32_t IOCP_RecoverBuffer(
    IOCPSpillManager* mgr,
    uint64_t sequence,
    void* outBuffer,
    uint32_t maxSize
);

/*===========================================================================
 * BACKPRESSURE
 *=========================================================================*/

/* Enable/disable backpressure manually */
void IOCP_SetBackpressure(IOCPSpillManager* mgr, bool enable);

/* Check if backpressure is active */
BOOL IOCP_IsBackpressureActive(const IOCPSpillManager* mgr);

/*===========================================================================
 * STATISTICS
 *=========================================================================*/

/* Get current statistics (atomic read) */
void IOCP_GetStats(const IOCPSpillManager* mgr, IOCPStats* outStats);

/* Reset statistics */
void IOCP_ResetStats(IOCPSpillManager* mgr);

/* Get human-readable status string */
void IOCP_GetStatusString(const IOCPSpillManager* mgr, WCHAR* outBuffer, size_t bufferSize);

/*===========================================================================
 * INTERNAL API (Worker Thread)
 *=========================================================================*/

/* Worker thread procedure */
DWORD WINAPI IOCP_WorkerThreadProc(LPVOID lpParam);

/* Process completed I/O */
void IOCP_ProcessCompletion(IOCPSpillManager* mgr, DWORD bytesTransferred, ULONG_PTR completionKey, OVERLAPPED* overlapped);

/* Handle I/O error */
void IOCP_HandleIOError(IOCPSpillManager* mgr, SpillBuffer* buffer, DWORD errorCode);

/* Signal backpressure to admission controller */
void IOCP_SignalBackpressure(IOCPSpillManager* mgr, bool enable);

#ifdef __cplusplus
}
#endif
