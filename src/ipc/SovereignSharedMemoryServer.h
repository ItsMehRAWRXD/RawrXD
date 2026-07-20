/*===========================================================================
 * SovereignSharedMemoryServer.h
 * VAL-028.3: Integration Layer
 * 
 * Unified server that orchestrates fast-path (ControlBlock) and 
 * cold-path (IOCPSpillManager) with dynamic scheduling.
 *
 * Architecture:
 *   Producer (Inference) --
 *                        |
 *                        v
 *   ┌─────────────────────────────────────────┐
 *   │  SovereignSharedMemoryServer            │
 *   │  ┌──────────────┐    ┌──────────────┐   │
 *   │  │ ControlBlock │    │ IOCP Spill   │   │
 *   │  │ (Fast Path)  │-->│ (Cold Path)  │   │
 *   │  └──────────────┘    └──────────────┘   │
 *   └─────────────────────────────────────────┘
 *                        |
 *                        v
 *   Consumer (Client) --
 *                        |
 *                        v
 *   Backpressure --> AdmissionController
 *
 * Design Principle:
 *   - Never block the producer (Ghost Text Never Blocks)
 *   - Always have a place to put data (fast or cold)
 *   - Backpressure flows upstream, not downstream
 *===========================================================================*/

#pragma once

#include <windows.h>
#include <atomic>
#include <cstdint>
#include "ControlBlock.h"
#include "IOCPSpillManager.h"

#ifdef __cplusplus
extern "C" {
#endif

/*===========================================================================
 * CONSTANTS
 *=========================================================================*/
#define SSM_VERSION                     1
#define SSM_MAGIC                       0x5241575253534D53ULL  // "RAWRSSMS"

// Memory pool configuration
#define SSM_FAST_BUFFER_COUNT           16      // ControlBlock buffers
#define SSM_COLD_BUFFER_COUNT           256     // IOCP spill buffers
#define SSM_PAYLOAD_SIZE                65536   // 64KB per buffer

// Decision thresholds
#define SSM_SPILL_THRESHOLD             0.90f   // Spill when 90% full
#define SSM_EMERGENCY_THRESHOLD         0.98f   // Emergency measures at 98%

/*===========================================================================
 * BUFFER DESCRIPTOR
 * Unified view of fast or cold buffer
 *=========================================================================*/
enum class BufferLocation : uint32_t {
    FAST = 0,   // ControlBlock (shared memory)
    COLD = 1    // IOCP spill (disk)
};

struct BufferDescriptor {
    BufferLocation location;
    uint32_t index;         // Index in respective pool
    uint64_t sequence;      // Global sequence number
    uint32_t dataSize;      // Actual data bytes
    uint64_t timestamp;     // Creation timestamp
};

/*===========================================================================
 * WRITE DECISION
 *=========================================================================*/
enum class WriteDecision : uint32_t {
    WRITE_FAST = 0,       // Write to ControlBlock
    WRITE_COLD = 1,       // Spill to IOCP
    WRITE_EMERGENCY = 2   // Drop oldest, write new
};

/*===========================================================================
 * BACKPRESSURE STATE
 *=========================================================================*/
struct BackpressureState {
    std::atomic<bool> active;
    float currentPressure;      // 0.0 - 1.0
    uint64_t lastSignalTime;    // Timestamp of last signal
    uint32_t consecutiveHits;   // Consecutive threshold breaches
};

/*===========================================================================
 * SOVEREIGN SHARED MEMORY SERVER
 *=========================================================================*/
typedef struct SovereignSharedMemoryServer {
    // Magic and version
    uint64_t magic;
    uint32_t version;
    
    // Fast path: ControlBlock array
    ControlBlock* controlBlocks;
    uint32_t controlBlockCount;
    uint8_t* fastPayloadBuffer;     // SSM_PAYLOAD_SIZE * count
    
    // Cold path: IOCP Spill Manager
    IOCPSpillManager* spillManager;
    BOOL spillManagerActive;
    
    // Buffer pools
    BufferDescriptor* bufferPool;
    uint32_t bufferPoolSize;
    
    // Sequence management
    std::atomic<uint64_t> globalSequence;
    
    // Decision logic
    WriteDecision (*decisionFunction)(struct SovereignSharedMemoryServer* srv, 
                                       uint32_t dataSize);
    
    // Backpressure
    BackpressureState backpressure;
    void (*backpressureCallback)(bool enable, float pressure);
    
    // Statistics
    struct {
        uint64_t fastWrites;
        uint64_t coldWrites;
        uint64_t emergencyDrops;
        uint64_t fastReads;
        uint64_t coldReads;
        uint64_t backpressureSignals;
    } stats;
    
    // Threading
    HANDLE hMonitorThread;
    std::atomic<bool> shutdownRequested;
    
    // Configuration
    float spillThreshold;
    float emergencyThreshold;
    
} SovereignSharedMemoryServer;

/*===========================================================================
 * LIFECYCLE
 *=========================================================================*/

/* Initialize unified server
 * fastBufferCount: Number of ControlBlock buffers (e.g., 16)
 * spillFilePath: Path for IOCP spill file
 * backpressureCb: Callback for admission control
 * Returns: TRUE on success */
BOOL SSM_Initialize(
    SovereignSharedMemoryServer* srv,
    uint32_t fastBufferCount,
    const WCHAR* spillFilePath,
    void (*backpressureCb)(bool enable, float pressure)
);

/* Shutdown and cleanup */
void SSM_Shutdown(SovereignSharedMemoryServer* srv);

/* Check if server is active */
BOOL SSM_IsActive(const SovereignSharedMemoryServer* srv);

/*===========================================================================
 * WRITE OPERATIONS (Producer)
 *=========================================================================*/

/* Write data to server (automatic fast/cold decision)
 * data: Data to write
 * size: Data size in bytes
 * outDescriptor: Output buffer descriptor (optional)
 * Returns: TRUE if written (fast or cold), FALSE if dropped */
BOOL SSM_Write(
    SovereignSharedMemoryServer* srv,
    const void* data,
    uint32_t size,
    BufferDescriptor* outDescriptor
);

/* Force write to fast path (ControlBlock)
 * Returns FALSE if no fast buffers available */
BOOL SSM_WriteFast(
    SovereignSharedMemoryServer* srv,
    const void* data,
    uint32_t size,
    BufferDescriptor* outDescriptor
);

/* Force write to cold path (IOCP spill)
 * Always succeeds unless disk full */
BOOL SSM_WriteCold(
    SovereignSharedMemoryServer* srv,
    const void* data,
    uint32_t size,
    BufferDescriptor* outDescriptor
);

/* Get write decision without performing write */
WriteDecision SSM_GetWriteDecision(
    const SovereignSharedMemoryServer* srv,
    uint32_t dataSize
);

/*===========================================================================
 * READ OPERATIONS (Consumer)
 *=========================================================================*/

/* Read next available buffer
 * outDescriptor: Output descriptor with location info
 * outData: Output data pointer (valid only during read)
 * maxSize: Maximum bytes to read
 * Returns: Bytes read, or 0 if no data available */
uint32_t SSM_Read(
    SovereignSharedMemoryServer* srv,
    BufferDescriptor* outDescriptor,
    void* outData,
    uint32_t maxSize
);

/* Release buffer after reading
 * Must be called after SSM_Read to recycle buffer */
void SSM_Release(
    SovereignSharedMemoryServer* srv,
    const BufferDescriptor* descriptor
);

/* Peek at next sequence number without consuming */
uint64_t SSM_PeekNextSequence(const SovereignSharedMemoryServer* srv);

/*===========================================================================
 * DECISION LOGIC
 *=========================================================================*/

/* Default decision function: balances fast vs cold */
WriteDecision SSM_DefaultDecision(
    SovereignSharedMemoryServer* srv,
    uint32_t dataSize
);

/* Set custom decision function */
void SSM_SetDecisionFunction(
    SovereignSharedMemoryServer* srv,
    WriteDecision (*func)(SovereignSharedMemoryServer*, uint32_t)
);

/* Get current pressure (0.0 - 1.0) */
float SSM_GetPressure(const SovereignSharedMemoryServer* srv);

/*===========================================================================
 * BACKPRESSURE
 *=========================================================================*/

/* Check if backpressure is active */
BOOL SSM_IsBackpressureActive(const SovereignSharedMemoryServer* srv);

/* Get backpressure state */
void SSM_GetBackpressureState(
    const SovereignSharedMemoryServer* srv,
    BackpressureState* outState
);

/* Manual backpressure control */
void SSM_SetBackpressure(
    SovereignSharedMemoryServer* srv,
    bool enable
);

/*===========================================================================
 * STATISTICS
 *=========================================================================*/

/* Get server statistics */
void SSM_GetStats(
    const SovereignSharedMemoryServer* srv,
    void* outStats,  // ServerStats struct
    size_t statsSize
);

/* Get human-readable status */
void SSM_GetStatusString(
    const SovereignSharedMemoryServer* srv,
    WCHAR* outBuffer,
    size_t bufferSize
);

/*===========================================================================
 * INTERNAL API
 *=========================================================================*/

/* Monitor thread for backpressure and health */
DWORD WINAPI SSM_MonitorThreadProc(LPVOID lpParam);

/* Signal backpressure to admission controller */
void SSM_SignalBackpressure(
    SovereignSharedMemoryServer* srv,
    bool enable,
    float pressure
);

/* Find available ControlBlock */
ControlBlock* SSM_FindAvailableControlBlock(
    SovereignSharedMemoryServer* srv
);

/* Update statistics */
void SSM_UpdateStats(
    SovereignSharedMemoryServer* srv,
    WriteDecision decision,
    bool isRead
);

#ifdef __cplusplus
}
#endif
