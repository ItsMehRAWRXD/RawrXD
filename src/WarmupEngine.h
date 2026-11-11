/*===========================================================================
 * WarmupEngine.h
 * Memory Pre-faulting Engine for RawrXD Model Loading
 * 
 * Keeps model weights "hot" in physical RAM by pre-touching memory-mapped pages
 * before inference begins. Eliminates cold-start latency for large models.
 *
 * Integrates with: BraidedModelLoader, SovereignInferenceBridge
 *===========================================================================*/

#pragma once

#include <windows.h>
#include <atomic>
#include <thread>
#include <vector>
#include <functional>

#ifdef __cplusplus
extern "C" {
#endif

/*===========================================================================
 * CONSTANTS
 *=========================================================================*/
#define WARMUP_ENGINE_VERSION       1
#define WARMUP_DEFAULT_THREADS      4
#define WARMUP_CHUNK_SIZE           (64 * 1024 * 1024)  // 64MB chunks
#define WARMUP_MIN_CHUNK_SIZE       (4 * 1024 * 1024)   // 4MB minimum

/*===========================================================================
 * STATUS CODES
 *=========================================================================*/
typedef enum WarmupStatus {
    WARMUP_OK = 0,
    WARMUP_ERROR_NOT_INITIALIZED,
    WARMUP_ERROR_ALREADY_RUNNING,
    WARMUP_ERROR_INVALID_PARAMS,
    WARMUP_ERROR_MEMORY_ACCESS,
    WARMUP_ERROR_CANCELLED
} WarmupStatus;

/*===========================================================================
 * WARMUP CONFIGURATION
 *=========================================================================*/
typedef struct WarmupConfig {
    uint32_t    numThreads;         // Number of parallel warmup threads
    uint32_t    chunkSize;          // Bytes to prefetch per iteration
    uint32_t    priorityClass;      // Thread priority (e.g., BELOW_NORMAL)
    BOOL        sequentialOnly;     // TRUE = linear scan, FALSE = interleaved
    BOOL        cancelOnInference;  // Auto-cancel when inference starts
    void*       userData;           // Callback context
} WarmupConfig;

/*===========================================================================
 * PROGRESS CALLBACK
 *=========================================================================*/
typedef void (*WarmupProgressCallback)(
    uint64_t bytesWarmed,           // Bytes pre-faulted so far
    uint64_t totalBytes,            // Total model size
    float percentComplete,          // 0.0 - 100.0
    void* userData                  // Original userData from config
);

/*===========================================================================
 * COMPLETION CALLBACK
 *=========================================================================*/
typedef void (*WarmupCompleteCallback)(
    WarmupStatus status,            // WARMUP_OK or error code
    uint64_t bytesWarmed,           // Total bytes successfully warmed
    double elapsedSeconds,          // Time taken
    void* userData                  // Original userData from config
);

/*===========================================================================
 * LIFECYCLE FUNCTIONS
 *===========================================================================*/

/* Initialize the Warmup Engine
 * Must be called before any other functions
 * Returns: WARMUP_OK on success */
WarmupStatus WarmupEngine_Initialize(void);

/* Shutdown and cleanup the Warmup Engine
 * Cancels any running warmup and releases resources */
void WarmupEngine_Shutdown(void);

/* Check if engine is initialized */
BOOL WarmupEngine_IsReady(void);

/*===========================================================================
 * WARMUP OPERATIONS
 *===========================================================================*/

/* Start warming a memory-mapped region (NON-BLOCKING)
 * 
 * Parameters:
 *   baseAddress     - Start of mapped memory region
 *   sizeBytes       - Total size to warm
 *   config          - Warmup configuration
 *   progressCb      - Called periodically with progress updates (can be NULL)
 *   completeCb      - Called when warmup completes (can be NULL)
 * 
 * Returns: WARMUP_OK if warmup started successfully
 * 
 * Note: This returns immediately. Warmup happens in background threads.
 *       Use WarmupEngine_Cancel() to stop early.
 */
WarmupStatus WarmupEngine_Start(
    void* baseAddress,
    uint64_t sizeBytes,
    const WarmupConfig* config,
    WarmupProgressCallback progressCb,
    WarmupCompleteCallback completeCb
);

/* Cancel any running warmup operation */
void WarmupEngine_Cancel(void);

/* Check if warmup is currently running */
BOOL WarmupEngine_IsRunning(void);

/* Get current warmup progress (0.0 - 100.0) */
float WarmupEngine_GetProgress(void);

/* Wait for warmup to complete (blocking) with optional timeout
 * timeoutMs: 0 = infinite wait
 * Returns: TRUE if completed, FALSE if timeout */
BOOL WarmupEngine_WaitForComplete(uint32_t timeoutMs);

/*===========================================================================
 * UTILITY FUNCTIONS
 *===========================================================================*/

/* Get last error message */
const WCHAR* WarmupEngine_GetLastError(void);

/* Get version string */
const WCHAR* WarmupEngine_GetVersion(void);

/* Calculate optimal chunk size based on system memory */
uint32_t WarmupEngine_CalculateOptimalChunkSize(uint64_t modelSize);

/* Estimate warmup time based on storage type and model size */
double WarmupEngine_EstimateTime(
    uint64_t modelSizeBytes,
    uint32_t storageType  // 0=HDD, 1=SATA_SSD, 2=NVMe, 3=Optane
);

/*===========================================================================
 * INTEGRATION HELPERS
 *===========================================================================*/

/* Convenience: Warmup a file handle (maps file, warms, unmaps)
 * This is a blocking wrapper for simple use cases */
WarmupStatus WarmupEngine_WarmupFile(
    HANDLE hFile,
    const WarmupConfig* config
);

/* Convenience: Async warmup with auto-cleanup on inference */
WarmupStatus WarmupEngine_WarmupAsync(
    void* baseAddress,
    uint64_t sizeBytes,
    WarmupProgressCallback progressCb
);

#ifdef __cplusplus
}
#endif

/* E> End of WarmupEngine.h <3 */
