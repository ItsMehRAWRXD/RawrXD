/*===========================================================================
 * WarmupEngine.h
 * Pre-faults memory-mapped model pages to keep weights "hot" in RAM
 *===========================================================================*/

#pragma once

#include <windows.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*===========================================================================
 * CONSTANTS
 *=========================================================================*/
#define WARMUP_MAX_THREADS          16
#define WARMUP_DEFAULT_THREADS      4
#define WARMUP_PAGE_SIZE            4096

/*===========================================================================
 * STATUS CODES
 *=========================================================================*/
typedef enum WarmupStatus {
    WARMUP_OK = 0,
    WARMUP_ERROR_NOT_INITIALIZED,
    WARMUP_ERROR_INVALID_PARAM,
    WARMUP_ERROR_TIMEOUT,
    WARMUP_ERROR_CANCELLED
} WarmupStatus;

typedef enum WarmupState {
    WARMUP_STATE_IDLE = 0,
    WARMUP_STATE_RUNNING,
    WARMUP_STATE_COMPLETE,
    WARMUP_STATE_CANCELLED,
    WARMUP_STATE_ERROR
} WarmupState;

/*===========================================================================
 * CALLBACK
 *=========================================================================*/
typedef void (*WarmupProgressCallback)(float progress, void* userData);

/*===========================================================================
 * ENGINE STRUCTURE
 *=========================================================================*/
typedef struct WarmupEngine {
    WarmupState     state;
    float           progress;
    size_t          pagesTouched;
    size_t          totalPages;
    int             threadCount;
    HANDLE          threads[WARMUP_MAX_THREADS];
    volatile BOOL   cancelRequested;
    WarmupProgressCallback callback;
    void*           callbackUserData;
} WarmupEngine;

/*===========================================================================
 * API FUNCTIONS
 *=========================================================================*/

/* Initialize the warmup engine */
WarmupStatus WarmupEngine_Init(void);

/* Shutdown and cleanup */
void WarmupEngine_Shutdown(void);

/* Queue a warmup operation */
WarmupStatus WarmupEngine_Queue(void* modelBase, size_t modelSize, int numThreads);

/* Wait for warmup to complete */
WarmupStatus WarmupEngine_Wait(float timeoutSeconds);

/* Cancel current warmup */
void WarmupEngine_Cancel(void);

/* Get current progress (0.0 - 1.0) */
float WarmupEngine_GetProgress(void);

/* Get current state */
WarmupState WarmupEngine_GetState(void);

/* Get last error message */
const char* WarmupEngine_GetLastError(void);

#ifdef __cplusplus
}
#endif

/* E> End of WarmupEngine.h <3 */
