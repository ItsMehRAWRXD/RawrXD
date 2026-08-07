/*===========================================================================
 * SovereignInferenceBridge.h
 * Native AI Inference Bridge for RawrXD IDE
 * 
 * Connects Win32 IDE to Sovereign Runtime (CPUInferenceEngine)
 * for real-time Ghost Text completion without cloud dependencies.
 *
 * Architecture: Async non-blocking token streaming via message queue
 *===========================================================================*/

#pragma once

#include <windows.h>
#include "../BraidedModelLoader.h"
#include "../WarmupEngine.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*===========================================================================
 * CONSTANTS
 *=========================================================================*/
#define SIB_VERSION                     1
#define SIB_MAX_PROMPT_LEN              4096
#define SIB_MAX_COMPLETION_LEN          2048
#define SIB_MAX_TOKENS                  128
#define SIB_PIPE_NAME                   L"\\\\.\\pipe\\RawrXD_SovereignInference"
#define SIB_DEBOUNCE_MS                 250     /* 250ms debounce for typing */
#define SIB_STREAM_BUFFER_SIZE          8192

/*===========================================================================
 * STATUS CODES
 *=========================================================================*/
typedef enum SIB_Status {
    SIB_OK = 0,
    SIB_ERROR_NOT_INITIALIZED,
    SIB_ERROR_MODEL_NOT_LOADED,
    SIB_ERROR_INFERENCE_FAILED,
    SIB_ERROR_PIPE_FAILED,
    SIB_ERROR_TIMEOUT,
    SIB_ERROR_MEMORY,
    SIB_ERROR_INVALID_PARAM
} SIB_Status;

/*===========================================================================
 * MODEL INFO
 *=========================================================================*/
typedef struct SIB_ModelInfo {
    WCHAR       name[256];
    WCHAR       path[MAX_PATH];
    uint32_t    contextLength;
    uint32_t    vocabSize;
    uint32_t    numLayers;
    uint32_t    hiddenDim;
    uint32_t    numExperts;
    uint32_t    expertsPerToken;
    uint64_t    totalParams;
    uint64_t    fileSizeBytes;
    BOOL        isLoaded;
    BOOL        isQuantized;
    uint8_t     quantizationBits;  /* 4, 8, or 16 */
} SIB_ModelInfo;

/*===========================================================================
 * COMPLETION REQUEST
 *=========================================================================*/
typedef struct SIB_CompletionRequest {
    WCHAR       prompt[SIB_MAX_PROMPT_LEN];
    WCHAR       filePath[MAX_PATH];
    uint32_t    cursorLine;
    uint32_t    cursorColumn;
    uint32_t    maxTokens;
    float       temperature;
    float       topP;
    uint32_t    topK;
    BOOL        streamTokens;       /* TRUE = streaming, FALSE = blocking */
    void*       userData;           /* Passed back in callback */
} SIB_CompletionRequest;

/*===========================================================================
 * TOKEN CALLBACK
 * Called for each token during streaming inference
 *=========================================================================*/
typedef void (*SIB_TokenCallback)(
    const WCHAR* token,             /* Token text (UTF-16) */
    uint32_t tokenIndex,            /* Position in sequence */
    BOOL isComplete,                /* TRUE if this is the final token */
    void* userData                  /* Original userData from request */
);

/*===========================================================================
 * LIFECYCLE FUNCTIONS
 *=========================================================================*/

/* Initialize the Sovereign Inference Bridge
 * Must be called before any other functions
 * Returns: SIB_OK on success */
SIB_Status SIB_Initialize(void);

/* Shutdown and cleanup the bridge
 * Terminates any running inference and releases resources */
void SIB_Shutdown(void);

/* Check if bridge is initialized and ready */
BOOL SIB_IsReady(void);

/*===========================================================================
 * MODEL MANAGEMENT
 *=========================================================================*/

/* Load a GGUF model file
 * Path: Full path to .gguf file
 * Returns: SIB_OK on success, model info populated */
SIB_Status SIB_LoadModel(const WCHAR* ggufPath, SIB_ModelInfo* outInfo);

/* Unload current model and free memory */
void SIB_UnloadModel(void);

/* Get info about currently loaded model */
BOOL SIB_GetModelInfo(SIB_ModelInfo* outInfo);

/* Check if a model is currently loaded and ready for inference */
BOOL SIB_IsModelLoaded(void);

/*===========================================================================
 * INFERENCE FUNCTIONS
 *=========================================================================*/

/* Request completion (NON-BLOCKING)
 * This function returns immediately and streams tokens via callback
 * The callback is invoked on a background thread - UI must marshal to main thread
 * 
 * Usage:
 *   1. Fill out SIB_CompletionRequest
 *   2. Provide a SIB_TokenCallback
 *   3. Call SIB_RequestCompletion()
 *   4. Callback receives tokens as they're generated
 *   5. UI marshals tokens to main thread for Ghost Text display
 */
SIB_Status SIB_RequestCompletion(
    const SIB_CompletionRequest* request,
    SIB_TokenCallback callback
);

/* Cancel any in-flight completion request */
void SIB_CancelCompletion(void);

/* Check if inference is currently running */
BOOL SIB_IsInferencing(void);

/*===========================================================================
 * UTILITY FUNCTIONS
 *=========================================================================*/

/* Get last error message as UTF-16 string */
const WCHAR* SIB_GetLastError(void);

/* Get version string */
const WCHAR* SIB_GetVersion(void);

/* Format model size for display (e.g., "7B params, 4.2 GB") */
void SIB_FormatModelSize(
    const SIB_ModelInfo* info,
    WCHAR* outBuffer,
    size_t bufferSize
);

/* Estimate tokens in text (rough approximation for UI feedback) */
uint32_t SIB_EstimateTokens(const WCHAR* text);

/*===========================================================================
 * UI INTEGRATION HELPERS
 *=========================================================================*/

/* Marshal token to UI thread via PostMessage
 * Use this from the token callback to safely update the Ghost Text overlay
 * 
 * Parameters:
 *   hWndTarget - IDE main window handle
 *   msg        - Custom message ID (e.g., WM_APP + SIB_MSG_TOKEN)
 *   token      - Token text (will be copied)
 *   isComplete - Whether this is the final token
 */
BOOL SIB_PostTokenToUI(
    HWND hWndTarget,
    UINT msg,
    const WCHAR* token,
    BOOL isComplete
);

/* Custom window messages for UI integration */
#define WM_SIB_TOKEN          (WM_APP + 200)  /* wParam=token ptr, lParam=isComplete */
#define WM_SIB_COMPLETE       (WM_APP + 201)  /* Inference completed */
#define WM_SIB_ERROR          (WM_APP + 202)  /* wParam=error code */
#define WM_SIB_MODEL_LOADED   (WM_APP + 203)  /* Model loaded successfully */

#ifdef __cplusplus
}
#endif

/* E> End of SovereignInferenceBridge.h <3 */
