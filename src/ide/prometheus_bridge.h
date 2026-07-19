/*=============================================================================
 * prometheus_bridge.h
 * C Bridge Layer for PrometheusMoE Integration
 * 
 * Provides C-compatible interface to the C++ PrometheusMoE runtime.
 * This keeps the Win32 IDE (C) decoupled from C++ inference internals.
 *
 * Architecture:
 *   Win32 IDE (C) -> prometheus_bridge (C) -> PrometheusMoE (C++)
 *=============================================================================*/

#pragma once

#ifndef PROMETHEUS_BRIDGE_H
#define PROMETHEUS_BRIDGE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <windows.h>
#include <stdint.h>
#include <stdbool.h>

/*=============================================================================
 * Constants
 *=============================================================================*/
#define PB_MAX_PATH_LEN         512
#define PB_MAX_MODEL_NAME_LEN   256
#define PB_MAX_SUGGESTION_LEN   4096
#define PB_MAX_CONTEXT_LEN      2048
#define PB_MAX_ERROR_LEN        512

/*=============================================================================
 * Status Codes
 *=============================================================================*/
typedef enum PB_Status {
    PB_OK = 0,
    PB_ERROR_NOT_INITIALIZED = -1,
    PB_ERROR_ALREADY_LOADED = -2,
    PB_ERROR_LOAD_FAILED = -3,
    PB_ERROR_NOT_LOADED = -4,
    PB_ERROR_INFERENCE_FAILED = -5,
    PB_ERROR_INVALID_PARAM = -6,
    PB_ERROR_OUT_OF_MEMORY = -7,
    PB_ERROR_BRIDGE_ERROR = -8
} PB_Status;

/*=============================================================================
 * Model State
 *=============================================================================*/
typedef enum PB_ModelState {
    PB_STATE_NONE = 0,
    PB_STATE_PROBING,
    PB_STATE_LOADING,
    PB_STATE_LOADED,
    PB_STATE_ERROR
} PB_ModelState;

/*=============================================================================
 * MoE Configuration (C-compatible version)
 *=============================================================================*/
typedef struct PB_MoEConfig {
    bool        isMoE;
    uint32_t    numLayers;
    uint32_t    numExperts;
    uint32_t    expertsPerToken;
    uint32_t    numSharedExperts;
    uint32_t    hiddenDim;
    uint32_t    intermediateDim;
    uint32_t    numHeads;
    uint32_t    numKVHeads;
    uint32_t    headDim;
    uint32_t    vocabSize;
    uint32_t    topK;
    uint64_t    totalParams;
    uint64_t    activeParams;
    uint64_t    modelSizeBytes;
    uint64_t    kvCacheBytes;
    int         quantType;
    bool        isDeepSeekV3;
} PB_MoEConfig;

/*=============================================================================
 * Completion Request
 *=============================================================================*/
typedef struct PB_CompletionRequest {
    wchar_t     context[PB_MAX_CONTEXT_LEN];
    wchar_t     filePath[PB_MAX_PATH_LEN];
    uint32_t    cursorLine;
    uint32_t    cursorColumn;
    uint32_t    maxTokens;
    float       temperature;
    float       topP;
    uint32_t    topK;
    bool        streamTokens;
    void*       userData;
} PB_CompletionRequest;

/*=============================================================================
 * Completion Response
 *=============================================================================*/
typedef struct PB_CompletionResponse {
    wchar_t     text[PB_MAX_SUGGESTION_LEN];
    uint32_t    tokensGenerated;
    bool        isComplete;
    PB_Status   status;
    wchar_t     errorMessage[PB_MAX_ERROR_LEN];
} PB_CompletionResponse;

/*=============================================================================
 * Token Callback
 *=============================================================================*/
typedef void (*PB_TokenCallback)(
    const wchar_t* token,
    uint32_t tokenIndex,
    bool isComplete,
    void* userData
);

/*=============================================================================
 * Bridge API
 *=============================================================================*/

/**
 * Initialize the Prometheus bridge.
 * Must be called before any other bridge functions.
 * 
 * @return PB_OK on success, error code on failure
 */
PB_Status PB_Init(void);

/**
 * Shutdown the Prometheus bridge and release all resources.
 */
void PB_Shutdown(void);

/**
 * Check if the bridge is initialized and ready.
 * 
 * @return true if initialized, false otherwise
 */
bool PB_IsReady(void);

/**
 * Probe a GGUF file for MoE architecture metadata.
 * Fast metadata-only read, does not load weights.
 * 
 * @param path Wide-character path to GGUF file
 * @param config Output configuration structure
 * @return PB_OK on success, error code on failure
 */
PB_Status PB_ProbeModel(const wchar_t* path, PB_MoEConfig* config);

/**
 * Load a model for inference.
 * 
 * @param path Wide-character path to GGUF file
 * @param gpuLayers Number of layers to offload to GPU (-1 for auto)
 * @return PB_OK on success, error code on failure
 */
PB_Status PB_LoadModel(const wchar_t* path, int gpuLayers);

/**
 * Unload the currently loaded model.
 */
void PB_UnloadModel(void);

/**
 * Check if a model is currently loaded.
 * 
 * @return true if loaded, false otherwise
 */
bool PB_IsModelLoaded(void);

/**
 * Get the current model state.
 * 
 * @return Current model state
 */
PB_ModelState PB_GetModelState(void);

/**
 * Get configuration of the loaded model.
 * 
 * @param config Output configuration structure
 * @return PB_OK on success, error code on failure
 */
PB_Status PB_GetModelConfig(PB_MoEConfig* config);

/**
 * Get the last error message.
 * 
 * @return Wide-character error message (static buffer, do not free)
 */
const wchar_t* PB_GetLastError(void);

/**
 * Request a completion from the loaded model.
 * Synchronous version - blocks until completion is ready.
 * 
 * @param request Completion request parameters
 * @param response Output response structure
 * @return PB_OK on success, error code on failure
 */
PB_Status PB_CompleteSync(
    const PB_CompletionRequest* request,
    PB_CompletionResponse* response
);

/**
 * Request a completion from the loaded model.
 * Asynchronous version - returns immediately, tokens delivered via callback.
 * 
 * @param request Completion request parameters
 * @param callback Token callback function
 * @return PB_OK on success, error code on failure
 */
PB_Status PB_CompleteAsync(
    const PB_CompletionRequest* request,
    PB_TokenCallback callback
);

/**
 * Cancel an in-flight completion request.
 */
void PB_CancelCompletion(void);

/**
 * Check if a completion is currently in progress.
 * 
 * @return true if completion is active, false otherwise
 */
bool PB_IsCompletionActive(void);

/**
 * Format model size for display (e.g., "404 GB" or "37 B active").
 * 
 * @param bytes Size in bytes
 * @param output Output buffer
 * @param outputLen Length of output buffer
 */
void PB_FormatModelSize(uint64_t bytes, wchar_t* output, size_t outputLen);

/**
 * Convert narrow string to wide string.
 * Internal utility function.
 * 
 * @param narrow Input narrow string
 * @param wide Output wide string buffer
 * @param wideLen Length of output buffer
 * @return true on success, false on failure
 */
bool PB_NarrowToWide(
    const char* narrow,
    wchar_t* wide,
    size_t wideLen
);

/**
 * Convert wide string to narrow string (UTF-8).
 * Internal utility function.
 * 
 * @param wide Input wide string
 * @param narrow Output narrow string buffer
 * @param narrowLen Length of output buffer
 * @return true on success, false on failure
 */
bool PB_WideToNarrow(
    const wchar_t* wide,
    char* narrow,
    size_t narrowLen
);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // PROMETHEUS_BRIDGE_H
