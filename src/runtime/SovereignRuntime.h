/*===========================================================================
 * SovereignRuntime.h - Unified Inference Runtime Interface
 * 
 * Shared DLL interface for both CLI and GUI IDE
 * Exports C API for maximum compatibility
 * 
 * Architecture:
 *   CLI.exe / IDE.exe → SovereignRuntime.dll → Kernel Dispatch → MASM Kernels
 *===========================================================================*/

#pragma once

#include <windows.h>
#include <stdint.h>

#ifdef SOVEREIGN_RUNTIME_EXPORTS
#define SOVEREIGN_API __declspec(dllexport)
#else
#define SOVEREIGN_API __declspec(dllimport)
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*===========================================================================
 * CONSTANTS
 *=========================================================================*/
#define SR_VERSION_MAJOR        1
#define SR_VERSION_MINOR        2
#define SR_VERSION_PATCH        0

#define SR_MAX_PATH_LEN         512
#define SR_MAX_PROMPT_LEN       4096
#define SR_MAX_MODEL_NAME       256
#define SR_MAX_ERROR_LEN        512
#define SR_MAX_TOKENS_DEFAULT   128

/*===========================================================================
 * STATUS CODES
 *=========================================================================*/
typedef enum SR_Status {
    SR_OK = 0,
    SR_ERROR_NOT_INITIALIZED,
    SR_ERROR_MODEL_NOT_LOADED,
    SR_ERROR_MODEL_LOAD_FAILED,
    SR_ERROR_INFERENCE_FAILED,
    SR_ERROR_MEMORY_ALLOCATION,
    SR_ERROR_INVALID_PARAM,
    SR_ERROR_KERNEL_INIT_FAILED,
    SR_ERROR_UNSUPPORTED_MODEL,
    SR_ERROR_CANCELLED
} SR_Status;

/*===========================================================================
 * MODEL INFORMATION
 *=========================================================================*/
typedef struct SR_ModelInfo {
    WCHAR       name[SR_MAX_MODEL_NAME];
    WCHAR       path[SR_MAX_PATH_LEN];
    uint32_t    contextLength;
    uint32_t    vocabSize;
    uint32_t    numLayers;
    uint32_t    hiddenDim;
    uint32_t    numExperts;
    uint32_t    expertsPerToken;
    uint64_t    totalParams;
    uint64_t    fileSizeBytes;
    BOOL        isQuantized;
    uint8_t     quantizationBits;  /* 4, 8, or 16 */
    BOOL        isLoaded;
} SR_ModelInfo;

/*===========================================================================
 * INFERENCE CONFIGURATION
 *=========================================================================*/
typedef struct SR_InferenceConfig {
    uint32_t    maxTokens;
    float       temperature;
    float       topP;
    uint32_t    topK;
    float       repeatPenalty;
    uint32_t    repeatLastN;
    uint32_t    seed;              /* 0 = random */
    BOOL        streamOutput;      /* TRUE = callback per token */
    BOOL        useFlashAttention; /* Enable Flash Attention v2 */
    BOOL        useLargePages;     /* Enable large page support */
    BOOL        pinThreads;        /* Pin threads to cores */
    uint32_t    numThreads;        /* 0 = auto (all cores) */
} SR_InferenceConfig;

/* Default configuration */
static const SR_InferenceConfig SR_DEFAULT_CONFIG = {
    .maxTokens = 128,
    .temperature = 0.8f,
    .topP = 0.9f,
    .topK = 40,
    .repeatPenalty = 1.1f,
    .repeatLastN = 64,
    .seed = 0,
    .streamOutput = TRUE,
    .useFlashAttention = TRUE,
    .useLargePages = FALSE,
    .pinThreads = TRUE,
    .numThreads = 0
};

/*===========================================================================
 * TOKEN CALLBACK
 * Called for each generated token during streaming inference
 *=========================================================================*/
typedef void (*SR_TokenCallback)(
    const WCHAR* tokenText,     /* UTF-16 token text */
    uint32_t tokenId,           /* Token ID */
    uint32_t tokenIndex,        /* Position in sequence (0 = first) */
    BOOL isComplete,            /* TRUE if final token (EOS or max reached) */
    float logits[],             /* Optional: logits for this position */
    uint32_t vocabSize,         /* Size of logits array */
    void* userData              /* User data passed to Generate() */
);

/*===========================================================================
 * PROGRESS CALLBACK
 * Called periodically during model loading and inference
 *=========================================================================*/
typedef void (*SR_ProgressCallback)(
    const WCHAR* operation,     /* "Loading", "Inferencing", etc. */
    uint32_t current,           /* Current progress */
    uint32_t total,             /* Total items */
    void* userData
);

/*===========================================================================
 * LIFECYCLE FUNCTIONS
 *=========================================================================*/

/* Initialize the Sovereign Runtime
 * Must be called before any other functions
 * Returns: SR_OK on success */
SOVEREIGN_API SR_Status SR_Initialize(void);

/* Shutdown and cleanup the runtime
 * Cancels any running inference and releases all resources */
SOVEREIGN_API void SR_Shutdown(void);

/* Check if runtime is initialized and ready */
SOVEREIGN_API BOOL SR_IsInitialized(void);

/* Get runtime version string */
SOVEREIGN_API const char* SR_GetVersionString(void);

/* Get runtime capabilities */
SOVEREIGN_API void SR_GetCapabilities(
    BOOL* outHasAVX2,
    BOOL* outHasAVX512,
    BOOL* outHasLargePages,
    uint32_t* outNumCores
);

/*===========================================================================
 * MODEL MANAGEMENT
 *=========================================================================*/

/* Load a GGUF model from file
 * Path must be absolute or relative to working directory
 * Returns: SR_OK on success, model info populated in outInfo */
SOVEREIGN_API SR_Status SR_LoadModel(
    const WCHAR* ggufPath,
    SR_ModelInfo* outInfo,
    SR_ProgressCallback progressCallback,
    void* progressUserData
);

/* Unload current model and free associated memory */
SOVEREIGN_API void SR_UnloadModel(void);

/* Get information about currently loaded model */
SOVEREIGN_API BOOL SR_GetModelInfo(SR_ModelInfo* outInfo);

/* Check if a model is currently loaded */
SOVEREIGN_API BOOL SR_IsModelLoaded(void);

/*===========================================================================
 * INFERENCE FUNCTIONS
 *=========================================================================*/

/* Generate completion from prompt (STREAMING)
 * 
 * This function returns immediately and streams tokens via callback.
 * The callback is invoked from a background thread - UI must marshal to main thread.
 * 
 * For CLI: callback prints to console
 * For GUI: callback sends WM_USER_TOKEN message to UI thread
 * 
 * Returns: SR_OK if inference started successfully (not completion status)
 *          Check callback's isComplete for actual completion
 */
SOVEREIGN_API SR_Status SR_Generate(
    const WCHAR* prompt,
    const SR_InferenceConfig* config,
    SR_TokenCallback tokenCallback,
    void* userData
);

/* Generate completion from prompt (BLOCKING)
 * 
 * Simpler interface that blocks until completion is done.
 * Output buffer must be large enough for maxTokens * average token length.
 * 
 * Returns: SR_OK on successful completion
 */
SOVEREIGN_API SR_Status SR_GenerateBlocking(
    const WCHAR* prompt,
    const SR_InferenceConfig* config,
    WCHAR* outText,
    size_t outTextCapacity,
    uint32_t* outTokensGenerated
);

/* Cancel any in-flight generation */
SOVEREIGN_API void SR_CancelGeneration(void);

/* Check if generation is currently running */
SOVEREIGN_API BOOL SR_IsGenerating(void);

/* Wait for generation to complete (with timeout)
 * timeoutMs: 0 = infinite wait
 * Returns: TRUE if completed, FALSE if timeout */
SOVEREIGN_API BOOL SR_WaitForCompletion(uint32_t timeoutMs);

/*===========================================================================
 * TELEMETRY AND DEBUGGING
 *=========================================================================*/

typedef struct SR_Telemetry {
    uint64_t    tokensGenerated;
    uint64_t    tokensPerSecond;
    uint64_t    totalTimeMs;
    uint64_t    promptProcessingTimeMs;
    uint64_t    tokenGenerationTimeMs;
    uint64_t    memoryUsedBytes;
    uint64_t    memoryPeakBytes;
    uint32_t    kernelCalls;
    uint32_t    cacheHits;
    uint32_t    cacheMisses;
} SR_Telemetry;

/* Get telemetry from last generation */
SOVEREIGN_API BOOL SR_GetTelemetry(SR_Telemetry* outTelemetry);

/* Get last error message */
SOVEREIGN_API const WCHAR* SR_GetLastError(void);

/* Enable/disable verbose logging */
SOVEREIGN_API void SR_SetVerbose(BOOL enable);

/* Get kernel dispatch table for advanced use */
SOVEREIGN_API void* SR_GetKernelDispatchTable(void);

#ifdef __cplusplus
} /* extern "C" */
#endif
