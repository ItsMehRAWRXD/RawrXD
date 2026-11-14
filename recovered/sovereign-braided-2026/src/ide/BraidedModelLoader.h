/*===========================================================================
 * BraidedModelLoader.h
 * Universal Model Loader with Dynamic Braiding & Sharding
 * 
 * Supports ALL model architectures: Llama, DeepSeek, Mixtral, Qwen, etc.
 * Features: Hybrid memory, demand paging, multi-GPU, universal dispatch
 *===========================================================================*/

#pragma once

#include <windows.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/*===========================================================================
 * CONSTANTS
 *=========================================================================*/
#define BRAIDED_MAX_BRAIDS              256
#define BRAIDED_MAX_SHARDS              1024
#define BRAIDED_MAX_LAYERS              256
#define BRAIDED_MAX_EXPERTS             256
#define BRAIDED_MAX_PATH_LEN            512
#define BRAIDED_MAX_NAME_LEN            256
#define BRAIDED_CACHE_LINE_SIZE         64

/*===========================================================================
 * STATUS CODES
 *=========================================================================*/
typedef enum BraidedStatus {
    BRAIDED_OK = 0,
    BRAIDED_ERROR_INVALID_PARAM,
    BRAIDED_ERROR_FILE_NOT_FOUND,
    BRAIDED_ERROR_INVALID_FORMAT,
    BRAIDED_ERROR_MEMORY,
    BRAIDED_ERROR_UNSUPPORTED_ARCH,
    BRAIDED_ERROR_BRAIDING_FAILED,
    BRAIDED_ERROR_SHARDING_FAILED,
    BRAIDED_ERROR_INFERENCE_FAILED,
    BRAIDED_ERROR_NOT_INITIALIZED
} BraidedStatus;

/*===========================================================================
 * MODEL ARCHITECTURE TYPES
 * Supports ALL architectures
 *=========================================================================*/
typedef enum BraidedArchType {
    BRAIDED_ARCH_UNKNOWN = 0,
    BRAIDED_ARCH_LLAMA,         /* Llama 1/2/3, Mistral, etc. */
    BRAIDED_ARCH_DEEPSEEK,      /* DeepSeek-V2/V3 with MLA */
    BRAIDED_ARCH_MIXTRAL,       /* Mixtral MoE */
    BRAIDED_ARCH_QWEN,          /* Qwen 1/2 */
    BRAIDED_ARCH_GEMMA,         /* Google Gemma */
    BRAIDED_ARCH_PHI,           /* Microsoft Phi */
    BRAIDED_ARCH_STABLELM,      /* Stability AI StableLM */
    BRAIDED_ARCH_FALCON,        /* TII Falcon */
    BRAIDED_ARCH_MPT,           /* MosaicML MPT */
    BRAIDED_ARCH_GPTNEOX,       /* EleutherAI GPT-NeoX */
    BRAIDED_ARCH_CUSTOM         /* Custom/experimental */
} BraidedArchType;

/*===========================================================================
 * BACKEND TYPES
 *=========================================================================*/
typedef enum BraidedBackendType {
    BRAIDED_BACKEND_CPU = 0,
    BRAIDED_BACKEND_CUDA,
    BRAIDED_BACKEND_VULKAN,
    BRAIDED_BACKEND_METAL,
    BRAIDED_BACKEND_HYBRID      /* Auto-select best */
} BraidedBackendType;

/*===========================================================================
 * BRAIDING CONFIGURATION
 *=========================================================================*/
typedef struct BraidedConfig {
    /* Model path (UTF-8) */
    char        modelPath[BRAIDED_MAX_PATH_LEN];
    
    /* Architecture hints (0 = auto-detect) */
    BraidedArchType archType;
    uint32_t    numLayers;
    uint32_t    numExperts;
    uint32_t    hiddenDim;
    uint32_t    numHeads;
    uint32_t    headDim;
    uint32_t    vocabSize;
    uint32_t    contextLength;
    
    /* Braiding parameters (0 = auto-calculate) */
    uint32_t    numBraids;          /* Parallel execution streams */
    uint32_t    shardCount;         /* Number of shards */
    uint32_t    cacheSizeGB;        /* RAM cache size */
    uint32_t    pageSizeMB;         /* NVMe paging unit size */
    
    /* Execution parameters */
    BraidedBackendType backend;
    bool        useNVMe;            /* Enable hybrid memory */
    bool        useGPU;             /* Enable GPU acceleration */
    bool        useQuantization;    /* Enable dynamic quantization */
    uint8_t     quantBits;          /* 4, 8, or 16 */
    
    /* Threading */
    uint32_t    numThreads;         /* 0 = auto (CPU cores) */
    uint32_t    threadAffinity;     /* CPU affinity mask */
    
    /* Callbacks */
    void*       userData;
    void        (*progressCallback)(float percent, const char* stage, void* userData);
    void        (*errorCallback)(BraidedStatus error, const char* message, void* userData);
} BraidedConfig;

/*===========================================================================
 * MODEL HANDLE
 *=========================================================================*/
typedef struct BraidedModelContext* BraidedModelHandle;

/*===========================================================================
 * MODEL INFO
 *=========================================================================*/
typedef struct BraidedModelInfo {
    char        name[BRAIDED_MAX_NAME_LEN];
    char        archName[64];
    BraidedArchType archType;
    
    /* Parameters */
    uint64_t    totalParams;
    uint64_t    activeParams;       /* For MoE: params per token */
    uint32_t    numLayers;
    uint32_t    numExperts;
    uint32_t    expertsPerToken;    /* For MoE */
    uint32_t    hiddenDim;
    uint32_t    numHeads;
    uint32_t    vocabSize;
    uint32_t    contextLength;
    
    /* Memory */
    uint64_t    modelSizeBytes;
    uint32_t    quantizationBits;
    uint64_t    memoryRequiredBytes;
    
    /* Braiding */
    uint32_t    numBraids;
    uint32_t    shardCount;
    uint32_t    cacheSizeGB;
    
    /* Status */
    bool        isLoaded;
    bool        isQuantized;
    float       loadProgress;
} BraidedModelInfo;

/*===========================================================================
 * INFERENCE REQUEST/RESPONSE
 *=========================================================================*/
typedef struct BraidedInferenceRequest {
    /* Input context (UTF-8) */
    const char* context;
    uint32_t    contextLen;
    
    /* Generation parameters */
    uint32_t    maxTokens;
    float       temperature;
    float       topP;
    uint32_t    topK;
    float       repetitionPenalty;
    
    /* Streaming */
    bool        streamTokens;
    void        (*tokenCallback)(const char* token, uint32_t tokenIndex, 
                                  bool isComplete, void* userData);
    void*       callbackUserData;
} BraidedInferenceRequest;

typedef struct BraidedInferenceResult {
    BraidedStatus status;
    char*       text;               /* Generated text (UTF-8) - caller frees */
    uint32_t    textLen;
    uint32_t    tokensGenerated;
    float       confidence;
    float       perplexity;
    uint64_t    inferenceTimeMs;
} BraidedInferenceResult;

/*===========================================================================
 * LIFECYCLE FUNCTIONS
 *=========================================================================*/

/* Initialize the Braided Model Loader
 * Must be called before any other functions
 * Returns: BRAIDED_OK on success */
BraidedStatus BraidedModelLoader_Init(void);

/* Shutdown and cleanup the loader
 * Releases all resources and unloads models */
void BraidedModelLoader_Shutdown(void);

/* Get version string */
const char* BraidedModelLoader_GetVersion(void);

/*===========================================================================
 * MODEL LOADING FUNCTIONS
 *=========================================================================*/

/* Load a model with automatic architecture detection and braiding
 * 
 * This is the UNIVERSAL entry point - works with ALL model types:
 * - Llama (7B, 13B, 70B, 405B)
 * - DeepSeek (V2, V3, 671B)
 * - Mixtral (8x7B, 8x22B)
 * - Qwen (1.8B to 110B)
 * - Any GGUF format model
 * 
 * The loader automatically:
 * 1. Detects architecture from GGUF metadata
 * 2. Calculates optimal braiding based on hardware
 * 3. Sets up hybrid memory (RAM + NVMe) if needed
 * 4. Configures sharding for multi-GPU
 * 
 * Returns: BRAIDED_OK on success, modelHandle populated */
BraidedStatus BraidedModelLoader_LoadModel(
    const BraidedConfig* config,
    BraidedModelHandle* outHandle
);

/* Load with explicit architecture (for custom/experimental models) */
BraidedStatus BraidedModelLoader_LoadModelEx(
    const BraidedConfig* config,
    BraidedArchType forcedArch,
    BraidedModelHandle* outHandle
);

/* Unload a model and free resources */
void BraidedModelLoader_UnloadModel(BraidedModelHandle handle);

/* Get model info */
BraidedStatus BraidedModelLoader_GetModelInfo(
    BraidedModelHandle handle,
    BraidedModelInfo* outInfo
);

/* Check if model is ready for inference */
bool BraidedModelLoader_IsModelReady(BraidedModelHandle handle);

/* Get last error message */
const char* BraidedModelLoader_GetLastError(void);

/*===========================================================================
 * INFERENCE FUNCTIONS
 *=========================================================================*/

/* Synchronous inference (blocking)
 * Complete request/response in one call
 * Suitable for simple use cases */
BraidedStatus BraidedModelLoader_InferSync(
    BraidedModelHandle handle,
    const BraidedInferenceRequest* request,
    BraidedInferenceResult* outResult
);

/* Asynchronous inference (non-blocking)
 * Returns immediately, callback invoked with tokens
 * Suitable for streaming UI updates */
BraidedStatus BraidedModelLoader_InferAsync(
    BraidedModelHandle handle,
    const BraidedInferenceRequest* request,
    void* userData,
    void (*completionCallback)(const BraidedInferenceResult* result, void* userData)
);

/* Cancel ongoing inference */
void BraidedModelLoader_CancelInference(BraidedModelHandle handle);

/* Check if inference is running */
bool BraidedModelLoader_IsInferencing(BraidedModelHandle handle);

/*===========================================================================
 * MEMORY MANAGEMENT
 *=========================================================================*/

/* Preload specific layers into RAM (for predictable access patterns) */
BraidedStatus BraidedModelLoader_PreloadLayers(
    BraidedModelHandle handle,
    uint32_t startLayer,
    uint32_t endLayer
);

/* Evict layers from RAM (free memory for other operations) */
void BraidedModelLoader_EvictLayers(
    BraidedModelHandle handle,
    uint32_t startLayer,
    uint32_t endLayer
);

/* Get memory statistics */
typedef struct BraidedMemoryStats {
    uint64_t    totalModelSize;
    uint64_t    residentMemory;     /* Currently in RAM */
    uint64_t    cachedMemory;       /* In RAM cache */
    uint64_t    pagedMemory;        /* On NVMe */
    uint64_t    totalMemoryUsed;
    float       cacheHitRate;
    uint32_t    numPageFaults;
} BraidedMemoryStats;

BraidedStatus BraidedModelLoader_GetMemoryStats(
    BraidedModelHandle handle,
    BraidedMemoryStats* outStats
);

/*===========================================================================
 * UTILITY FUNCTIONS
 *=========================================================================*/

/* Auto-detect architecture from GGUF file */
BraidedArchType BraidedModelLoader_DetectArchitecture(
    const char* modelPath
);

/* Calculate optimal braiding for hardware */
BraidedStatus BraidedModelLoader_CalculateOptimalBraiding(
    uint64_t modelSizeBytes,
    uint32_t numLayers,
    uint32_t numExperts,
    uint64_t availableRAM,
    uint32_t* outNumBraids,
    uint32_t* outShardCount,
    uint32_t* outCacheSizeGB
);

/* Format model size for display */
void BraidedModelLoader_FormatSize(
    uint64_t bytes,
    char* outBuffer,
    size_t bufferSize
);

/* Get supported architectures list */
const char** BraidedModelLoader_GetSupportedArchitectures(
    uint32_t* outCount
);

#ifdef __cplusplus
}
#endif

/* E> End of BraidedModelLoader.h <3 */
