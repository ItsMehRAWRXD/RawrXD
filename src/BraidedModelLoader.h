/*===========================================================================
 * BraidedModelLoader.h
 * Universal Model Loader with Braided Architecture Support
 * 
 * Supports: DeepSeek-V3, Llama, Mixtral, Phi, Qwen, and all GGUF models
 * Features: Dynamic braiding, hybrid memory, demand paging, warmup engine
 *
 * Integrates with: WarmupEngine, SovereignInferenceBridge
 *===========================================================================*/

#pragma once

#include <windows.h>
#include <stdint.h>
#include "WarmupEngine.h"

#ifdef __cplusplus
extern "C" {
#endif

/*===========================================================================
 * CONSTANTS
 *=========================================================================*/
#define BRAIDED_LOADER_VERSION      1
#define BRAIDED_MAX_BRAIDS          64
#define BRAIDED_MAX_SHARDS          256
#define BRAIDED_MAX_LAYERS          256
#define BRAIDED_MAX_EXPERTS         256
#define BRAIDED_MAX_MODEL_PATH      512

/*===========================================================================
 * ARCHITECTURE TYPES
 *=========================================================================*/
typedef enum BraidedArchitecture {
    BRAIDED_ARCH_UNKNOWN = 0,
    BRAIDED_ARCH_LLAMA,         // Llama, Llama2, Llama3
    BRAIDED_ARCH_DEEPSEEK_V3,   // DeepSeek-V3 with MLA + GQA + MoE
    BRAIDED_ARCH_MIXTRAL,       // Mixtral 8x7B, 8x22B
    BRAIDED_ARCH_PHI,           // Phi-3, Phi-4
    BRAIDED_ARCH_QWEN,          // Qwen2, Qwen2.5
    BRAIDED_ARCH_GEMMA,         // Gemma, Gemma2
    BRAIDED_ARCH_MISTRAL,       // Mistral, Mistral-Nemo
    BRAIDED_ARCH_COMMAND_R,     // Cohere Command-R
    BRAIDED_ARCH_STABLELM,      // StableLM
    BRAIDED_ARCH_COUNT
} BraidedArchitecture;

/*===========================================================================
 * BACKEND TYPES
 *=========================================================================*/
typedef enum BraidedBackend {
    BRAIDED_BACKEND_AUTO = 0,
    BRAIDED_BACKEND_CPU,
    BRAIDED_BACKEND_CUDA,
    BRAIDED_BACKEND_VULKAN,
    BRAIDED_BACKEND_METAL,
    BRAIDED_BACKEND_HYBRID      // CPU + GPU split
} BraidedBackend;

/*===========================================================================
 * STATUS CODES
 *=========================================================================*/
typedef enum BraidedStatus {
    BRAIDED_OK = 0,
    BRAIDED_ERROR_NOT_INITIALIZED,
    BRAIDED_ERROR_INVALID_PARAMS,
    BRAIDED_ERROR_FILE_NOT_FOUND,
    BRAIDED_ERROR_INVALID_FORMAT,
    BRAIDED_ERROR_UNSUPPORTED_ARCH,
    BRAIDED_ERROR_MEMORY,
    BRAIDED_ERROR_WARMUP_FAILED,
    BRAIDED_ERROR_BACKEND_INIT,
    BRAIDED_ERROR_INFERENCE
} BraidedStatus;

/*===========================================================================
 * MODEL CONFIGURATION
 *=========================================================================*/
typedef struct BraidedModelConfig {
    WCHAR       modelPath[BRAIDED_MAX_MODEL_PATH];
    uint32_t    numBraids;          // 2-64, auto-detected if 0
    uint32_t    shardCount;         // Number of shards
    uint32_t    cacheSizeGB;        // RAM cache size
    uint32_t    contextLength;      // Max context
    BraidedBackend backend;
    BOOL        useNVMe;              // Enable hybrid memory
    BOOL        enableWarmup;         // Pre-fault memory
    BOOL        demandPaging;         // Load weights on-demand
    void*       userData;
} BraidedModelConfig;

/*===========================================================================
 * MODEL INFO
 *=========================================================================*/
typedef struct BraidedModelInfo {
    BraidedArchitecture arch;
    WCHAR       name[256];
    uint32_t    numLayers;
    uint32_t    numExperts;
    uint32_t    numHeads;
    uint32_t    headDim;
    uint32_t    hiddenDim;
    uint32_t    vocabSize;
    uint64_t    totalParams;
    uint64_t    fileSizeBytes;
    uint32_t    quantizationBits;
    BOOL        usesMLA;            // Multi-head Latent Attention
    BOOL        usesGQA;            // Grouped Query Attention
    BOOL        usesMoE;            // Mixture of Experts
} BraidedModelInfo;

/*===========================================================================
 * MODEL HANDLE
 *=========================================================================*/
typedef struct BraidedModelContext* BraidedModelHandle;

/*===========================================================================
 * INFERENCE REQUEST/RESPONSE
 *=========================================================================*/
typedef struct BraidedInferenceRequest {
    const char* context;            // UTF-8 prompt
    uint32_t    contextLen;
    uint32_t    maxTokens;
    float       temperature;
    float       topP;
    uint32_t    topK;
    uint32_t    seed;
    void*       userData;
} BraidedInferenceRequest;

typedef struct BraidedInferenceResponse {
    BraidedStatus status;
    char*       text;               // Generated text (caller frees)
    uint32_t    textLen;
            float       confidence;
    uint32_t    tokensGenerated;
    double      generationTimeMs;
} BraidedInferenceResponse;

/*===========================================================================
 * CALLBACKS
 *=========================================================================*/
typedef void (*BraidedProgressCallback)(
    float percentComplete,
    const WCHAR* stage,
    void* userData
);

typedef void (*BraidedTokenCallback)(
    const char* token,
    uint32_t tokenIndex,
    BOOL isComplete,
    void* userData
);

/*===========================================================================
 * LIFECYCLE FUNCTIONS
 *===========================================================================*/

/* Initialize the Braided Model Loader
 * Must be called before any other functions */
BraidedStatus BraidedModelLoader_Initialize(void);

/* Shutdown and cleanup */
void BraidedModelLoader_Shutdown(void);

/* Check if loader is ready */
BOOL BraidedModelLoader_IsReady(void);

/*===========================================================================
 * MODEL LOADING
 *===========================================================================*/

/* Load a model with automatic architecture detection and braiding
 * 
 * This is the main entry point. It will:
 *   1. Detect architecture from GGUF metadata
 *   2. Calculate optimal braiding configuration
 *   3. Map model into memory (with optional demand paging)
 *   4. Run WarmupEngine if enabled
 *   5. Return a handle for inference
 */
BraidedStatus BraidedModelLoader_LoadModel(
    const BraidedModelConfig* config,
    BraidedModelHandle* outHandle,
    BraidedProgressCallback progressCb
);

/* Unload a model and free resources */
void BraidedModelLoader_UnloadModel(BraidedModelHandle handle);

/* Get model information */
BraidedStatus BraidedModelLoader_GetModelInfo(
    BraidedModelHandle handle,
    BraidedModelInfo* outInfo
);

/* Check if model is loaded and ready */
BOOL BraidedModelLoader_IsModelReady(BraidedModelHandle handle);

/*===========================================================================
 * INFERENCE
 *===========================================================================*/

/* Synchronous inference (blocking) */
BraidedStatus BraidedModelLoader_InferSync(
    BraidedModelHandle handle,
    const BraidedInferenceRequest* request,
    BraidedInferenceResponse* response
);

/* Asynchronous inference (non-blocking) */
BraidedStatus BraidedModelLoader_InferAsync(
    BraidedModelHandle handle,
    const BraidedInferenceRequest* request,
    BraidedTokenCallback tokenCb,
    void* completeUserData
);

/* Cancel ongoing inference */
void BraidedModelLoader_CancelInference(BraidedModelHandle handle);

/*===========================================================================
 * UTILITY FUNCTIONS
 *===========================================================================*/

/* Get last error message */
const WCHAR* BraidedModelLoader_GetLastError(void);

/* Get version string */
const WCHAR* BraidedModelLoader_GetVersion(void);

/* Auto-detect optimal configuration for a model */
BraidedStatus BraidedModelLoader_AutoConfig(
    const WCHAR* modelPath,
    BraidedModelConfig* outConfig
);

/* Calculate memory requirements */
uint64_t BraidedModelLoader_CalculateMemoryRequirement(
    const BraidedModelConfig* config,
    const BraidedModelInfo* info
);

/* Get supported architectures */
const WCHAR** BraidedModelLoader_GetSupportedArchitectures(void);

#ifdef __cplusplus
}
#endif

/* E> End of BraidedModelLoader.h <3 */
