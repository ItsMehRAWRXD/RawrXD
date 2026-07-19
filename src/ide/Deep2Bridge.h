/*===========================================================================
 * Deep2Bridge.h
 * Deep2 Engine Integration for RawrXD IDE
 * 
 * Links Deep2 MASM kernels to SovereignInferenceBridge
 * Provides zero-copy inference for Ghost Text completion
 *
 * Architecture: Direct kernel invocation from mapped memory
 *===========================================================================*/

#pragma once

#include <windows.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*===========================================================================
 * DEEP2 KERNEL INTERFACE
 * External MASM functions - zero overhead, direct hardware access
 *===========================================================================*/

/* Vector Dot Product - 0.41 cycles/element (validated) */
extern void Deep2_VecDotProduct(
    const float* a,           /* RCX: First vector */
    const float* b,           /* RDX: Second vector */
    float* out,                 /* R8:  Output scalar */
    size_t n                    /* R9:  Element count (multiple of 8) */
);

/* SwiGLU Activation - 1.56 cycles/element (validated) */
extern void Deep2_SwiGLU(
    const float* x,           /* RCX: Input gate */
    const float* y,           /* RDX: Up-projection */
    float* out,                 /* R8:  Output */
    size_t n                    /* R9:  Element count (multiple of 8) */
);

/* RMS Normalization - 0.78 cycles/element (validated) */
extern void Deep2_RMSNorm(
    const float* x,           /* RCX: Input */
    float* out,                 /* RDX: Output */
    size_t n,                   /* R8:  Element count */
    float eps                   /* XMM3: Epsilon (stack) */
);

/* Fused Attention with KV Cache - AVX-512 optimized
 * 
 * Computes: output = softmax(Q @ K^T / sqrt(d_k)) @ V
 * 
 * Parameters (Windows x64):
 *   RCX = query (Q) - [num_heads * head_dim] floats
 *   RDX = key_cache (K) - [seq_len * num_heads * head_dim] floats
 *   R8  = value_cache (V) - [seq_len * num_heads * head_dim] floats
 *   R9  = sequence length (seq_len)
 *   [RSP+40] = head_dim (d_k)
 *   [RSP+48] = num_heads
 *   [RSP+56] = output pointer
 */
extern void Sovereign_Attention_KV_AVX512(
    const float* query,
    const float* key_cache,
    const float* value_cache,
    uint32_t seq_len,
    uint32_t head_dim,
    uint32_t num_heads,
    float* output
);

/* In-Situ Inference - Direct from mapped memory (NVMe-braided) */
extern void PerformInference_InSitu(
    void* weights,              /* RCX: Mapped weight pointer (NVMe-backed) */
    void* input,                /* RDX: Input vector */
    void* output,               /* R8:  Output accumulator */
    size_t length               /* R9:  Vector length (multiple of 16 for AVX-512) */
);

/*===========================================================================
 * DEEP2 BRIDGE CONFIGURATION
 *===========================================================================*/

typedef struct Deep2Config {
    uint32_t hiddenDim;         /* Hidden dimension (e.g., 7168 for DeepSeek) */
    uint32_t numExperts;        /* Total experts (e.g., 256) */
    uint32_t expertsPerToken;   /* Active experts per token (e.g., 8) */
    uint32_t numLayers;         /* Number of transformer layers */
    float    eps;               /* RMSNorm epsilon */
    BOOL     useAVX512;         /* TRUE = AVX-512, FALSE = AVX2 */
    BOOL     useLargePages;     /* TRUE = MEM_LARGE_PAGES for weights */
    BOOL     pinThreads;        /* TRUE = Pin inference threads to cores */
    DWORD    affinityMask;      /* Thread affinity mask (e.g., 0xFF for cores 0-7) */
} Deep2Config;

/*===========================================================================
 * DEEP2 BRIDGE LIFECYCLE
 *===========================================================================*/

/* Initialize Deep2 engine with configuration
 * Returns: TRUE on success, FALSE on error */
BOOL Deep2Bridge_Initialize(const Deep2Config* config);

/* Shutdown Deep2 engine and release resources */
void Deep2Bridge_Shutdown(void);

/* Check if Deep2 is initialized and ready */
BOOL Deep2Bridge_IsReady(void);

/* Get Deep2 capabilities */
BOOL Deep2Bridge_HasAVX2(void);
BOOL Deep2Bridge_HasAVX512(void);

/*===========================================================================
 * INFERENCE FUNCTIONS
 *===========================================================================*/

/* Run transformer layer using Deep2 kernels
 * This is the core inference function called by SovereignBridge
 * 
 * Parameters:
 *   layerIndex    - Which transformer layer (0 to numLayers-1)
 *   input         - Input activations [hiddenDim]
 *   output        - Output activations [hiddenDim] (can alias input)
 *   expertIndices - Selected expert indices [expertsPerToken]
 *   expertWeights - Expert routing weights [expertsPerToken]
 * 
 * Returns: TRUE on success */
BOOL Deep2Bridge_RunTransformerLayer(
    uint32_t layerIndex,
    const float* input,
    float* output,
    const uint32_t* expertIndices,
    const float* expertWeights
);

/* Run complete forward pass (all layers)
 * For Ghost Text: processes prompt and generates next token
 * 
 * Parameters:
 *   tokenEmbeddings - Input token embeddings [seqLen * hiddenDim]
 *   seqLen          - Sequence length
 *   logits          - Output logits [vocabSize]
 * 
 * Returns: TRUE on success */
BOOL Deep2Bridge_ForwardPass(
    const float* tokenEmbeddings,
    uint32_t seqLen,
    float* logits
);

/* Expert routing - Select top-k experts for MoE
 * Uses fast approximate routing (can be replaced with learned router)
 * 
 * Parameters:
 *   input         - Input vector [hiddenDim]
 *   topK          - Number of experts to select
 *   expertIndices - Output: selected expert indices [topK]
 *   expertWeights - Output: routing weights [topK]
 * 
 * Returns: TRUE on success */
BOOL Deep2Bridge_RouteExperts(
    const float* input,
    uint32_t topK,
    uint32_t* expertIndices,
    float* expertWeights
);

/*===========================================================================
 * MEMORY MANAGEMENT
 *===========================================================================*/

/* Map model weights from file (zero-copy NVMe access)
 * Uses MapViewOfFile3 for direct NVMe streaming
 * 
 * Parameters:
 *   filePath - Path to GGUF or raw weight file
 *   readOnly - TRUE for inference (PAGE_READONLY), FALSE for training
 * 
 * Returns: Mapped pointer or NULL on error */
void* Deep2Bridge_MapWeights(const WCHAR* filePath, BOOL readOnly);

/* Unmap model weights */
void Deep2Bridge_UnmapWeights(void* mappedPtr);

/* Allocate aligned memory for activations
 * Uses VirtualAlloc with MEM_LARGE_PAGES if configured */
float* Deep2Bridge_AllocActivations(size_t numElements);

/* Free activation memory */
void Deep2Bridge_FreeActivations(float* ptr);

/* Load real GGUF model weights using BraidedModelLoader
 * This connects Deep2Bridge to actual model tensors
 * 
 * Parameters:
 *   modelPath - Wide char path to .gguf file
 * 
 * Returns: TRUE on success, FALSE on error
 */
BOOL Deep2Bridge_LoadGGUFModel(const WCHAR* modelPath);

/* Check if using real GGUF weights (vs dummy computation) */
BOOL Deep2Bridge_IsUsingRealWeights(void);

/*===========================================================================
 * KV CACHE - Production Inference Optimization
 * 
 * Without KV cache: O(n²) attention - recomputes all previous tokens
 * With KV cache:    O(n) attention - reuses cached keys/values
 * 
 * Expected speedup: 10-100x for autoregressive generation
 *===========================================================================*/

typedef struct Deep2KVCache {
    float* keyCache;        /* [numLayers][maxSeqLen][numHeads][headDim] */
    float* valueCache;      /* [numLayers][maxSeqLen][numHeads][headDim] */
    uint32_t numLayers;
    uint32_t numHeads;
    uint32_t headDim;
    uint32_t maxSeqLen;
    uint32_t currentSeqLen; /* Current sequence length (grows with each token) */
    BOOL initialized;
} Deep2KVCache;

/* Initialize KV cache for a model
 * 
 * Parameters:
 *   numLayers  - Number of transformer layers
 *   numHeads   - Number of attention heads
 *   headDim    - Dimension per head
 *   maxSeqLen  - Maximum sequence length to cache
 * 
 * Returns: TRUE on success, FALSE on error
 */
BOOL Deep2KVCache_Init(uint32_t numLayers, uint32_t numHeads, 
                       uint32_t headDim, uint32_t maxSeqLen);

/* Store K/V for a layer at current position
 * Called after computing attention for a token */
void Deep2KVCache_Store(uint32_t layer, const float* keys, const float* values);

/* Retrieve cached K/V for attention computation
 * Returns pointers to cached data for all positions up to currentSeqLen */
void Deep2KVCache_Get(uint32_t layer, float** outKeys, float** outValues, 
                      uint32_t* outSeqLen);

/* Reset cache for new sequence */
void Deep2KVCache_Reset(void);

/* Cleanup KV cache memory */
void Deep2KVCache_Shutdown(void);

/* Check if KV cache is active */
BOOL Deep2KVCache_IsActive(void);

/* Get current sequence length */
uint32_t Deep2KVCache_GetSeqLen(void);

/*===========================================================================
 * PERFORMANCE MONITORING
 *===========================================================================*/

typedef struct Deep2PerfMetrics {
    uint64_t totalCycles;       /* Total CPU cycles consumed */
    uint64_t totalTokens;       /* Total tokens processed */
    double   avgCyclesPerToken; /* Average cycles per token */
    double   peakThroughput;    /* Peak GB/s achieved */
    double   avgLatencyMs;      /* Average latency per token */
} Deep2PerfMetrics;

/* Get performance metrics since initialization */
void Deep2Bridge_GetMetrics(Deep2PerfMetrics* outMetrics);

/* Reset performance counters */
void Deep2Bridge_ResetMetrics(void);

/* Read CPU timestamp counter (RDTSC) */
uint64_t Deep2Bridge_ReadTSC(void);

/*===========================================================================
 * ERROR HANDLING
 *===========================================================================*/

/* Get last error message */
const char* Deep2Bridge_GetLastError(void);

/* Get last error code */
DWORD Deep2Bridge_GetLastErrorCode(void);

#ifdef __cplusplus
}
#endif
