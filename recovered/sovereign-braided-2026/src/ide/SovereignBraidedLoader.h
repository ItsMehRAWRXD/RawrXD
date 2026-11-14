/*===========================================================================
 * SovereignBraidedLoader.h
 * Braided Streaming Loader for 671B+ Parameter Models
 * 
 * Implements interleaved shard loading with rotating cylinder architecture.
 * Enables parallel weight streams and on-demand parameter activation.
 *===========================================================================*/

#pragma once

#include <windows.h>
#include <cstdint>
#include <functional>

#ifdef __cplusplus
extern "C" {
#endif

/*===========================================================================
 * BRAIDING CONFIGURATION
 *=========================================================================*/
#define SBL_MAX_SHARDS              8       /* Maximum parallel shards */
#define SBL_SHARD_BUFFER_SIZE       256     /* MB per shard buffer */
#define SBL_BRAID_INTERLEAVE        4       /* Interleave factor */
#define SBL_CYLINDER_LAYERS         4       /* Active layers in rotation */
#define SBL_PREFETCH_AHEAD          2       /* Layers to prefetch */

/*===========================================================================
 * BRAID DESCRIPTOR
 * Describes a single model shard in the braid
 *=========================================================================*/
typedef struct SBL_BraidDescriptor {
    WCHAR       shardPath[MAX_PATH];        /* Path to shard file */
    uint64_t    shardOffset;                /* Offset in combined model */
    uint64_t    shardSize;                  /* Size of this shard */
    uint32_t    layerStart;                 /* First layer in shard */
    uint32_t    layerEnd;                   /* Last layer in shard */
    uint32_t    braidIndex;                 /* Position in braid */
    HANDLE      hFile;                      /* File handle */
    HANDLE      hMapping;                   /* Memory mapping */
    void*       pMappedView;                /* Mapped view pointer */
    volatile BOOL ready;                    /* Shard loaded flag */
} SBL_BraidDescriptor;

/*===========================================================================
 * CYLINDER STATE
 * Tracks active layers in rotating window
 *=========================================================================*/
typedef struct SBL_CylinderState {
    uint32_t    activeLayers[SBL_CYLINDER_LAYERS];  /* Currently loaded layer IDs */
    uint32_t    cylinderPosition;                   /* Current rotation position */
    uint64_t    hitCount;                           /* Cache hits */
    uint64_t    missCount;                          /* Cache misses (triggers load) */
    float       hitRate;                            /* Cache hit rate % */
} SBL_CylinderState;

/*===========================================================================
 * STREAMING CONTEXT
 *=========================================================================*/
typedef struct SBL_StreamingContext {
    /* Braiding */
    SBL_BraidDescriptor shards[SBL_MAX_SHARDS];
    uint32_t            shardCount;
    uint32_t            activeShardCount;
    
    /* Cylinder */
    SBL_CylinderState   cylinder;
    
    /* Memory management */
    HANDLE              hHeap;              /* Dedicated loader heap */
    uint64_t            totalLoadedBytes;   /* Total bytes in RAM */
    uint64_t            maxMemoryBudget;      /* Memory limit */
    
    /* Callbacks */
    void*               userData;
    void (*onLayerLoaded)(uint32_t layerId, void* userData);
    void (*onLayerEvicted)(uint32_t layerId, void* userData);
    void (*onBraidComplete)(void* userData);
} SBL_StreamingContext;

/*===========================================================================
 * LIFECYCLE
 *=========================================================================*/

/* Initialize braided loader with memory budget */
BOOL SBL_Initialize(SBL_StreamingContext* ctx, uint64_t memoryBudgetMB);

/* Shutdown and cleanup all resources */
void SBL_Shutdown(SBL_StreamingContext* ctx);

/*===========================================================================
 * BRAID MANAGEMENT
 *=========================================================================*/

/* Add a shard to the braid */
BOOL SBL_AddShard(SBL_StreamingContext* ctx, const WCHAR* shardPath, 
                  uint32_t layerStart, uint32_t layerEnd);

/* Start parallel loading of all shards */
BOOL SBL_StartBraidLoad(SBL_StreamingContext* ctx);

/* Wait for braid to be fully loaded */
BOOL SBL_WaitForBraidComplete(SBL_StreamingContext* ctx, DWORD timeoutMs);

/*===========================================================================
 * CYLINDER OPERATIONS
 *=========================================================================*/

/* Rotate cylinder to bring layer into active set */
BOOL SBL_RotateToLayer(SBL_StreamingContext* ctx, uint32_t targetLayer);

/* Get pointer to layer weights (triggers load if not in cylinder) */
void* SBL_GetLayerWeights(SBL_StreamingContext* ctx, uint32_t layerId, 
                          uint64_t* outSize);

/* Prefetch upcoming layers */
BOOL SBL_PrefetchLayers(SBL_StreamingContext* ctx, uint32_t startLayer, 
                        uint32_t count);

/* Check if layer is in active cylinder */
BOOL SBL_IsLayerActive(SBL_StreamingContext* ctx, uint32_t layerId);

/*===========================================================================
 * BRAIDED INFERENCE
 *=========================================================================*/

/* Execute forward pass with braided weight loading */
typedef void (*SBL_InferenceCallback)(uint32_t layerId, void* weights, 
                                      uint64_t size, void* userData);

BOOL SBL_ExecuteBraidedForward(SBL_StreamingContext* ctx, 
                               uint32_t startLayer, uint32_t endLayer,
                               SBL_InferenceCallback callback);

/*===========================================================================
 * STATISTICS
 *=========================================================================*/

typedef struct SBL_Statistics {
    uint64_t    bytesReadFromDisk;
    uint64_t    bytesReadFromCache;
    uint64_t    layerLoads;
    uint64_t    layerEvictions;
    float       averageLoadTimeMs;
    float       cacheHitRate;
    uint32_t    activeShards;
    uint64_t    memoryUsed;
} SBL_Statistics;

BOOL SBL_GetStatistics(SBL_StreamingContext* ctx, SBL_Statistics* outStats);

#ifdef __cplusplus
}
#endif

/* E> End of SovereignBraidedLoader.h <3 */
