/*===========================================================================
 * SovereignBraidedLoader.cpp
 * Implementation of Braided Streaming Loader
 * 
 * Parallel shard loading with rotating cylinder for 671B+ models
 *===========================================================================*/

#include "SovereignBraidedLoader.h"
#include <vector>
#include <algorithm>
#include <atomic>

/*===========================================================================
 * INTERNAL STATE
 *=========================================================================*/

typedef struct SBL_Internal {
    SBL_StreamingContext    ctx;
    std::atomic<BOOL>       loadingComplete;
    std::atomic<BOOL>       shutdownRequested;
    HANDLE                  hLoadThread[SBL_MAX_SHARDS];
    CRITICAL_SECTION        cylinderLock;
    CRITICAL_SECTION        statsLock;
    SBL_Statistics          stats;
    LARGE_INTEGER           perfFreq;
} SBL_Internal;

static SBL_Internal g_SBL = {0};

/*===========================================================================
 * HELPER FUNCTIONS
 *=========================================================================*/

static double SBL_GetElapsedMs(LARGE_INTEGER start, LARGE_INTEGER end) {
    return ((double)(end.QuadPart - start.QuadPart) * 1000.0) / g_SBL.perfFreq.QuadPart;
}

static DWORD WINAPI SBL_ShardLoaderThread(LPVOID param) {
    SBL_BraidDescriptor* shard = (SBL_BraidDescriptor*)param;
    if (!shard) return 1;
    
    LARGE_INTEGER startTime, endTime;
    QueryPerformanceCounter(&startTime);
    
    /* Open shard file */
    shard->hFile = CreateFileW(shard->shardPath, GENERIC_READ, FILE_SHARE_READ,
                                NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (shard->hFile == INVALID_HANDLE_VALUE) {
        shard->ready = FALSE;
        return 1;
    }
    
    /* Create file mapping */
    shard->hMapping = CreateFileMapping(shard->hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!shard->hMapping) {
        CloseHandle(shard->hFile);
        shard->hFile = INVALID_HANDLE_VALUE;
        shard->ready = FALSE;
        return 1;
    }
    
    /* Map view - but only partially for large shards */
    SIZE_T mapSize = (SIZE_T)min((uint64_t)SBL_SHARD_BUFFER_SIZE * 1024 * 1024, shard->shardSize);
    shard->pMappedView = MapViewOfFile(shard->hMapping, FILE_MAP_READ, 0, 0, mapSize);
    
    QueryPerformanceCounter(&endTime);
    
    EnterCriticalSection(&g_SBL.statsLock);
    g_SBL.stats.bytesReadFromDisk += mapSize;
    g_SBL.stats.layerLoads++;
    LeaveCriticalSection(&g_SBL.statsLock);
    
    shard->ready = TRUE;
    return 0;
}

/*===========================================================================
 * LIFECYCLE IMPLEMENTATION
 *===========================================================================*/

BOOL SBL_Initialize(SBL_StreamingContext* ctx, uint64_t memoryBudgetMB) {
    if (!ctx) return FALSE;
    
    ZeroMemory(&g_SBL, sizeof(g_SBL));
    ZeroMemory(ctx, sizeof(SBL_StreamingContext));
    
    QueryPerformanceFrequency(&g_SBL.perfFreq);
    InitializeCriticalSection(&g_SBL.cylinderLock);
    InitializeCriticalSection(&g_SBL.statsLock);
    
    /* Create dedicated heap for loader */
    ctx->hHeap = HeapCreate(0, 1024 * 1024 * 64, memoryBudgetMB * 1024 * 1024);
    if (!ctx->hHeap) return FALSE;
    
    ctx->maxMemoryBudget = memoryBudgetMB * 1024 * 1024;
    ctx->totalLoadedBytes = 0;
    ctx->shardCount = 0;
    ctx->activeShardCount = 0;
    
    /* Initialize cylinder */
    ZeroMemory(&ctx->cylinder, sizeof(SBL_CylinderState));
    for (int i = 0; i < SBL_CYLINDER_LAYERS; i++) {
        ctx->cylinder.activeLayers[i] = 0xFFFFFFFF; /* Invalid layer */
    }
    
    g_SBL.loadingComplete = FALSE;
    g_SBL.shutdownRequested = FALSE;
    
    CopyMemory(&g_SBL.ctx, ctx, sizeof(SBL_StreamingContext));
    
    return TRUE;
}

void SBL_Shutdown(SBL_StreamingContext* ctx) {
    if (!ctx) return;
    
    g_SBL.shutdownRequested = TRUE;
    
    /* Wait for all loader threads */
    for (uint32_t i = 0; i < ctx->shardCount; i++) {
        if (g_SBL.hLoadThread[i]) {
            WaitForSingleObject(g_SBL.hLoadThread[i], 5000);
            CloseHandle(g_SBL.hLoadThread[i]);
        }
    }
    
    /* Cleanup shards */
    for (uint32_t i = 0; i < ctx->shardCount; i++) {
        SBL_BraidDescriptor* shard = &ctx->shards[i];
        if (shard->pMappedView) {
            UnmapViewOfFile(shard->pMappedView);
            shard->pMappedView = NULL;
        }
        if (shard->hMapping) {
            CloseHandle(shard->hMapping);
            shard->hMapping = NULL;
        }
        if (shard->hFile != INVALID_HANDLE_VALUE) {
            CloseHandle(shard->hFile);
            shard->hFile = INVALID_HANDLE_VALUE;
        }
    }
    
    /* Destroy heap */
    if (ctx->hHeap) {
        HeapDestroy(ctx->hHeap);
        ctx->hHeap = NULL;
    }
    
    DeleteCriticalSection(&g_SBL.cylinderLock);
    DeleteCriticalSection(&g_SBL.statsLock);
    
    ZeroMemory(&g_SBL, sizeof(g_SBL));
}

/*===========================================================================
 * BRAID MANAGEMENT
 *===========================================================================*/

BOOL SBL_AddShard(SBL_StreamingContext* ctx, const WCHAR* shardPath,
                  uint32_t layerStart, uint32_t layerEnd) {
    if (!ctx || ctx->shardCount >= SBL_MAX_SHARDS) return FALSE;
    
    SBL_BraidDescriptor* shard = &ctx->shards[ctx->shardCount];
    ZeroMemory(shard, sizeof(SBL_BraidDescriptor));
    
    StringCchCopyW(shard->shardPath, MAX_PATH, shardPath);
    shard->layerStart = layerStart;
    shard->layerEnd = layerEnd;
    shard->braidIndex = ctx->shardCount;
    shard->hFile = INVALID_HANDLE_VALUE;
    shard->ready = FALSE;
    
    /* Get file size */
    WIN32_FILE_ATTRIBUTE_DATA fad;
    if (GetFileAttributesExW(shardPath, GetFileExInfoStandard, &fad)) {
        LARGE_INTEGER size;
        size.HighPart = fad.nFileSizeHigh;
        size.LowPart = fad.nFileSizeLow;
        shard->shardSize = size.QuadPart;
    } else {
        return FALSE;
    }
    
    ctx->shardCount++;
    return TRUE;
}

BOOL SBL_StartBraidLoad(SBL_StreamingContext* ctx) {
    if (!ctx) return FALSE;
    
    /* Start loader thread for each shard */
    for (uint32_t i = 0; i < ctx->shardCount; i++) {
        g_SBL.hLoadThread[i] = CreateThread(NULL, 0, SBL_ShardLoaderThread,
                                            &ctx->shards[i], 0, NULL);
        if (!g_SBL.hLoadThread[i]) return FALSE;
    }
    
    return TRUE;
}

BOOL SBL_WaitForBraidComplete(SBL_StreamingContext* ctx, DWORD timeoutMs) {
    if (!ctx) return FALSE;
    
    HANDLE handles[SBL_MAX_SHARDS];
    DWORD handleCount = 0;
    
    for (uint32_t i = 0; i < ctx->shardCount; i++) {
        if (g_SBL.hLoadThread[i]) {
            handles[handleCount++] = g_SBL.hLoadThread[i];
        }
    }
    
    if (handleCount == 0) return TRUE;
    
    DWORD result = WaitForMultipleObjects(handleCount, handles, TRUE, timeoutMs);
    
    if (result == WAIT_OBJECT_0) {
        g_SBL.loadingComplete = TRUE;
        
        /* Count active shards */
        ctx->activeShardCount = 0;
        for (uint32_t i = 0; i < ctx->shardCount; i++) {
            if (ctx->shards[i].ready) ctx->activeShardCount++;
        }
        
        if (ctx->onBraidComplete) {
            ctx->onBraidComplete(ctx->userData);
        }
        
        return TRUE;
    }
    
    return FALSE;
}

/*===========================================================================
 * CYLINDER OPERATIONS
 *===========================================================================*/

BOOL SBL_RotateToLayer(SBL_StreamingContext* ctx, uint32_t targetLayer) {
    if (!ctx) return FALSE;
    
    EnterCriticalSection(&g_SBL.cylinderLock);
    
    /* Check if layer is already active */
    for (int i = 0; i < SBL_CYLINDER_LAYERS; i++) {
        if (ctx->cylinder.activeLayers[i] == targetLayer) {
            ctx->cylinder.hitCount++;
            ctx->cylinder.hitRate = (float)ctx->cylinder.hitCount / 
                                   (ctx->cylinder.hitCount + ctx->cylinder.missCount) * 100.0f;
            LeaveCriticalSection(&g_SBL.cylinderLock);
            return TRUE;
        }
    }
    
    /* Cache miss - need to load layer */
    ctx->cylinder.missCount++;
    
    /* Find which shard contains this layer */
    SBL_BraidDescriptor* targetShard = NULL;
    for (uint32_t i = 0; i < ctx->shardCount; i++) {
        if (targetLayer >= ctx->shards[i].layerStart && 
            targetLayer <= ctx->shards[i].layerEnd) {
            targetShard = &ctx->shards[i];
            break;
        }
    }
    
    if (!targetShard || !targetShard->ready) {
        LeaveCriticalSection(&g_SBL.cylinderLock);
        return FALSE;
    }
    
    /* Evict oldest layer from cylinder */
    uint32_t evictIdx = ctx->cylinder.cylinderPosition % SBL_CYLINDER_LAYERS;
    uint32_t oldLayer = ctx->cylinder.activeLayers[evictIdx];
    
    if (oldLayer != 0xFFFFFFFF && ctx->onLayerEvicted) {
        ctx->onLayerEvicted(oldLayer, ctx->userData);
    }
    
    /* Load new layer */
    ctx->cylinder.activeLayers[evictIdx] = targetLayer;
    ctx->cylinder.cylinderPosition++;
    
    EnterCriticalSection(&g_SBL.statsLock);
    g_SBL.stats.layerLoads++;
    LeaveCriticalSection(&g_SBL.statsLock);
    
    if (ctx->onLayerLoaded) {
        ctx->onLayerLoaded(targetLayer, ctx->userData);
    }
    
    LeaveCriticalSection(&g_SBL.cylinderLock);
    return TRUE;
}

void* SBL_GetLayerWeights(SBL_StreamingContext* ctx, uint32_t layerId, 
                          uint64_t* outSize) {
    if (!ctx || !outSize) return NULL;
    
    /* Ensure layer is in cylinder */
    if (!SBL_IsLayerActive(ctx, layerId)) {
        if (!SBL_RotateToLayer(ctx, layerId)) return NULL;
    }
    
    /* Find shard containing layer */
    for (uint32_t i = 0; i < ctx->shardCount; i++) {
        SBL_BraidDescriptor* shard = &ctx->shards[i];
        if (layerId >= shard->layerStart && layerId <= shard->layerEnd && shard->ready) {
            /* Calculate offset within shard */
            uint64_t layerOffset = ((uint64_t)(layerId - shard->layerStart) * shard->shardSize) / 
                                  (shard->layerEnd - shard->layerStart + 1);
            
            *outSize = shard->shardSize / (shard->layerEnd - shard->layerStart + 1);
            
            if (shard->pMappedView) {
                return (void*)((uint8_t*)shard->pMappedView + layerOffset);
            }
        }
    }
    
    return NULL;
}

BOOL SBL_IsLayerActive(SBL_StreamingContext* ctx, uint32_t layerId) {
    if (!ctx) return FALSE;
    
    EnterCriticalSection(&g_SBL.cylinderLock);
    for (int i = 0; i < SBL_CYLINDER_LAYERS; i++) {
        if (ctx->cylinder.activeLayers[i] == layerId) {
            LeaveCriticalSection(&g_SBL.cylinderLock);
            return TRUE;
        }
    }
    LeaveCriticalSection(&g_SBL.cylinderLock);
    return FALSE;
}

/*===========================================================================
 * BRAIDED INFERENCE
 *===========================================================================*/

BOOL SBL_ExecuteBraidedForward(SBL_StreamingContext* ctx,
                               uint32_t startLayer, uint32_t endLayer,
                               SBL_InferenceCallback callback) {
    if (!ctx || !callback) return FALSE;
    
    for (uint32_t layer = startLayer; layer <= endLayer; layer++) {
        /* Prefetch ahead */
        if (layer + SBL_PREFETCH_AHEAD <= endLayer) {
            SBL_RotateToLayer(ctx, layer + SBL_PREFETCH_AHEAD);
        }
        
        /* Get layer weights */
        uint64_t weightSize = 0;
        void* weights = SBL_GetLayerWeights(ctx, layer, &weightSize);
        if (!weights) return FALSE;
        
        /* Execute callback for this layer */
        callback(layer, weights, weightSize, ctx->userData);
        
        EnterCriticalSection(&g_SBL.statsLock);
        g_SBL.stats.bytesReadFromCache += weightSize;
        LeaveCriticalSection(&g_SBL.statsLock);
    }
    
    return TRUE;
}

/*===========================================================================
 * STATISTICS
 *===========================================================================*/

BOOL SBL_GetStatistics(SBL_StreamingContext* ctx, SBL_Statistics* outStats) {
    if (!ctx || !outStats) return FALSE;
    
    EnterCriticalSection(&g_SBL.statsLock);
    CopyMemory(outStats, &g_SBL.stats, sizeof(SBL_Statistics));
    outStats->activeShards = ctx->activeShardCount;
    outStats->memoryUsed = ctx->totalLoadedBytes;
    outStats->cacheHitRate = ctx->cylinder.hitRate;
    LeaveCriticalSection(&g_SBL.statsLock);
    
    return TRUE;
}

/* E> End of SovereignBraidedLoader.cpp <3 */
