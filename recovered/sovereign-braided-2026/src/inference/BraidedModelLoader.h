/*===========================================================================
 * BraidedModelLoader.h
 * Universal Braided Loading for ALL Model Architectures
 * 
 * Auto-detects: Llama, DeepSeek, Qwen, Mixtral, Phi, Gemma, etc.
 * Supports: Q4, Q8, F16, F32 quantization
 * Scales: 7B to 1.6T+ parameters
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
#define BRAID_MAX_SHARDS        16
#define BRAID_MAX_LAYERS        256
#define BRAID_MAX_STREAMS       8
#define BRAID_CACHE_SLOTS       64
#define BRAID_PREFETCH_DISTANCE 4

/*===========================================================================
 * MODEL ARCHITECTURE DETECTION
 *=========================================================================*/
typedef enum BraidedModelType {
    BRAID_MODEL_UNKNOWN = 0,
    BRAID_MODEL_LLAMA,          // Llama 2/3, Mistral, etc.
    BRAID_MODEL_DEEPSEEK,       // DeepSeek V2/V3 (MLA attention)
    BRAID_MODEL_QWEN,           // Qwen 1.5/2/2.5
    BRAID_MODEL_MIXTRAL,        // Mixtral 8x7B/8x22B (MoE)
    BRAID_MODEL_PHI,            // Phi-3/4
    BRAID_MODEL_GEMMA,          // Gemma 2/3
    BRAID_MODEL_COMMAND_R,      // Cohere Command R
    BRAID_MODEL_STABLELM,       // StableLM
    BRAID_MODEL_COUNT
} BraidedModelType;

typedef enum BraidedQuantType {
    BRAID_QUANT_UNKNOWN = 0,
    BRAID_QUANT_Q4_0,           // 4-bit, block size 32
    BRAID_QUANT_Q4_1,
    BRAID_QUANT_Q4_K,           // K-quants
    BRAID_QUANT_Q4_K_S,
    BRAID_QUANT_Q4_K_M,
    BRAID_QUANT_Q5_0,
    BRAID_QUANT_Q5_1,
    BRAID_QUANT_Q5_K,
    BRAID_QUANT_Q6_K,
    BRAID_QUANT_Q8_0,           // 8-bit
    BRAID_QUANT_Q8_K,
    BRAID_QUANT_F16,            // Half precision
    BRAID_QUANT_F32,            // Full precision
    BRAID_QUANT_COUNT
} BraidedQuantType;

/*===========================================================================
 * MODEL CAPABILITIES
 *=========================================================================*/
typedef struct BraidedModelCaps {
    // Architecture
    BraidedModelType  arch;
    BraidedQuantType  quant;
    uint32_t          version;
    
    // Dimensions
    uint32_t          vocab_size;
    uint32_t          context_length;
    uint32_t          embedding_dim;
    uint32_t          num_layers;
    uint32_t          num_heads;
    uint32_t          num_kv_heads;
    uint32_t          head_dim;
    uint32_t          ffn_dim;
    
    // MoE specific
    uint32_t          num_experts;
    uint32_t          experts_per_token;
    bool              uses_moe;
    
    // Attention type
    bool              uses_gqa;       // Grouped Query Attention
    bool              uses_mla;       // Multi-head Latent Attention (DeepSeek)
    bool              uses_alibi;     // ALiBi position encoding
    bool              uses_rope;      // RoPE position encoding
    
    // Size info
    uint64_t          total_params;
    uint64_t          active_params;
    uint64_t          file_size;
    uint32_t          tensor_count;
    
    // Braiding parameters (auto-calculated)
    uint32_t          braid_count;
    uint32_t          shards_per_braid;
    uint32_t          layers_per_shard;
    uint64_t          shard_size;
    uint32_t          prefetch_window;
} BraidedModelCaps;

/*===========================================================================
 * BRAIDED LOADER STATE
 *=========================================================================*/
typedef struct BraidedShard {
    uint32_t          shard_id;
    uint64_t          file_offset;
    uint64_t          size;
    uint32_t          start_layer;
    uint32_t          end_layer;
    HANDLE            hFile;
    HANDLE            hMapping;
    void*             mapped_addr;
    bool              resident;
    uint64_t          last_access;
    uint32_t          access_count;
} BraidedShard;

typedef struct BraidedStream {
    uint32_t          stream_id;
    uint32_t          current_layer;
    uint32_t          direction;        // 0=up, 1=down
    BraidedShard*     active_shard;
    uint64_t          bytes_loaded;
    uint64_t          bytes_evicted;
    uint32_t          cache_hits;
    uint32_t          cache_misses;
} BraidedStream;

typedef struct BraidedCache {
    uint32_t          slot_count;
    BraidedShard*     slots[BRAID_CACHE_SLOTS];
    uint64_t          total_resident;
    uint64_t          max_resident;
    uint32_t          eviction_policy;  // 0=LRU, 1=LFU
} BraidedCache;

typedef struct BraidedLoader {
    // Model info
    BraidedModelCaps  caps;
    WCHAR             model_path[MAX_PATH];
    
    // Sharding
    uint32_t          num_shards;
    BraidedShard      shards[BRAID_MAX_SHARDS];
    
    // Streams
    uint32_t          num_streams;
    BraidedStream     streams[BRAID_MAX_STREAMS];
    
    // Cache
    BraidedCache      cache;
    
    // Threading
    HANDLE            hPrefetchThread;
    HANDLE            hEvictionThread;
    HANDLE            hCompletionPort;
    CRITICAL_SECTION  cs;
    
    // Statistics
    uint64_t          total_bytes_read;
    uint64_t          total_bytes_evicted;
    uint32_t          total_prefetches;
    uint32_t          prefetch_hits;
    uint32_t          prefetch_misses;
    double            avg_load_latency_ms;
    
    // State
    bool              initialized;
    bool              running;
    uint64_t          start_time;
} BraidedLoader;

/*===========================================================================
 * LIFECYCLE
 *=========================================================================*/

/* Initialize braided loader for a model
 * Automatically detects architecture and calculates optimal braiding
 * Returns: true on success, false on failure */
bool BraidedLoader_Init(BraidedLoader* loader, const WCHAR* model_path);

/* Shutdown and cleanup all resources */
void BraidedLoader_Shutdown(BraidedLoader* loader);

/* Check if loader is ready */
bool BraidedLoader_IsReady(const BraidedLoader* loader);

/*===========================================================================
 * MODEL DETECTION
 *=========================================================================*/

/* Auto-detect model architecture from GGUF metadata
 * Returns: detected model type */
BraidedModelType BraidedLoader_DetectModel(const WCHAR* model_path);

/* Get human-readable model type name */
const char* BraidedLoader_GetModelTypeName(BraidedModelType type);

/* Get human-readable quantization name */
const char* BraidedLoader_GetQuantTypeName(BraidedQuantType type);

/*===========================================================================
 * BRAIDING CONFIGURATION
 *=========================================================================*/

/* Calculate optimal braiding parameters based on:
 * - Model size and architecture
 * - Available system RAM
 * - Storage bandwidth
 * Returns: true if configuration is viable */
bool BraidedLoader_CalculateBraiding(BraidedLoader* loader, 
                                     uint64_t available_ram,
                                     uint64_t storage_bandwidth_mbps);

/* Get recommended braiding for a model size
 * Pre-configured for common model sizes */
bool BraidedLoader_GetRecommendedBraiding(uint64_t model_size_gb,
                                          uint32_t* out_braid_count,
                                          uint32_t* out_shards_per_braid,
                                          uint64_t* out_cache_size);

/*===========================================================================
 * LAYER ACCESS
 *=========================================================================*/

/* Load a specific layer into memory (demand paging)
 * Returns: pointer to layer data, NULL on failure */
void* BraidedLoader_LoadLayer(BraidedLoader* loader, uint32_t layer_id);

/* Prefetch layers for upcoming computation
 * Non-blocking, returns immediately */
void BraidedLoader_PrefetchLayers(BraidedLoader* loader, 
                                   uint32_t start_layer,
                                   uint32_t count);

/* Release a layer from resident memory
 * Mark as evictable */
void BraidedLoader_ReleaseLayer(BraidedLoader* loader, uint32_t layer_id);

/* Check if layer is resident in memory */
bool BraidedLoader_IsLayerResident(const BraidedLoader* loader, uint32_t layer_id);

/*===========================================================================
 * STREAMING
 *=========================================================================*/

/* Create a bidirectional stream for layer access
 * Used for autoregressive generation */
uint32_t BraidedLoader_CreateStream(BraidedLoader* loader, 
                                     uint32_t start_layer,
                                     int direction);

/* Advance stream to next layer
 * Automatically handles shard boundaries and prefetching */
void* BraidedLoader_StreamNext(BraidedLoader* loader, uint32_t stream_id);

/* Reset stream position */
void BraidedLoader_ResetStream(BraidedLoader* loader, 
                                uint32_t stream_id,
                                uint32_t layer_id);

/* Destroy stream */
void BraidedLoader_DestroyStream(BraidedLoader* loader, uint32_t stream_id);

/*===========================================================================
 * CACHE MANAGEMENT
 *=========================================================================*/

/* Set cache size limit (bytes) */
void BraidedLoader_SetCacheLimit(BraidedLoader* loader, uint64_t max_bytes);

/* Get current cache statistics */
void BraidedLoader_GetCacheStats(const BraidedLoader* loader,
                                   uint64_t* out_resident,
                                   uint64_t* out_max,
                                   uint32_t* out_hits,
                                   uint32_t* out_misses);

/* Force eviction of all non-active layers */
void BraidedLoader_FlushCache(BraidedLoader* loader);

/*===========================================================================
 * STATISTICS
 *=========================================================================*/

/* Get loader performance statistics */
typedef struct BraidedLoaderStats {
    uint64_t    total_bytes_read;
    uint64_t    total_bytes_evicted;
    uint32_t    total_prefetches;
    uint32_t    prefetch_hits;
    uint32_t    prefetch_misses;
    double      avg_load_latency_ms;
    double      hit_rate_percent;
    uint32_t    active_layers;
    uint32_t    resident_shards;
    uint64_t    cache_utilization_bytes;
} BraidedLoaderStats;

void BraidedLoader_GetStats(const BraidedLoader* loader, BraidedLoaderStats* stats);

/* Reset statistics counters */
void BraidedLoader_ResetStats(BraidedLoader* loader);

/*===========================================================================
 * UNIVERSAL MODEL SUPPORT
 *=========================================================================*/

/* Pre-configured braiding profiles for common models */
typedef struct BraidedProfile {
    const char*       name;
    uint64_t          min_size_gb;
    uint64_t          max_size_gb;
    uint32_t          default_braids;
    uint32_t          default_shards;
    uint64_t          cache_size_gb;
    const char*       notes;
} BraidedProfile;

/* Get profile for a model size */
const BraidedProfile* BraidedLoader_GetProfile(uint64_t model_size_gb);

/* Built-in profiles */
extern const BraidedProfile BRAID_PROFILE_7B;
extern const BraidedProfile BRAID_PROFILE_13B;
extern const BraidedProfile BRAID_PROFILE_30B;
extern const BraidedProfile BRAID_PROFILE_70B;
extern const BraidedProfile BRAID_PROFILE_180B;
extern const BraidedProfile BRAID_PROFILE_400B;
extern const BraidedProfile BRAID_PROFILE_671B;
extern const BraidedProfile BRAID_PROFILE_1T;

#ifdef __cplusplus
}
#endif

/* E> End of BraidedModelLoader.h <3 */
