// =============================================================================
// sovereign_kv_cache.h
// Phase 20: Memory Optimization & Caching
// Paged attention KV cache for transformer inference
// =============================================================================

#ifndef SOVEREIGN_KV_CACHE_H
#define SOVEREIGN_KV_CACHE_H

#include "sovereign_memory_pool.h"
#include <inttypes.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// =============================================================================
// Configuration
// =============================================================================

#define SOVEREIGN_KV_HEAD_DIM        128     // Attention head dimension
#define SOVEREIGN_KV_MAX_SEQ_LEN     32768   // Maximum sequence length
#define SOVEREIGN_KV_BLOCK_SIZE      256     // Tokens per block
#define SOVEREIGN_KV_MAX_LAYERS      128     // Maximum model layers
#define SOVEREIGN_KV_MAX_HEADS       64      // Maximum attention heads
#define SOVEREIGN_KV_CACHE_ALIGNMENT 64      // AVX-512 alignment

// =============================================================================
// Opaque Handles
// =============================================================================

typedef struct SovereignKVCache* SovereignKVCacheHandle;
typedef struct SovereignKVCacheBlock* SovereignKVCacheBlockHandle;
typedef struct SovereignKVCacheManager* SovereignKVCacheManagerHandle;

// =============================================================================
// Block State
// =============================================================================

typedef enum {
    SOVEREIGN_KV_BLOCK_FREE = 0,      // Available for allocation
    SOVEREIGN_KV_BLOCK_ALLOCATED,     // In use by a sequence
    SOVEREIGN_KV_BLOCK_COMPUTED,      // KV values computed
    SOVEREIGN_KV_BLOCK_EVICTING       // Being evicted
} SovereignKVBlockState;

// =============================================================================
// Cache Block Metadata
// =============================================================================

typedef struct SovereignKVCacheBlock {
    uint32_t block_id;                // Unique block identifier
    uint32_t ref_count;               // Reference count (shared blocks)
    uint32_t num_tokens;              // Actual tokens stored (0 to BLOCK_SIZE)
    uint32_t layer_id;                // Which transformer layer
    SovereignKVBlockState state;      // Current state
    
    // Physical memory
    void* k_data;                     // Key tensor data
    void* v_data;                     // Value tensor data
    size_t data_size;                 // Size per K/V tensor
    
    // Block linking for sequences
    struct SovereignKVCacheBlock* prev;
    struct SovereignKVCacheBlock* next;
    
    // Hash for deduplication
    uint64_t content_hash;            // Hash of KV data for sharing
    uint32_t hash_valid;              // Is hash computed?
    
    // Statistics
    uint64_t last_access_time;        // For LRU eviction
    uint64_t access_count;            // Usage frequency
} SovereignKVCacheBlock;

// =============================================================================
// Sequence Mapping
// =============================================================================

typedef struct SovereignKVSequence {
    uint64_t sequence_id;             // Unique sequence identifier
    uint32_t num_blocks;              // Number of blocks allocated
    uint32_t total_tokens;            // Total tokens in sequence
    uint32_t num_layers;              // Layers per token
    uint32_t num_heads;               // Attention heads per layer
    uint32_t head_dim;                // Dimension per head
    
    // Block list (array of block pointers)
    SovereignKVCacheBlock** blocks;
    uint32_t blocks_capacity;
    
    // Memory pool reference
    SovereignBlockAllocatorHandle allocator;
    
    // State
    uint32_t is_generating;           // Currently generating tokens?
    uint32_t is_shared;               // Shared across sequences?
    
    // Statistics
    uint64_t cache_hits;              // Reused blocks
    uint64_t cache_misses;            // New allocations
} SovereignKVSequence;

// =============================================================================
// Cache Configuration
// =============================================================================

typedef struct SovereignKVCacheConfig {
    uint32_t num_layers;              // Number of transformer layers
    uint32_t num_heads;               // Attention heads per layer
    uint32_t head_dim;                // Head dimension
    uint32_t block_size;              // Tokens per block
    uint64_t max_memory_bytes;        // Maximum cache memory
    uint32_t enable_sharing;          // Enable block deduplication
    uint32_t enable_lru;              // Enable LRU eviction
    float eviction_threshold;           // Evict when above this % of max
} SovereignKVCacheConfig;

// =============================================================================
// Cache Statistics
// =============================================================================

typedef struct SovereignKVCacheStats {
    uint64_t total_blocks;            // Total blocks in cache
    uint64_t free_blocks;             // Available blocks
    uint64_t used_blocks;             // Allocated blocks
    uint64_t shared_blocks;           // Shared across sequences
    uint64_t sequences_active;        // Active sequences
    uint64_t sequences_total;         // Total sequences served
    uint64_t tokens_cached;           // Total tokens in cache
    uint64_t tokens_evicted;          // Tokens evicted
    uint64_t cache_hits;              // Block reuse hits
    uint64_t cache_misses;            // Block allocation misses
    uint64_t memory_used_bytes;       // Current memory usage
    uint64_t memory_peak_bytes;       // Peak memory usage
    double hit_rate;                  // Cache hit rate
    double fragmentation_ratio;       // Memory fragmentation
} SovereignKVCacheStats;

// =============================================================================
// Cache Manager API
// =============================================================================

// Initialize KV cache manager
__declspec(dllexport) SovereignKVCacheManagerHandle Sovereign_KVCacheManager_Init(
    const SovereignKVCacheConfig* config
);

// Shutdown cache manager
__declspec(dllexport) void Sovereign_KVCacheManager_Shutdown(SovereignKVCacheManagerHandle manager);

// Create a new sequence cache
__declspec(dllexport) SovereignKVCacheHandle Sovereign_KVCache_CreateSequence(
    SovereignKVCacheManagerHandle manager,
    uint64_t sequence_id,
    uint32_t num_layers,
    uint32_t num_heads,
    uint32_t head_dim
);

// Destroy a sequence cache
__declspec(dllexport) void Sovereign_KVCache_DestroySequence(
    SovereignKVCacheManagerHandle manager,
    SovereignKVCacheHandle cache
);

// =============================================================================
// Block Management
// =============================================================================

// Allocate a new block for sequence
__declspec(dllexport) SovereignKVCacheBlockHandle Sovereign_KVCache_AllocateBlock(
    SovereignKVCacheManagerHandle manager,
    SovereignKVCacheHandle cache,
    uint32_t layer_id
);

// Release a block (decrement ref count)
__declspec(dllexport) void Sovereign_KVCache_ReleaseBlock(
    SovereignKVCacheManagerHandle manager,
    SovereignKVCacheBlockHandle block
);

// Get block for token position
__declspec(dllexport) SovereignKVCacheBlockHandle Sovereign_KVCache_GetBlockForToken(
    SovereignKVCacheHandle cache,
    uint32_t token_pos,
    uint32_t layer_id
);

// Mark block as computed (hash for dedup)
__declspec(dllexport) void Sovereign_KVCache_MarkBlockComputed(
    SovereignKVCacheBlockHandle block
);

// =============================================================================
// Data Access
// =============================================================================

// Get K tensor pointer for token
__declspec(dllexport) void* Sovereign_KVCache_GetKTensor(
    SovereignKVCacheHandle cache,
    uint32_t token_pos,
    uint32_t layer_id,
    uint32_t head_id
);

// Get V tensor pointer for token
__declspec(dllexport) void* Sovereign_KVCache_GetVTensor(
    SovereignKVCacheHandle cache,
    uint32_t token_pos,
    uint32_t layer_id,
    uint32_t head_id
);

// Get contiguous K/V block for attention computation
__declspec(dllexport) int Sovereign_KVCache_GetAttentionBlock(
    SovereignKVCacheHandle cache,
    uint32_t start_token,
    uint32_t end_token,
    uint32_t layer_id,
    void** k_out,
    void** v_out,
    uint32_t* num_tokens_out
);

// =============================================================================
// Sequence Operations
// =============================================================================

// Append token to sequence
__declspec(dllexport) int Sovereign_KVCache_AppendToken(
    SovereignKVCacheManagerHandle manager,
    SovereignKVCacheHandle cache,
    uint32_t layer_id
);

// Copy sequence (for beam search)
__declspec(dllexport) SovereignKVCacheHandle Sovereign_KVCache_CopySequence(
    SovereignKVCacheManagerHandle manager,
    SovereignKVCacheHandle source,
    uint64_t new_sequence_id
);

// Share blocks between sequences (for prompt caching)
__declspec(dllexport) int Sovereign_KVCache_ShareBlocks(
    SovereignKVCacheHandle source,
    SovereignKVCacheHandle target,
    uint32_t num_tokens
);

// Trim sequence to length (for backtracking)
__declspec(dllexport) void Sovereign_KVCache_TrimSequence(
    SovereignKVCacheHandle cache,
    uint32_t new_length
);

// =============================================================================
// Eviction & Management
// =============================================================================

// Run eviction to free memory
__declspec(dllexport) uint64_t Sovereign_KVCache_RunEviction(
    SovereignKVCacheManagerHandle manager,
    uint64_t target_free_bytes
);

// Compact cache to reduce fragmentation
__declspec(dllexport) uint64_t Sovereign_KVCache_Compact(
    SovereignKVCacheManagerHandle manager
);

// Get cache statistics
__declspec(dllexport) void Sovereign_KVCache_GetStats(
    SovereignKVCacheManagerHandle manager,
    SovereignKVCacheStats* stats
);

// Dump cache state for debugging
__declspec(dllexport) void Sovereign_KVCache_DumpState(
    SovereignKVCacheManagerHandle manager
);

// =============================================================================
// Prefetching
// =============================================================================

// Prefetch blocks for upcoming tokens
__declspec(dllexport) void Sovereign_KVCache_PrefetchBlocks(
    SovereignKVCacheHandle cache,
    uint32_t start_token,
    uint32_t num_tokens
);

// Set prefetch window size
__declspec(dllexport) void Sovereign_KVCache_SetPrefetchWindow(
    SovereignKVCacheManagerHandle manager,
    uint32_t window_size
);

#ifdef __cplusplus
}
#endif

#endif // SOVEREIGN_KV_CACHE_H
