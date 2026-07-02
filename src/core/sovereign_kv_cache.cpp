// =============================================================================
// sovereign_kv_cache.cpp
// Phase 20: Memory Optimization & Caching
// Paged attention KV cache implementation
// =============================================================================

#include "sovereign_kv_cache.h"
#include <windows.h>
#include <atomic>
#include <vector>
#include <map>
#include <set>
#include <cstring>
#include <algorithm>

// =============================================================================
// Internal Structures
// =============================================================================

struct KVCacheBlock {
    SovereignKVCacheBlock header;
    uint32_t in_use;
    
    KVCacheBlock() : in_use(0) {
        memset(&header, 0, sizeof(header));
        header.state = SOVEREIGN_KV_BLOCK_FREE;
    }
};

struct KVCacheSequence {
    SovereignKVSequence header;
    std::vector<KVCacheBlock*> block_list;
    
    KVCacheSequence() {
        memset(&header, 0, sizeof(header));
    }
    
    ~KVCacheSequence() {
        if (header.blocks) {
            delete[] header.blocks;
        }
    }
};

struct SovereignKVCacheManager {
    SovereignKVCacheConfig config;
    
    // Block pool
    std::vector<KVCacheBlock*> all_blocks;
    std::vector<KVCacheBlock*> free_blocks;
    std::map<uint64_t, KVCacheBlock*> hash_to_block;  // For deduplication
    
    // Sequence management
    std::map<uint64_t, KVCacheSequence*> sequences;
    uint64_t next_sequence_id;
    
    // Memory pool
    SovereignBlockAllocatorHandle allocator;
    
    // Statistics
    SovereignKVCacheStats stats{};
    
    // Thread safety
    CRITICAL_SECTION lock;
    
    // Prefetch
    uint32_t prefetch_window;
    
    SovereignKVCacheManager() : next_sequence_id(1), prefetch_window(4) {
        InitializeCriticalSection(&lock);
    }
    
    ~SovereignKVCacheManager() {
        DeleteCriticalSection(&lock);
    }
};

// =============================================================================
// Utility Functions
// =============================================================================

static uint64_t ComputeHash(const void* data, size_t len) {
    // Simple FNV-1a hash
    const uint8_t* bytes = static_cast<const uint8_t*>(data);
    uint64_t hash = 14695981039346656037ULL;
    for (size_t i = 0; i < len; i++) {
        hash ^= bytes[i];
        hash *= 1099511628211ULL;
    }
    return hash;
}

static size_t CalculateBlockDataSize(uint32_t num_heads, uint32_t head_dim, uint32_t block_size) {
    // K and V tensors: [block_size, num_heads, head_dim] each
    return block_size * num_heads * head_dim * sizeof(float) * 2;  // *2 for K+V
}

// =============================================================================
// Cache Manager Implementation
// =============================================================================

__declspec(dllexport) SovereignKVCacheManagerHandle Sovereign_KVCacheManager_Init(
    const SovereignKVCacheConfig* config) {
    
    if (!config) return nullptr;
    
    auto* manager = new SovereignKVCacheManager();
    manager->config = *config;
    
    // Initialize memory pool
    Sovereign_MemoryPool_Init();
    manager->allocator = Sovereign_BlockAllocator_Create(0);
    
    // Pre-allocate blocks
    size_t block_data_size = CalculateBlockDataSize(
        config->num_heads,
        config->head_dim,
        config->block_size
    );
    
    uint64_t max_blocks = config->max_memory_bytes / (block_data_size + sizeof(KVCacheBlock));
    if (max_blocks > 100000) max_blocks = 100000;  // Sanity limit
    
    for (uint64_t i = 0; i < max_blocks / 4; i++) {  // Start with 25%
        auto* block = new KVCacheBlock();
        block->header.block_id = static_cast<uint32_t>(i);
        block->header.data_size = block_data_size;
        block->header.k_data = Sovereign_BlockAllocator_Allocate(manager->allocator, block_data_size / 2, 64);
        block->header.v_data = Sovereign_BlockAllocator_Allocate(manager->allocator, block_data_size / 2, 64);
        
        if (!block->header.k_data || !block->header.v_data) {
            delete block;
            break;
        }
        
        manager->all_blocks.push_back(block);
        manager->free_blocks.push_back(block);
    }
    
    manager->stats.total_blocks = manager->all_blocks.size();
    manager->stats.free_blocks = manager->free_blocks.size();
    
    return manager;
}

__declspec(dllexport) void Sovereign_KVCacheManager_Shutdown(SovereignKVCacheManagerHandle manager) {
    if (!manager) return;
    
    EnterCriticalSection(&manager->lock);
    
    // Free all sequences
    for (auto& pair : manager->sequences) {
        delete pair.second;
    }
    manager->sequences.clear();
    
    // Free all blocks
    for (auto* block : manager->all_blocks) {
        if (block->header.k_data) {
            Sovereign_BlockAllocator_Deallocate(manager->allocator, block->header.k_data);
        }
        if (block->header.v_data) {
            Sovereign_BlockAllocator_Deallocate(manager->allocator, block->header.v_data);
        }
        delete block;
    }
    manager->all_blocks.clear();
    manager->free_blocks.clear();
    
    LeaveCriticalSection(&manager->lock);
    
    // Cleanup allocator
    if (manager->allocator) {
        Sovereign_BlockAllocator_Destroy(manager->allocator);
    }
    
    delete manager;
}

// =============================================================================
// Sequence Management
// =============================================================================

__declspec(dllexport) SovereignKVCacheHandle Sovereign_KVCache_CreateSequence(
    SovereignKVCacheManagerHandle manager,
    uint64_t sequence_id,
    uint32_t num_layers,
    uint32_t num_heads,
    uint32_t head_dim) {
    
    if (!manager) return nullptr;
    
    auto* seq = new KVCacheSequence();
    seq->header.sequence_id = sequence_id;
    seq->header.num_layers = num_layers;
    seq->header.num_heads = num_heads;
    seq->header.head_dim = head_dim;
    seq->header.total_tokens = 0;
    seq->header.num_blocks = 0;
    seq->header.blocks_capacity = 128;  // Initial capacity
    seq->header.blocks = new SovereignKVCacheBlock*[seq->header.blocks_capacity];
    seq->header.allocator = manager->allocator;
    
    EnterCriticalSection(&manager->lock);
    manager->sequences[sequence_id] = seq;
    manager->stats.sequences_active++;
    manager->stats.sequences_total++;
    LeaveCriticalSection(&manager->lock);
    
    return reinterpret_cast<SovereignKVCacheHandle>(seq);
}

__declspec(dllexport) void Sovereign_KVCache_DestroySequence(
    SovereignKVCacheManagerHandle manager,
    SovereignKVCacheHandle cache) {
    
    if (!manager || !cache) return;
    
    auto* seq = reinterpret_cast<KVCacheSequence*>(cache);
    
    EnterCriticalSection(&manager->lock);
    
    // Release all blocks
    for (auto* block : seq->block_list) {
        block->header.ref_count--;
        if (block->header.ref_count == 0) {
            block->header.state = SOVEREIGN_KV_BLOCK_FREE;
            block->header.num_tokens = 0;
            manager->free_blocks.push_back(block);
            manager->stats.used_blocks--;
            manager->stats.free_blocks++;
        }
    }
    
    manager->sequences.erase(seq->header.sequence_id);
    manager->stats.sequences_active--;
    
    LeaveCriticalSection(&manager->lock);
    
    delete seq;
}

// =============================================================================
// Block Allocation
// =============================================================================

__declspec(dllexport) SovereignKVCacheBlockHandle Sovereign_KVCache_AllocateBlock(
    SovereignKVCacheManagerHandle manager,
    SovereignKVCacheHandle cache,
    uint32_t layer_id) {
    
    if (!manager || !cache) return nullptr;
    
    auto* seq = reinterpret_cast<KVCacheSequence*>(cache);
    
    EnterCriticalSection(&manager->lock);
    
    KVCacheBlock* block = nullptr;
    
    // Try to get from free list
    if (!manager->free_blocks.empty()) {
        block = manager->free_blocks.back();
        manager->free_blocks.pop_back();
        manager->stats.cache_hits++;
    } else {
        // Need to evict
        manager->stats.cache_misses++;
        // TODO: Implement LRU eviction
    }
    
    if (block) {
        block->header.state = SOVEREIGN_KV_BLOCK_ALLOCATED;
        block->header.ref_count = 1;
        block->header.layer_id = layer_id;
        block->header.last_access_time = GetTickCount64();
        block->in_use = 1;
        
        // Add to sequence
        if (seq->block_list.size() >= seq->header.blocks_capacity) {
            // Grow block array
            uint32_t new_capacity = seq->header.blocks_capacity * 2;
            auto* new_blocks = new SovereignKVCacheBlock*[new_capacity];
            memcpy(new_blocks, seq->header.blocks, 
                   seq->header.blocks_capacity * sizeof(SovereignKVCacheBlock*));
            delete[] seq->header.blocks;
            seq->header.blocks = new_blocks;
            seq->header.blocks_capacity = new_capacity;
        }
        
        seq->block_list.push_back(block);
        seq->header.blocks[seq->header.num_blocks] = &block->header;
        seq->header.num_blocks++;
        
        manager->stats.used_blocks++;
        manager->stats.free_blocks--;
    }
    
    LeaveCriticalSection(&manager->lock);
    
    return block ? &block->header : nullptr;
}

__declspec(dllexport) void Sovereign_KVCache_ReleaseBlock(
    SovereignKVCacheManagerHandle manager,
    SovereignKVCacheBlockHandle block) {
    
    if (!manager || !block) return;
    
    auto* kv_block = reinterpret_cast<KVCacheBlock*>(
        reinterpret_cast<char*>(block) - offsetof(KVCacheBlock, header)
    );
    
    EnterCriticalSection(&manager->lock);
    
    kv_block->header.ref_count--;
    if (kv_block->header.ref_count == 0) {
        kv_block->header.state = SOVEREIGN_KV_BLOCK_FREE;
        kv_block->header.num_tokens = 0;
        kv_block->in_use = 0;
        manager->free_blocks.push_back(kv_block);
        manager->stats.used_blocks--;
        manager->stats.free_blocks++;
    }
    
    LeaveCriticalSection(&manager->lock);
}

// =============================================================================
// Data Access
// =============================================================================

__declspec(dllexport) void* Sovereign_KVCache_GetKTensor(
    SovereignKVCacheHandle cache,
    uint32_t token_pos,
    uint32_t layer_id,
    uint32_t head_id) {
    
    if (!cache) return nullptr;
    
    auto* seq = reinterpret_cast<KVCacheSequence*>(cache);
    
    uint32_t block_idx = token_pos / SOVEREIGN_KV_BLOCK_SIZE;
    uint32_t token_in_block = token_pos % SOVEREIGN_KV_BLOCK_SIZE;
    
    if (block_idx >= seq->block_list.size()) return nullptr;
    
    auto* block = seq->block_list[block_idx];
    if (!block || !block->header.k_data) return nullptr;
    
    // Calculate offset: [token_in_block, head_id, head_dim]
    size_t offset = (token_in_block * seq->header.num_heads + head_id) * seq->header.head_dim;
    
    return reinterpret_cast<float*>(block->header.k_data) + offset;
}

__declspec(dllexport) void* Sovereign_KVCache_GetVTensor(
    SovereignKVCacheHandle cache,
    uint32_t token_pos,
    uint32_t layer_id,
    uint32_t head_id) {
    
    if (!cache) return nullptr;
    
    auto* seq = reinterpret_cast<KVCacheSequence*>(cache);
    
    uint32_t block_idx = token_pos / SOVEREIGN_KV_BLOCK_SIZE;
    uint32_t token_in_block = token_pos % SOVEREIGN_KV_BLOCK_SIZE;
    
    if (block_idx >= seq->block_list.size()) return nullptr;
    
    auto* block = seq->block_list[block_idx];
    if (!block || !block->header.v_data) return nullptr;
    
    size_t offset = (token_in_block * seq->header.num_heads + head_id) * seq->header.head_dim;
    
    return reinterpret_cast<float*>(block->header.v_data) + offset;
}

// =============================================================================
// Sequence Operations
// =============================================================================

__declspec(dllexport) int Sovereign_KVCache_AppendToken(
    SovereignKVCacheManagerHandle manager,
    SovereignKVCacheHandle cache,
    uint32_t layer_id) {
    
    if (!manager || !cache) return -1;
    
    auto* seq = reinterpret_cast<KVCacheSequence*>(cache);
    
    uint32_t token_pos = seq->header.total_tokens;
    uint32_t block_idx = token_pos / SOVEREIGN_KV_BLOCK_SIZE;
    
    // Check if we need a new block
    if (block_idx >= seq->block_list.size()) {
        auto* block = Sovereign_KVCache_AllocateBlock(manager, cache, layer_id);
        if (!block) return -1;
    }
    
    seq->header.total_tokens++;
    
    // Update block token count
    uint32_t token_in_block = token_pos % SOVEREIGN_KV_BLOCK_SIZE;
    auto* block = seq->block_list[block_idx];
    if (token_in_block >= block->header.num_tokens) {
        block->header.num_tokens = token_in_block + 1;
    }
    
    return 0;
}

__declspec(dllexport) SovereignKVCacheHandle Sovereign_KVCache_CopySequence(
    SovereignKVCacheManagerHandle manager,
    SovereignKVCacheHandle source,
    uint64_t new_sequence_id) {
    
    if (!manager || !source) return nullptr;
    
    auto* src_seq = reinterpret_cast<KVCacheSequence*>(source);
    
    // Create new sequence
    auto* new_cache = Sovereign_KVCache_CreateSequence(
        manager, new_sequence_id,
        src_seq->header.num_layers,
        src_seq->header.num_heads,
        src_seq->header.head_dim
    );
    
    if (!new_cache) return nullptr;
    
    auto* dst_seq = reinterpret_cast<KVCacheSequence*>(new_cache);
    
    EnterCriticalSection(&manager->lock);
    
    // Share blocks (increment ref count)
    for (auto* block : src_seq->block_list) {
        block->header.ref_count++;
        dst_seq->block_list.push_back(block);
        
        if (dst_seq->header.num_blocks < dst_seq->header.blocks_capacity) {
            dst_seq->header.blocks[dst_seq->header.num_blocks] = &block->header;
            dst_seq->header.num_blocks++;
        }
    }
    
    dst_seq->header.total_tokens = src_seq->header.total_tokens;
    dst_seq->header.is_shared = 1;
    
    manager->stats.shared_blocks += static_cast<uint64_t>(src_seq->block_list.size());
    
    LeaveCriticalSection(&manager->lock);
    
    return new_cache;
}

// =============================================================================
// Statistics
// =============================================================================

__declspec(dllexport) void Sovereign_KVCache_GetStats(
    SovereignKVCacheManagerHandle manager,
    SovereignKVCacheStats* stats) {
    
    if (!manager || !stats) return;
    
    EnterCriticalSection(&manager->lock);
    
    *stats = manager->stats;
    
    // Calculate derived stats
    if (stats->cache_hits + stats->cache_misses > 0) {
        stats->hit_rate = static_cast<double>(stats->cache_hits) /
                          (stats->cache_hits + stats->cache_misses);
    }
    
    stats->tokens_cached = 0;
    for (auto& pair : manager->sequences) {
        stats->tokens_cached += pair.second->header.total_tokens;
    }
    
    LeaveCriticalSection(&manager->lock);
}

__declspec(dllexport) void Sovereign_KVCache_DumpState(SovereignKVCacheManagerHandle manager) {
    if (!manager) return;
    
    SovereignKVCacheStats stats;
    Sovereign_KVCache_GetStats(manager, &stats);
    
    printf("\n=== Sovereign KV Cache State ===\n");
    printf("Total Blocks: %llu\n", stats.total_blocks);
    printf("Free Blocks: %llu\n", stats.free_blocks);
    printf("Used Blocks: %llu\n", stats.used_blocks);
    printf("Shared Blocks: %llu\n", stats.shared_blocks);
    printf("Active Sequences: %llu\n", stats.sequences_active);
    printf("Tokens Cached: %llu\n", stats.tokens_cached);
    printf("Cache Hit Rate: %.2f%%\n", stats.hit_rate * 100.0);
    printf("================================\n\n");
}

// =============================================================================
// Placeholder Functions (for future implementation)
// =============================================================================

__declspec(dllexport) SovereignKVCacheBlockHandle Sovereign_KVCache_GetBlockForToken(
    SovereignKVCacheHandle cache, uint32_t token_pos, uint32_t layer_id) {
    (void)layer_id;
    if (!cache) return nullptr;
    auto* seq = reinterpret_cast<KVCacheSequence*>(cache);
    uint32_t block_idx = token_pos / SOVEREIGN_KV_BLOCK_SIZE;
    if (block_idx >= seq->block_list.size()) return nullptr;
    return &seq->block_list[block_idx]->header;
}

__declspec(dllexport) void Sovereign_KVCache_MarkBlockComputed(SovereignKVCacheBlockHandle block) {
    if (!block) return;
    block->state = SOVEREIGN_KV_BLOCK_COMPUTED;
    block->last_access_time = GetTickCount64();
}

__declspec(dllexport) int Sovereign_KVCache_GetAttentionBlock(
    SovereignKVCacheHandle cache, uint32_t start_token, uint32_t end_token,
    uint32_t layer_id, void** k_out, void** v_out, uint32_t* num_tokens_out) {
    (void)cache; (void)start_token; (void)end_token; (void)layer_id;
    if (k_out) *k_out = nullptr;
    if (v_out) *v_out = nullptr;
    if (num_tokens_out) *num_tokens_out = 0;
    return -1;  // TODO: Implement contiguous block gathering
}

__declspec(dllexport) int Sovereign_KVCache_ShareBlocks(
    SovereignKVCacheHandle source, SovereignKVCacheHandle target, uint32_t num_tokens) {
    (void)source; (void)target; (void)num_tokens;
    return 0;  // TODO: Implement fine-grained sharing
}

__declspec(dllexport) void Sovereign_KVCache_TrimSequence(SovereignKVCacheHandle cache, uint32_t new_length) {
    if (!cache) return;
    auto* seq = reinterpret_cast<KVCacheSequence*>(cache);
    if (new_length >= seq->header.total_tokens) return;
    seq->header.total_tokens = new_length;
    // TODO: Release excess blocks
}

__declspec(dllexport) uint64_t Sovereign_KVCache_RunEviction(
    SovereignKVCacheManagerHandle manager, uint64_t target_free_bytes) {
    (void)manager; (void)target_free_bytes;
    return 0;  // TODO: Implement LRU eviction
}

__declspec(dllexport) uint64_t Sovereign_KVCache_Compact(SovereignKVCacheManagerHandle manager) {
    (void)manager;
    return 0;  // TODO: Implement defragmentation
}

__declspec(dllexport) void Sovereign_KVCache_PrefetchBlocks(
    SovereignKVCacheHandle cache, uint32_t start_token, uint32_t num_tokens) {
    (void)cache; (void)start_token; (void)num_tokens;
    // TODO: Implement software prefetching
}

__declspec(dllexport) void Sovereign_KVCache_SetPrefetchWindow(
    SovereignKVCacheManagerHandle manager, uint32_t window_size) {
    if (!manager) return;
    manager->prefetch_window = window_size;
}
