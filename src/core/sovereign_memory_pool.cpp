// =============================================================================
// sovereign_memory_pool.cpp
// Phase 20: Memory Optimization & Caching
// Lock-free thread-local memory allocator implementation
// =============================================================================

#include "sovereign_memory_pool.h"
#include <windows.h>
#include <process.h>
#include <atomic>
#include <vector>
#include <cstring>
#include <cstdio>
#include <algorithm>
#include <intrin.h>

// =============================================================================
// Platform Abstraction
// =============================================================================

#ifdef _WIN32
    #define SOVEREIGN_PAGE_SIZE 4096
    #define SOVEREIGN_ALLOC_PAGES(size) VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    #define SOVEREIGN_FREE_PAGES(ptr, size) VirtualFree(ptr, 0, MEM_RELEASE)
    #define SOVEREIGN_PREFETCH(ptr, hint) _mm_prefetch((const char*)(ptr), hint)
#else
    #define SOVEREIGN_PAGE_SIZE 4096
    #include <sys/mman.h>
    #define SOVEREIGN_ALLOC_PAGES(size) mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)
    #define SOVEREIGN_FREE_PAGES(ptr, size) munmap(ptr, size)
    #define SOVEREIGN_PREFETCH(ptr, hint) __builtin_prefetch(ptr, 0, hint)
#endif

// =============================================================================
// Memory Chunk (OS-level allocation)
// =============================================================================

struct MemoryChunk {
    void* base_address;
    size_t total_size;
    uint32_t num_blocks;
    uint32_t used_blocks;
    uint32_t numa_node;
    std::atomic<bool> in_use{false};
    
    MemoryChunk() : base_address(nullptr), total_size(0), num_blocks(0), used_blocks(0), numa_node(0) {}
};

// =============================================================================
// Block Allocator (Thread-Local)
// =============================================================================

struct BlockNode {
    SovereignMemoryBlockHeader header;
    alignas(64) char data[SOVEREIGN_MEMORY_BLOCK_SIZE - sizeof(SovereignMemoryBlockHeader)];
};

struct SovereignBlockAllocator {
    uint32_t thread_id;
    
    // Free list (LIFO stack)
    std::atomic<BlockNode*> free_list{nullptr};
    
    // Statistics
    std::atomic<uint64_t> allocations{0};
    std::atomic<uint64_t> deallocations{0};
    std::atomic<uint64_t> current_used{0};
    std::atomic<uint64_t> peak_used{0};
    std::atomic<uint64_t> cache_hits{0};
    std::atomic<uint64_t> cache_misses{0};
    
    // Chunks owned by this allocator
    std::vector<MemoryChunk*> chunks;
    CRITICAL_SECTION chunk_lock;
    
    // Debug
    int canary_checking{1};
    
    SovereignBlockAllocator(uint32_t tid) : thread_id(tid) {
        InitializeCriticalSection(&chunk_lock);
    }
    
    ~SovereignBlockAllocator() {
        DeleteCriticalSection(&chunk_lock);
    }
};

// =============================================================================
// Global Memory Pool State
// =============================================================================

struct GlobalMemoryPool {
    std::atomic<bool> initialized{false};
    std::vector<SovereignBlockAllocator*> allocators;
    std::vector<MemoryChunk*> all_chunks;
    CRITICAL_SECTION global_lock;
    
    // Global statistics
    SovereignMemoryStats global_stats{};
    
    GlobalMemoryPool() {
        InitializeCriticalSection(&global_lock);
    }
    
    ~GlobalMemoryPool() {
        DeleteCriticalSection(&global_lock);
    }
};

static GlobalMemoryPool g_memory_pool;

// =============================================================================
// Internal Functions
// =============================================================================

static BlockNode* PopFromFreeList(SovereignBlockAllocator* allocator) {
    BlockNode* head = allocator->free_list.load(std::memory_order_relaxed);
    while (head != nullptr) {
        BlockNode* next = reinterpret_cast<BlockNode*>(head->header.next);
        if (allocator->free_list.compare_exchange_weak(head, next, 
                                                         std::memory_order_acquire,
                                                         std::memory_order_relaxed)) {
            return head;
        }
    }
    return nullptr;
}

static void PushToFreeList(SovereignBlockAllocator* allocator, BlockNode* node) {
    BlockNode* head = allocator->free_list.load(std::memory_order_relaxed);
    do {
        node->header.next = reinterpret_cast<SovereignMemoryBlockHeader*>(head);
    } while (!allocator->free_list.compare_exchange_weak(head, node,
                                                          std::memory_order_release,
                                                          std::memory_order_relaxed));
}

static MemoryChunk* AllocateChunk(SovereignBlockAllocator* allocator) {
    size_t chunk_size = SOVEREIGN_MEMORY_BLOCKS_PER_CHUNK * sizeof(BlockNode);
    
    // Align to page boundary
    chunk_size = (chunk_size + SOVEREIGN_PAGE_SIZE - 1) & ~(SOVEREIGN_PAGE_SIZE - 1);
    
    void* memory = SOVEREIGN_ALLOC_PAGES(chunk_size);
    if (!memory) return nullptr;
    
    MemoryChunk* chunk = new MemoryChunk();
    chunk->base_address = memory;
    chunk->total_size = chunk_size;
    chunk->num_blocks = SOVEREIGN_MEMORY_BLOCKS_PER_CHUNK;
    chunk->used_blocks = 0;
    chunk->numa_node = allocator->thread_id % 2;  // Simple NUMA distribution
    
    // Initialize blocks and add to free list
    BlockNode* nodes = reinterpret_cast<BlockNode*>(memory);
    for (uint32_t i = 0; i < SOVEREIGN_MEMORY_BLOCKS_PER_CHUNK; i++) {
        BlockNode* node = &nodes[i];
        node->header.canary = SOVEREIGN_MEMORY_CANARY_VALUE;
        node->header.thread_id = allocator->thread_id;
        node->header.block_size = SOVEREIGN_MEMORY_BLOCK_SIZE;
        node->header.flags = 0;
        node->header.alloc_time = 0;
        node->header.next = nullptr;
        
        PushToFreeList(allocator, node);
    }
    
    // Track chunk
    EnterCriticalSection(&allocator->chunk_lock);
    allocator->chunks.push_back(chunk);
    LeaveCriticalSection(&allocator->chunk_lock);
    
    EnterCriticalSection(&g_memory_pool.global_lock);
    g_memory_pool.all_chunks.push_back(chunk);
    g_memory_pool.global_stats.chunks_allocated++;
    LeaveCriticalSection(&g_memory_pool.global_lock);
    
    return chunk;
}

// =============================================================================
// Public API Implementation
// =============================================================================

__declspec(dllexport) int Sovereign_MemoryPool_Init(void) {
    if (g_memory_pool.initialized.exchange(true)) {
        return 0;  // Already initialized
    }
    
    // Pre-allocate some global chunks
    return 0;
}

__declspec(dllexport) void Sovereign_MemoryPool_Shutdown(void) {
    if (!g_memory_pool.initialized.load()) return;
    
    // Clean up all allocators
    EnterCriticalSection(&g_memory_pool.global_lock);
    for (auto* allocator : g_memory_pool.allocators) {
        // Free all chunks
        EnterCriticalSection(&allocator->chunk_lock);
        for (auto* chunk : allocator->chunks) {
            if (chunk->base_address) {
                SOVEREIGN_FREE_PAGES(chunk->base_address, chunk->total_size);
            }
            delete chunk;
        }
        LeaveCriticalSection(&allocator->chunk_lock);
        delete allocator;
    }
    g_memory_pool.allocators.clear();
    g_memory_pool.all_chunks.clear();
    LeaveCriticalSection(&g_memory_pool.global_lock);
    
    g_memory_pool.initialized.store(false);
}

__declspec(dllexport) void Sovereign_MemoryPool_GetStats(SovereignMemoryStats* stats) {
    if (!stats) return;
    
    memset(stats, 0, sizeof(*stats));
    
    EnterCriticalSection(&g_memory_pool.global_lock);
    *stats = g_memory_pool.global_stats;
    
    // Aggregate from all allocators
    for (auto* allocator : g_memory_pool.allocators) {
        stats->blocks_allocated += allocator->allocations.load();
        stats->blocks_freed += allocator->deallocations.load();
        stats->current_used += allocator->current_used.load();
        stats->cache_hits += allocator->cache_hits.load();
        stats->cache_misses += allocator->cache_misses.load();
    }
    
    stats->total_allocated = stats->blocks_allocated * SOVEREIGN_MEMORY_BLOCK_SIZE;
    stats->total_freed = stats->blocks_freed * SOVEREIGN_MEMORY_BLOCK_SIZE;
    LeaveCriticalSection(&g_memory_pool.global_lock);
}

__declspec(dllexport) void Sovereign_MemoryPool_DumpState(void) {
    SovereignMemoryStats stats;
    Sovereign_MemoryPool_GetStats(&stats);
    
    printf("\n=== Sovereign Memory Pool State ===\n");
    printf("Total Allocated: %llu bytes\n", stats.total_allocated);
    printf("Current Used: %llu bytes\n", stats.current_used);
    printf("Peak Used: %llu bytes\n", stats.peak_used);
    printf("Blocks Allocated: %llu\n", stats.blocks_allocated);
    printf("Blocks Freed: %llu\n", stats.blocks_freed);
    printf("Cache Hits: %llu\n", stats.cache_hits);
    printf("Cache Misses: %llu\n", stats.cache_misses);
    printf("Chunks: %llu\n", stats.chunks_allocated);
    printf("=====================================\n\n");
}

// =============================================================================
// Block Allocator Implementation
// =============================================================================

__declspec(dllexport) SovereignBlockAllocatorHandle Sovereign_BlockAllocator_Create(uint32_t thread_id) {
    if (!g_memory_pool.initialized.load()) {
        Sovereign_MemoryPool_Init();
    }
    
    auto* allocator = new SovereignBlockAllocator(thread_id);
    
    EnterCriticalSection(&g_memory_pool.global_lock);
    g_memory_pool.allocators.push_back(allocator);
    LeaveCriticalSection(&g_memory_pool.global_lock);
    
    return allocator;
}

__declspec(dllexport) void Sovereign_BlockAllocator_Destroy(SovereignBlockAllocatorHandle allocator) {
    if (!allocator) return;
    
    // Remove from global list
    EnterCriticalSection(&g_memory_pool.global_lock);
    auto& allocators = g_memory_pool.allocators;
    allocators.erase(std::remove(allocators.begin(), allocators.end(), allocator), allocators.end());
    LeaveCriticalSection(&g_memory_pool.global_lock);
    
    // Chunks will be freed in Shutdown
    delete allocator;
}

__declspec(dllexport) void* Sovereign_BlockAllocator_Allocate(
    SovereignBlockAllocatorHandle allocator,
    size_t size,
    uint32_t alignment) {
    
    if (!allocator) return nullptr;
    
    // For now, only support sizes that fit in a block
    if (size > SOVEREIGN_MEMORY_BLOCK_SIZE - sizeof(SovereignMemoryBlockHeader)) {
        // Fall back to OS allocation for large blocks
        allocator->cache_misses.fetch_add(1);
        return _aligned_malloc(size, alignment);
    }
    
    // Try to get from free list
    BlockNode* node = PopFromFreeList(allocator);
    
    if (!node) {
        // Need to allocate a new chunk
        if (!AllocateChunk(allocator)) {
            return nullptr;
        }
        node = PopFromFreeList(allocator);
        if (!node) return nullptr;
    }
    
    // Mark as allocated
    node->header.alloc_time = GetTickCount64();
    node->header.flags = 1;  // Allocated flag
    
    allocator->allocations.fetch_add(1);
    allocator->cache_hits.fetch_add(1);
    
    uint64_t current = allocator->current_used.fetch_add(SOVEREIGN_MEMORY_BLOCK_SIZE);
    uint64_t peak = allocator->peak_used.load();
    while (current + SOVEREIGN_MEMORY_BLOCK_SIZE > peak) {
        if (allocator->peak_used.compare_exchange_weak(peak, current + SOVEREIGN_MEMORY_BLOCK_SIZE)) {
            break;
        }
    }
    
    // Return pointer to data area
    return node->data;
}

__declspec(dllexport) void Sovereign_BlockAllocator_Deallocate(
    SovereignBlockAllocatorHandle allocator,
    void* ptr) {
    
    if (!allocator || !ptr) return;
    
    // Check if this is a pool pointer
    BlockNode* node = reinterpret_cast<BlockNode*>(
        reinterpret_cast<char*>(ptr) - offsetof(BlockNode, data)
    );
    
    if (node->header.canary != SOVEREIGN_MEMORY_CANARY_VALUE) {
        // Not our pointer - use OS free
        _aligned_free(ptr);
        return;
    }
    
    // Validate ownership
    if (node->header.thread_id != allocator->thread_id) {
        // Cross-thread deallocation - still safe due to atomic free list
        allocator->cache_misses.fetch_add(1);
    }
    
    // Clear and return to free list
    node->header.flags = 0;
    node->header.alloc_time = 0;
    PushToFreeList(allocator, node);
    
    allocator->deallocations.fetch_add(1);
    allocator->current_used.fetch_sub(SOVEREIGN_MEMORY_BLOCK_SIZE);
}

__declspec(dllexport) void Sovereign_BlockAllocator_GetStats(
    SovereignBlockAllocatorHandle allocator,
    SovereignMemoryStats* stats) {
    
    if (!allocator || !stats) return;
    
    memset(stats, 0, sizeof(*stats));
    stats->blocks_allocated = allocator->allocations.load();
    stats->blocks_freed = allocator->deallocations.load();
    stats->current_used = allocator->current_used.load();
    stats->peak_used = allocator->peak_used.load();
    stats->cache_hits = allocator->cache_hits.load();
    stats->cache_misses = allocator->cache_misses.load();
}

// =============================================================================
// Aligned Allocation Helpers
// =============================================================================

__declspec(dllexport) void* Sovereign_AlignedAlloc(size_t size, size_t alignment) {
    return _aligned_malloc(size, alignment);
}

__declspec(dllexport) void Sovereign_AlignedFree(void* ptr) {
    _aligned_free(ptr);
}

__declspec(dllexport) int Sovereign_IsPoolPointer(void* ptr) {
    if (!ptr) return 0;
    
    BlockNode* node = reinterpret_cast<BlockNode*>(
        reinterpret_cast<char*>(ptr) - offsetof(BlockNode, data)
    );
    
    return node->header.canary == SOVEREIGN_MEMORY_CANARY_VALUE;
}

// =============================================================================
// NUMA-Aware Allocation
// =============================================================================

__declspec(dllexport) void* Sovereign_NumaAlloc(size_t size, uint32_t numa_node, uint32_t alignment) {
    // Simplified - just use aligned alloc
    // In production, would use VirtualAllocExNuma on Windows
    (void)numa_node;
    return Sovereign_AlignedAlloc(size, alignment);
}

__declspec(dllexport) int Sovereign_GetNumaNode(void* ptr) {
    if (!ptr) return -1;
    
    BlockNode* node = reinterpret_cast<BlockNode*>(
        reinterpret_cast<char*>(ptr) - offsetof(BlockNode, data)
    );
    
    if (node->header.canary == SOVEREIGN_MEMORY_CANARY_VALUE) {
        return node->header.thread_id % 2;  // Simplified NUMA mapping
    }
    
    return -1;
}

__declspec(dllexport) void Sovereign_Prefetch(void* ptr, int hint) {
    if (!ptr) return;
    
#ifdef _WIN32
    // _MM_HINT_T0=3 (L1), _MM_HINT_T1=2 (L2), _MM_HINT_T2=1 (L3)
    switch (hint) {
        case 0: _mm_prefetch(reinterpret_cast<const char*>(ptr), _MM_HINT_T0); break;  // L1
        case 1: _mm_prefetch(reinterpret_cast<const char*>(ptr), _MM_HINT_T1); break;  // L2
        case 2: _mm_prefetch(reinterpret_cast<const char*>(ptr), _MM_HINT_T2); break;  // L3
        default: _mm_prefetch(reinterpret_cast<const char*>(ptr), _MM_HINT_T0); break; // L1
    }
#else
    __builtin_prefetch(ptr, 0, hint);
#endif
}

// =============================================================================
// Debug & Safety
// =============================================================================

__declspec(dllexport) int Sovereign_ValidateBlock(void* ptr) {
    if (!ptr) return 0;
    
    BlockNode* node = reinterpret_cast<BlockNode*>(
        reinterpret_cast<char*>(ptr) - offsetof(BlockNode, data)
    );
    
    if (node->header.canary != SOVEREIGN_MEMORY_CANARY_VALUE) {
        return -1;  // Corrupted or not our block
    }
    
    if (node->header.flags == 0) {
        return -2;  // Already freed
    }
    
    return 0;  // Valid
}

__declspec(dllexport) int Sovereign_CheckLeaks(void) {
    int leaks = 0;
    
    EnterCriticalSection(&g_memory_pool.global_lock);
    for (auto* allocator : g_memory_pool.allocators) {
        uint64_t allocs = allocator->allocations.load();
        uint64_t frees = allocator->deallocations.load();
        if (allocs > frees) {
            leaks += static_cast<int>(allocs - frees);
        }
    }
    LeaveCriticalSection(&g_memory_pool.global_lock);
    
    return leaks;
}

__declspec(dllexport) void Sovereign_SetCanaryChecking(int enable) {
    // Global setting would require iterating all allocators
    // For now, this is a placeholder
    (void)enable;
}
