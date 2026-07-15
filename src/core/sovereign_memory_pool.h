// =============================================================================
// sovereign_memory_pool.h
// Phase 20: Memory Optimization & Caching
// Lock-free thread-local memory allocator for inference scaling
// =============================================================================

#ifndef SOVEREIGN_MEMORY_POOL_H
#define SOVEREIGN_MEMORY_POOL_H

#include <inttypes.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// =============================================================================
// Configuration
// =============================================================================

#define SOVEREIGN_MEMORY_BLOCK_SIZE       4096    // 4KB blocks
#define SOVEREIGN_MEMORY_BLOCKS_PER_CHUNK 256     // 1MB chunks
#define SOVEREIGN_MEMORY_MAX_CHUNKS         1024   // 1GB max per pool
#define SOVEREIGN_MEMORY_ALIGNMENT        64     // Cache line alignment
#define SOVEREIGN_MEMORY_CANARY_VALUE     0xDEADBEEF

// =============================================================================
// Opaque Handles
// =============================================================================

typedef struct SovereignMemoryPool* SovereignMemoryPoolHandle;
typedef struct SovereignBlockAllocator* SovereignBlockAllocatorHandle;

// =============================================================================
// Block Header (internal tracking)
// =============================================================================

typedef struct SovereignMemoryBlockHeader {
    uint32_t canary;           // SOVEREIGN_MEMORY_CANARY_VALUE
    uint32_t thread_id;        // Owning thread
    uint32_t block_size;       // Actual allocated size
    uint32_t flags;            // Usage flags
    uint64_t alloc_time;       // For debugging/leak detection
    struct SovereignMemoryBlockHeader* next;  // Free list linkage
} SovereignMemoryBlockHeader;

// =============================================================================
// Statistics
// =============================================================================

typedef struct SovereignMemoryStats {
    uint64_t total_allocated;      // Total bytes allocated
    uint64_t total_freed;          // Total bytes freed
    uint64_t current_used;         // Currently in use
    uint64_t peak_used;            // Peak usage
    uint64_t blocks_allocated;     // Number of block allocations
    uint64_t blocks_freed;         // Number of block deallocations
    uint64_t chunks_allocated;     // OS chunks requested
    uint64_t cache_hits;         // Thread-local hits
    uint64_t cache_misses;         // Cross-thread allocations
    uint64_t fragmentation_bytes;  // Estimated fragmentation
    double avg_allocation_time_us; // Average alloc latency
} SovereignMemoryStats;

// =============================================================================
// Memory Pool API (Global)
// =============================================================================

// Initialize global memory pool system
__declspec(dllexport) int Sovereign_MemoryPool_Init(void);

// Shutdown and cleanup all memory pools
__declspec(dllexport) void Sovereign_MemoryPool_Shutdown(void);

// Get global memory statistics
__declspec(dllexport) void Sovereign_MemoryPool_GetStats(SovereignMemoryStats* stats);

// Dump memory pool state for debugging
__declspec(dllexport) void Sovereign_MemoryPool_DumpState(void);

// =============================================================================
// Thread-Local Block Allocator API
// =============================================================================

// Create a thread-local allocator (call once per thread)
__declspec(dllexport) SovereignBlockAllocatorHandle Sovereign_BlockAllocator_Create(uint32_t thread_id);

// Destroy a thread-local allocator
__declspec(dllexport) void Sovereign_BlockAllocator_Destroy(SovereignBlockAllocatorHandle allocator);

// Allocate a block (O(1), lock-free for thread-local)
__declspec(dllexport) void* Sovereign_BlockAllocator_Allocate(
    SovereignBlockAllocatorHandle allocator,
    size_t size,
    uint32_t alignment
);

// Deallocate a block (O(1), lock-free for thread-local)
__declspec(dllexport) void Sovereign_BlockAllocator_Deallocate(
    SovereignBlockAllocatorHandle allocator,
    void* ptr
);

// Get allocator statistics
__declspec(dllexport) void Sovereign_BlockAllocator_GetStats(
    SovereignBlockAllocatorHandle allocator,
    SovereignMemoryStats* stats
);

// =============================================================================
// Aligned Allocation Helpers
// =============================================================================

// Allocate aligned memory for SIMD/AVX-512
__declspec(dllexport) void* Sovereign_AlignedAlloc(size_t size, size_t alignment);

// Free aligned memory
__declspec(dllexport) void Sovereign_AlignedFree(void* ptr);

// Check if pointer is from sovereign pool
__declspec(dllexport) int Sovereign_IsPoolPointer(void* ptr);

// =============================================================================
// NUMA-Aware Allocation
// =============================================================================

// Allocate memory on specific NUMA node
__declspec(dllexport) void* Sovereign_NumaAlloc(
    size_t size,
    uint32_t numa_node,
    uint32_t alignment
);

// Get NUMA node for pointer
__declspec(dllexport) int Sovereign_GetNumaNode(void* ptr);

// Prefetch memory for next access
__declspec(dllexport) void Sovereign_Prefetch(void* ptr, int hint);

// =============================================================================
// Debug & Safety
// =============================================================================

// Validate memory block integrity
__declspec(dllexport) int Sovereign_ValidateBlock(void* ptr);

// Check for memory leaks
__declspec(dllexport) int Sovereign_CheckLeaks(void);

// Enable/disable canary checking
__declspec(dllexport) void Sovereign_SetCanaryChecking(int enable);

#ifdef __cplusplus
}
#endif

#endif // SOVEREIGN_MEMORY_POOL_H
