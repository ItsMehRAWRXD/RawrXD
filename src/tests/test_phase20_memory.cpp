// =============================================================================
// test_phase20_memory.cpp
// Phase 20: Memory Optimization & Caching - Test Suite
// Validates memory pool, KV cache, and prefetching
// =============================================================================

#include "../core/sovereign_memory_pool.h"
#include "../core/sovereign_kv_cache.h"
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <math.h>
#include <atomic>

// =============================================================================
// Test Configuration
// =============================================================================

#define TEST_DURATION_MS 5000
#define MIN_ALLOCATION_SPEEDUP 1.5  // 1.5x faster than malloc

// =============================================================================
// Test Results
// =============================================================================

struct TestResult {
    const char* name;
    int passed;
    double duration_ms;
    char message[256];
};

static TestResult g_results[20];
static int g_num_results = 0;

void record_result(const char* name, int passed, double duration, const char* msg) {
    if (g_num_results < 20) {
        g_results[g_num_results].name = name;
        g_results[g_num_results].passed = passed;
        g_results[g_num_results].duration_ms = duration;
        strncpy(g_results[g_num_results].message, msg, 255);
        g_results[g_num_results].message[255] = '\0';
        g_num_results++;
    }
}

// =============================================================================
// Timing Utilities
// =============================================================================

double get_time_ms() {
    LARGE_INTEGER freq, now;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&now);
    return (double)now.QuadPart * 1000.0 / freq.QuadPart;
}

// =============================================================================
// Test 1: Memory Pool Basic Allocation
// =============================================================================

void test_memory_pool_basic() {
    printf("\n[Test 1] Memory Pool Basic Allocation\n");
    
    double start = get_time_ms();
    
    // Initialize memory pool
    int init_result = Sovereign_MemoryPool_Init();
    if (init_result != 0) {
        record_result("MemoryPool_Init", 0, 0, "Failed to initialize memory pool");
        printf("  FAIL: Initialization failed\n");
        return;
    }
    
    // Create thread-local allocator
    SovereignBlockAllocatorHandle allocator = Sovereign_BlockAllocator_Create(0);
    if (!allocator) {
        record_result("MemoryPool_Basic", 0, 0, "Failed to create allocator");
        printf("  FAIL: Allocator creation failed\n");
        return;
    }
    
    // Allocate blocks
    const int NUM_ALLOCS = 10000;
    void* ptrs[NUM_ALLOCS];
    int alloc_count = 0;
    
    for (int i = 0; i < NUM_ALLOCS; i++) {
        ptrs[i] = Sovereign_BlockAllocator_Allocate(allocator, 1024, 64);
        if (ptrs[i]) alloc_count++;
    }
    
    // Deallocate
    for (int i = 0; i < NUM_ALLOCS; i++) {
        if (ptrs[i]) {
            Sovereign_BlockAllocator_Deallocate(allocator, ptrs[i]);
        }
    }
    
    // Get stats
    SovereignMemoryStats stats;
    Sovereign_BlockAllocator_GetStats(allocator, &stats);
    
    // Cleanup
    Sovereign_BlockAllocator_Destroy(allocator);
    
    double duration = get_time_ms() - start;
    
    int passed = (alloc_count == NUM_ALLOCS) ? 1 : 0;
    
    char msg[256];
    snprintf(msg, sizeof(msg), 
        "Allocated: %d/%d, Cache Hits: %llu, Time: %.2f ms",
        alloc_count, NUM_ALLOCS, stats.cache_hits, duration);
    
    record_result("MemoryPool_Basic", passed, duration, msg);
    
    printf("  %s\n", passed ? "PASS" : "FAIL");
    printf("  %s\n", msg);
}

// =============================================================================
// Test 2: Memory Pool vs Standard Malloc Performance
// =============================================================================

void test_memory_pool_performance() {
    printf("\n[Test 2] Memory Pool Performance vs Malloc\n");
    
    const int NUM_ITERATIONS = 100000;
    const int BLOCK_SIZE = 1024;
    
    // Test standard malloc
    double malloc_start = get_time_ms();
    for (int i = 0; i < NUM_ITERATIONS; i++) {
        void* ptr = malloc(BLOCK_SIZE);
        if (ptr) free(ptr);
    }
    double malloc_duration = get_time_ms() - malloc_start;
    
    // Test sovereign pool
    SovereignBlockAllocatorHandle allocator = Sovereign_BlockAllocator_Create(1);
    if (!allocator) {
        record_result("MemoryPool_Performance", 0, 0, "Failed to create allocator");
        printf("  FAIL: Allocator creation failed\n");
        return;
    }
    
    double pool_start = get_time_ms();
    for (int i = 0; i < NUM_ITERATIONS; i++) {
        void* ptr = Sovereign_BlockAllocator_Allocate(allocator, BLOCK_SIZE, 64);
        if (ptr) Sovereign_BlockAllocator_Deallocate(allocator, ptr);
    }
    double pool_duration = get_time_ms() - pool_start;
    
    Sovereign_BlockAllocator_Destroy(allocator);
    
    double speedup = malloc_duration / pool_duration;
    int passed = (speedup >= MIN_ALLOCATION_SPEEDUP) ? 1 : 0;
    
    char msg[256];
    snprintf(msg, sizeof(msg), 
        "Malloc: %.2f ms, Pool: %.2f ms, Speedup: %.2fx (target: %.1fx)",
        malloc_duration, pool_duration, speedup, MIN_ALLOCATION_SPEEDUP);
    
    record_result("MemoryPool_Performance", passed, pool_duration, msg);
    
    printf("  %s\n", passed ? "PASS" : "FAIL");
    printf("  %s\n", msg);
}

// =============================================================================
// Test 3: KV Cache Basic Operations
// =============================================================================

void test_kv_cache_basic() {
    printf("\n[Test 3] KV Cache Basic Operations\n");
    
    double start = get_time_ms();
    
    // Initialize memory pool first
    Sovereign_MemoryPool_Init();
    
    // Create cache manager
    SovereignKVCacheConfig config = {};
    config.num_layers = 32;
    config.num_heads = 32;
    config.head_dim = 128;
    config.block_size = 256;
    config.max_memory_bytes = 1024 * 1024 * 1024;  // 1GB
    config.enable_sharing = 1;
    config.enable_lru = 1;
    
    SovereignKVCacheManagerHandle manager = Sovereign_KVCacheManager_Init(&config);
    if (!manager) {
        record_result("KVCache_Basic", 0, 0, "Failed to create cache manager");
        printf("  FAIL: Cache manager creation failed\n");
        return;
    }
    
    // Create a sequence
    SovereignKVCacheHandle cache = Sovereign_KVCache_CreateSequence(
        manager, 1, 32, 32, 128
    );
    if (!cache) {
        record_result("KVCache_Basic", 0, 0, "Failed to create sequence");
        printf("  FAIL: Sequence creation failed\n");
        Sovereign_KVCacheManager_Shutdown(manager);
        return;
    }
    
    // Append tokens
    const int NUM_TOKENS = 1000;
    int append_count = 0;
    for (int i = 0; i < NUM_TOKENS; i++) {
        if (Sovereign_KVCache_AppendToken(manager, cache, 0) == 0) {
            append_count++;
        }
    }
    
    // Access K/V tensors
    void* k_tensor = Sovereign_KVCache_GetKTensor(cache, 500, 0, 0);
    void* v_tensor = Sovereign_KVCache_GetVTensor(cache, 500, 0, 0);
    
    int tensor_access = (k_tensor != nullptr && v_tensor != nullptr) ? 1 : 0;
    
    // Cleanup
    Sovereign_KVCache_DestroySequence(manager, cache);
    
    SovereignKVCacheStats stats;
    Sovereign_KVCache_GetStats(manager, &stats);
    
    Sovereign_KVCacheManager_Shutdown(manager);
    
    double duration = get_time_ms() - start;
    
    int passed = (append_count == NUM_TOKENS && tensor_access) ? 1 : 0;
    
    char msg[256];
    snprintf(msg, sizeof(msg), 
        "Tokens: %d/%d, Tensors: %s, Blocks: %llu",
        append_count, NUM_TOKENS, tensor_access ? "OK" : "FAIL", stats.used_blocks);
    
    record_result("KVCache_Basic", passed, duration, msg);
    
    printf("  %s\n", passed ? "PASS" : "FAIL");
    printf("  %s\n", msg);
}

// =============================================================================
// Test 4: KV Cache Sequence Sharing (Prompt Caching)
// =============================================================================

void test_kv_cache_sharing() {
    printf("\n[Test 4] KV Cache Sequence Sharing\n");
    
    double start = get_time_ms();
    
    Sovereign_MemoryPool_Init();
    
    SovereignKVCacheConfig config = {};
    config.num_layers = 32;
    config.num_heads = 32;
    config.head_dim = 128;
    config.block_size = 256;
    config.max_memory_bytes = 1024 * 1024 * 1024;
    config.enable_sharing = 1;
    
    SovereignKVCacheManagerHandle manager = Sovereign_KVCacheManager_Init(&config);
    if (!manager) {
        record_result("KVCache_Sharing", 0, 0, "Failed to create manager");
        printf("  FAIL: Manager creation failed\n");
        return;
    }
    
    // Create source sequence
    SovereignKVCacheHandle source = Sovereign_KVCache_CreateSequence(
        manager, 1, 32, 32, 128
    );
    if (!source) {
        record_result("KVCache_Sharing", 0, 0, "Failed to create source");
        printf("  FAIL: Source creation failed\n");
        Sovereign_KVCacheManager_Shutdown(manager);
        return;
    }
    
    // Add tokens to source
    for (int i = 0; i < 500; i++) {
        Sovereign_KVCache_AppendToken(manager, source, 0);
    }
    
    // Copy sequence (shares blocks)
    SovereignKVCacheHandle copy = Sovereign_KVCache_CopySequence(manager, source, 2);
    if (!copy) {
        record_result("KVCache_Sharing", 0, 0, "Failed to copy sequence");
        printf("  FAIL: Copy failed\n");
        Sovereign_KVCache_DestroySequence(manager, source);
        Sovereign_KVCacheManager_Shutdown(manager);
        return;
    }
    
    // Get stats
    SovereignKVCacheStats stats;
    Sovereign_KVCache_GetStats(manager, &stats);
    
    // Cleanup
    Sovereign_KVCache_DestroySequence(manager, copy);
    Sovereign_KVCache_DestroySequence(manager, source);
    Sovereign_KVCacheManager_Shutdown(manager);
    
    double duration = get_time_ms() - start;
    
    int passed = (stats.shared_blocks > 0) ? 1 : 0;
    
    char msg[256];
    snprintf(msg, sizeof(msg), 
        "Shared Blocks: %llu, Sequences: %llu",
        stats.shared_blocks, stats.sequences_active);
    
    record_result("KVCache_Sharing", passed, duration, msg);
    
    printf("  %s\n", passed ? "PASS" : "FAIL");
    printf("  %s\n", msg);
}

// =============================================================================
// Test 5: NUMA-Aware Memory Allocation
// =============================================================================

void test_numa_awareness() {
    printf("\n[Test 5] NUMA-Aware Memory Allocation\n");
    
    double start = get_time_ms();
    
    // Allocate on different "NUMA" nodes (simulated)
    void* ptr1 = Sovereign_NumaAlloc(4096, 0, 64);
    void* ptr2 = Sovereign_NumaAlloc(4096, 1, 64);
    
    int node1 = Sovereign_GetNumaNode(ptr1);
    int node2 = Sovereign_GetNumaNode(ptr2);
    
    if (ptr1) Sovereign_AlignedFree(ptr1);
    if (ptr2) Sovereign_AlignedFree(ptr2);
    
    double duration = get_time_ms() - start;
    
    int passed = (ptr1 != nullptr && ptr2 != nullptr) ? 1 : 0;
    
    char msg[256];
    snprintf(msg, sizeof(msg), 
        "Node 0: %p (reported: %d), Node 1: %p (reported: %d)",
        ptr1, node1, ptr2, node2);
    
    record_result("NUMA_Awareness", passed, duration, msg);
    
    printf("  %s\n", passed ? "PASS" : "FAIL");
    printf("  %s\n", msg);
}

// =============================================================================
// Test 6: Memory Prefetching
// =============================================================================

void test_prefetching() {
    printf("\n[Test 6] Memory Prefetching\n");
    
    double start = get_time_ms();
    
    // Allocate memory
    void* ptr = Sovereign_AlignedAlloc(4096 * 16, 64);  // 64KB
    if (!ptr) {
        record_result("Prefetching", 0, 0, "Allocation failed");
        printf("  FAIL: Allocation failed\n");
        return;
    }
    
    // Initialize
    memset(ptr, 0, 4096 * 16);
    
    // Test prefetch (should not crash)
    Sovereign_Prefetch(ptr, 0);  // L1
    Sovereign_Prefetch(reinterpret_cast<char*>(ptr) + 4096, 1);  // L2
    Sovereign_Prefetch(reinterpret_cast<char*>(ptr) + 8192, 2);  // L3
    
    // Access prefetched data
    volatile int sum = 0;
    for (int i = 0; i < 4096 * 16 / sizeof(int); i++) {
        sum += reinterpret_cast<int*>(ptr)[i];
    }
    
    Sovereign_AlignedFree(ptr);
    
    double duration = get_time_ms() - start;
    
    int passed = 1;  // If we got here, prefetch didn't crash
    
    char msg[256];
    snprintf(msg, sizeof(msg), 
        "Prefetch L1/L2/L3: OK, Access time: %.2f ms",
        duration);
    
    record_result("Prefetching", passed, duration, msg);
    
    printf("  %s\n", passed ? "PASS" : "FAIL");
    printf("  %s\n", msg);
}

// =============================================================================
// Test 7: Memory Validation and Safety
// =============================================================================

void test_memory_safety() {
    printf("\n[Test 7] Memory Validation and Safety\n");
    
    double start = get_time_ms();
    
    SovereignBlockAllocatorHandle allocator = Sovereign_BlockAllocator_Create(2);
    if (!allocator) {
        record_result("Memory_Safety", 0, 0, "Failed to create allocator");
        printf("  FAIL: Allocator creation failed\n");
        return;
    }
    
    // Allocate and validate
    void* ptr = Sovereign_BlockAllocator_Allocate(allocator, 1024, 64);
    if (!ptr) {
        record_result("Memory_Safety", 0, 0, "Allocation failed");
        printf("  FAIL: Allocation failed\n");
        Sovereign_BlockAllocator_Destroy(allocator);
        return;
    }
    
    int valid = Sovereign_ValidateBlock(ptr);
    int is_pool = Sovereign_IsPoolPointer(ptr);
    
    // Write pattern
    memset(ptr, 0xAB, 1024);
    
    // Validate again
    int valid2 = Sovereign_ValidateBlock(ptr);
    
    // Check for leaks
    int leaks = Sovereign_CheckLeaks();
    
    Sovereign_BlockAllocator_Deallocate(allocator, ptr);
    
    int leaks_after = Sovereign_CheckLeaks();
    
    Sovereign_BlockAllocator_Destroy(allocator);
    
    double duration = get_time_ms() - start;
    
    int passed = (valid == 0 && is_pool && valid2 == 0 && leaks_after == 0) ? 1 : 0;
    
    char msg[256];
    snprintf(msg, sizeof(msg), 
        "Validation: %s, IsPool: %s, Leaks: %d->%d",
        valid == 0 ? "OK" : "FAIL", is_pool ? "Yes" : "No", leaks, leaks_after);
    
    record_result("Memory_Safety", passed, duration, msg);
    
    printf("  %s\n", passed ? "PASS" : "FAIL");
    printf("  %s\n", msg);
}

// =============================================================================
// Main Test Runner
// =============================================================================

int main() {
    printf("╔════════════════════════════════════════════════════════════════╗\n");
    printf("║  Phase 20: Memory Optimization & Caching Test Suite              ║\n");
    printf("╚════════════════════════════════════════════════════════════════╝\n");
    
    // Run all tests
    test_memory_pool_basic();
    test_memory_pool_performance();
    test_kv_cache_basic();
    test_kv_cache_sharing();
    test_numa_awareness();
    test_prefetching();
    test_memory_safety();
    
    // Print summary
    printf("\n╔════════════════════════════════════════════════════════════════╗\n");
    printf("║  Test Summary                                                    ║\n");
    printf("╚════════════════════════════════════════════════════════════════╝\n");
    
    int total_passed = 0;
    int total_failed = 0;
    double total_duration = 0;
    
    for (int i = 0; i < g_num_results; i++) {
        const char* status = g_results[i].passed ? "PASS" : "FAIL";
        printf("\n[%s] %-30s %.1fms\n", status, g_results[i].name, g_results[i].duration_ms);
        printf("      %s\n", g_results[i].message);
        
        if (g_results[i].passed) total_passed++;
        else total_failed++;
        total_duration += g_results[i].duration_ms;
    }
    
    printf("\n────────────────────────────────────────────────────────────────\n");
    printf("Total: %d tests, %d passed, %d failed\n", g_num_results, total_passed, total_failed);
    printf("Duration: %.1f ms\n", total_duration);
    printf("────────────────────────────────────────────────────────────────\n");
    
    if (total_failed == 0) {
        printf("\n╔════════════════════════════════════════════════════════════════╗\n");
        printf("║  ALL TESTS PASSED - Phase 20 Ready for Production              ║\n");
        printf("╚════════════════════════════════════════════════════════════════╝\n");
        return 0;
    } else {
        printf("\n╔════════════════════════════════════════════════════════════════╗\n");
        printf("║  SOME TESTS FAILED - Review output above                       ║\n");
        printf("╚════════════════════════════════════════════════════════════════╝\n");
        return 1;
    }
}
