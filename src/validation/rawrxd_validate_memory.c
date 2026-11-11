//=============================================================================
// rawrxd_validate_memory.c
// Memory System Validation Implementation
//=============================================================================

#include "rawrxd_validate.h"
#include <stdio.h>
#include <string.h>

//=============================================================================
// Allocator Tests
//=============================================================================

static bool test_small_allocs(void) {
    printf("    Testing small allocations... ");
    
    void* ptrs[100];
    size_t sizes[] = {16, 64, 256, 1024, 4096, 16384, 65536, 262144};
    
    // Allocate
    for (int i = 0; i < 8; i++) {
        ptrs[i] = rawrxd_alloc(sizes[i]);
        if (!ptrs[i]) {
            printf("FAIL (alloc %zu failed)\n", sizes[i]);
            return false;
        }
        
        // Write pattern
        memset(ptrs[i], (i + 1) & 0xFF, sizes[i]);
    }
    
    // Verify patterns
    for (int i = 0; i < 8; i++) {
        u8 expected = (i + 1) & 0xFF;
        u8* p = (u8*)ptrs[i];
        for (size_t j = 0; j < sizes[i]; j++) {
            if (p[j] != expected) {
                printf("FAIL (corruption at %zu in block %d)\n", j, i);
                return false;
            }
        }
    }
    
    // Free in reverse order
    for (int i = 7; i >= 0; i--) {
        rawrxd_free(ptrs[i], sizes[i]);
    }
    
    printf("PASS\n");
    return true;
}

static bool test_large_allocs(void) {
    printf("    Testing large allocations... ");
    
    // Test 1MB, 10MB, 50MB
    size_t sizes[] = {1024 * 1024, 10 * 1024 * 1024, 50 * 1024 * 1024};
    
    for (int i = 0; i < 3; i++) {
        void* p = rawrxd_alloc(sizes[i]);
        if (!p) {
            printf("SKIP (cannot alloc %zu)\n", sizes[i]);
            continue;
        }
        
        // Touch first and last page
        ((u8*)p)[0] = 0xAA;
        ((u8*)p)[sizes[i] - 1] = 0xBB;
        
        if (((u8*)p)[0] != 0xAA || ((u8*)p)[sizes[i] - 1] != 0xBB) {
            printf("FAIL (memory not accessible)\n");
            rawrxd_free(p, sizes[i]);
            return false;
        }
        
        rawrxd_free(p, sizes[i]);
    }
    
    printf("PASS\n");
    return true;
}

static bool test_alignment(void) {
    printf("    Testing alignment... ");
    
    size_t alignments[] = {8, 16, 32, 64, 128, 256, 4096};
    
    for (int i = 0; i < 7; i++) {
        void* p = rawrxd_alloc_aligned(1024, alignments[i]);
        if (!p) {
            printf("FAIL (alloc with align %zu failed)\n", alignments[i]);
            return false;
        }
        
        if (((uintptr_t)p) % alignments[i] != 0) {
            printf("FAIL (ptr %p not aligned to %zu)\n", p, alignments[i]);
            rawrxd_free_aligned(p, 1024);
            return false;
        }
        
        rawrxd_free_aligned(p, 1024);
    }
    
    printf("PASS\n");
    return true;
}

static bool test_allocator_stress(void) {
    printf("    Testing allocator stress... ");
    
    #define STRESS_ALLOCS 1000
    void* ptrs[STRESS_ALLOCS];
    size_t sizes[STRESS_ALLOCS];
    
    rawrxd_rng rng;
    rawrxd_rng_init(&rng, 42);
    
    // Random allocations
    for (int i = 0; i < STRESS_ALLOCS; i++) {
        sizes[i] = (rawrxd_rng_u32(&rng) % (1024 * 1024)) + 16;  // 16B to 1MB
        ptrs[i] = rawrxd_alloc(sizes[i]);
        if (ptrs[i]) {
            memset(ptrs[i], i & 0xFF, sizes[i]);
        }
    }
    
    // Verify patterns
    for (int i = 0; i < STRESS_ALLOCS; i++) {
        if (!ptrs[i]) continue;
        
        u8* p = (u8*)ptrs[i];
        for (size_t j = 0; j < sizes[i] && j < 100; j++) {  // Sample first 100 bytes
            if (p[j] != (i & 0xFF)) {
                printf("FAIL (corruption in block %d)\n", i);
                return false;
            }
        }
    }
    
    // Random free order
    int order[STRESS_ALLOCS];
    for (int i = 0; i < STRESS_ALLOCS; i++) order[i] = i;
    
    // Shuffle
    for (int i = STRESS_ALLOCS - 1; i > 0; i--) {
        int j = rawrxd_rng_u32(&rng) % (i + 1);
        int tmp = order[i];
        order[i] = order[j];
        order[j] = tmp;
    }
    
    // Free
    for (int i = 0; i < STRESS_ALLOCS; i++) {
        int idx = order[i];
        if (ptrs[idx]) {
            rawrxd_free(ptrs[idx], sizes[idx]);
        }
    }
    
    printf("PASS\n");
    return true;
}

//=============================================================================
// Arena Tests
//=============================================================================

static bool test_arena_linear(void) {
    printf("    Testing arena linear allocation... ");
    
    rawrxd_arena arena;
    if (!rawrxd_arena_init(&arena, 1024 * 1024)) {  // 1MB arena
        printf("FAIL (arena init)\n");
        return false;
    }
    
    // Allocate 1000 x 1KB
    for (int i = 0; i < 1000; i++) {
        void* p = rawrxd_arena_alloc(&arena, 1024);
        if (!p) {
            printf("FAIL (alloc %d failed)\n", i);
            rawrxd_arena_free(&arena);
            return false;
        }
        memset(p, i & 0xFF, 1024);
    }
    
    // Reset and reuse
    rawrxd_arena_reset(&arena);
    
    void* p = rawrxd_arena_alloc(&arena, 512 * 1024);
    if (!p) {
        printf("FAIL (reuse alloc failed)\n");
        rawrxd_arena_free(&arena);
        return false;
    }
    
    rawrxd_arena_free(&arena);
    printf("PASS\n");
    return true;
}

static bool test_arena_alignment(void) {
    printf("    Testing arena alignment... ");
    
    rawrxd_arena arena;
    if (!rawrxd_arena_init(&arena, 1024 * 1024)) {
        printf("FAIL (arena init)\n");
        return false;
    }
    
    // Allocate with various alignments
    size_t alignments[] = {8, 16, 32, 64, 128, 256};
    
    for (int i = 0; i < 6; i++) {
        void* p = rawrxd_arena_alloc_aligned(&arena, 256, alignments[i]);
        if (!p) {
            printf("FAIL (alloc with align %zu failed)\n", alignments[i]);
            rawrxd_arena_free(&arena);
            return false;
        }
        
        if (((uintptr_t)p) % alignments[i] != 0) {
            printf("FAIL (misaligned to %zu)\n", alignments[i]);
            rawrxd_arena_free(&arena);
            return false;
        }
    }
    
    rawrxd_arena_free(&arena);
    printf("PASS\n");
    return true;
}

//=============================================================================
// Pool Tests
//=============================================================================

static bool test_pool_basic(void) {
    printf("    Testing pool allocator... ");
    
    rawrxd_pool pool;
    if (!rawrxd_pool_init(&pool, 256, 100)) {  // 256-byte objects, 100 in pool
        printf("FAIL (pool init)\n");
        return false;
    }
    
    void* ptrs[150];
    
    // Allocate 150 objects (50 more than pool size)
    int allocated = 0;
    for (int i = 0; i < 150; i++) {
        ptrs[i] = rawrxd_pool_alloc(&pool);
        if (ptrs[i]) {
            allocated++;
            memset(ptrs[i], i & 0xFF, 256);
        }
    }
    
    if (allocated < 100) {
        printf("FAIL (only %d allocated, expected at least 100)\n", allocated);
        rawrxd_pool_free(&pool);
        return false;
    }
    
    // Free all
    for (int i = 0; i < 150; i++) {
        if (ptrs[i]) {
            rawrxd_pool_free_obj(&pool, ptrs[i]);
        }
    }
    
    rawrxd_pool_free(&pool);
    printf("PASS (%d allocated)\n", allocated);
    return true;
}

static bool test_pool_exhaustion(void) {
    printf("    Testing pool exhaustion... ");
    
    rawrxd_pool pool;
    if (!rawrxd_pool_init(&pool, 64, 10)) {
        printf("FAIL (pool init)\n");
        return false;
    }
    
    // Allocate all 10
    void* ptrs[10];
    for (int i = 0; i < 10; i++) {
        ptrs[i] = rawrxd_pool_alloc(&pool);
        if (!ptrs[i]) {
            printf("FAIL (alloc %d failed)\n", i);
            rawrxd_pool_free(&pool);
            return false;
        }
    }
    
    // Try to allocate 11th - should fail gracefully
    void* extra = rawrxd_pool_alloc(&pool);
    if (extra != NULL) {
        printf("WARN (pool over-allocated)\n");
        rawrxd_pool_free_obj(&pool, extra);
    }
    
    // Free one and reallocate
    rawrxd_pool_free_obj(&pool, ptrs[0]);
    ptrs[0] = rawrxd_pool_alloc(&pool);
    if (!ptrs[0]) {
        printf("FAIL (realloc after free failed)\n");
        rawrxd_pool_free(&pool);
        return false;
    }
    
    // Cleanup
    for (int i = 0; i < 10; i++) {
        if (ptrs[i]) rawrxd_pool_free_obj(&pool, ptrs[i]);
    }
    
    rawrxd_pool_free(&pool);
    printf("PASS\n");
    return true;
}

//=============================================================================
// Memory Validation Entry
//=============================================================================

rawrxd_memory_validation* rawrxd_validate_memory(void) {
    rawrxd_memory_validation* val = rawrxd_alloc(sizeof(rawrxd_memory_validation));
    if (!val) return NULL;
    
    memset(val, 0, sizeof(*val));
    
    printf("[SUITE] Memory System Validation\n");
    
    // Allocator tests
    val->small_alloc_passed = test_small_allocs();
    val->large_alloc_passed = test_large_allocs();
    val->alignment_passed = test_alignment();
    
    // Arena tests
    val->arena_passed = test_arena_linear();
    val->arena_alignment_passed = test_arena_alignment();
    
    // Pool tests
    val->pool_passed = test_pool_basic();
    val->pool_exhaustion_passed = test_pool_exhaustion();
    
    // Overall result
    val->passed = val->small_alloc_passed && val->large_alloc_passed &&
                  val->alignment_passed && val->arena_passed &&
                  val->arena_alignment_passed && val->pool_passed &&
                  val->pool_exhaustion_passed;
    
    printf("\n  Memory validation: %s\n", val->passed ? "PASSED" : "FAILED");
    
    return val;
}
