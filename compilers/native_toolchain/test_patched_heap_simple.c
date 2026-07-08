// ============================================================================
// test_patched_heap_simple.c
// Simple test for patched heap - focuses on core functionality
// Compile: gcc -O2 test_patched_heap_simple.c sovereign_memory_patch.obj -o test_patched_heap_simple.exe
// ============================================================================

#include <stdio.h>
#include <string.h>

// Declare patched heap functions (from ASM)
extern int Heap_Init(void);
extern void* Heap_Alloc(unsigned long long size);
extern int Heap_Free(void* ptr);
extern void* Heap_Realloc(void* ptr, unsigned long long size);
extern void Heap_Cleanup(void);

static int g_tests_passed = 0;
static int g_tests_failed = 0;

#define TEST(name) printf("  [TEST] %-40s ", name);
#define PASS() do { printf("PASS\n"); g_tests_passed++; } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); g_tests_failed++; } while(0)

int main(void) {
    printf("========================================\n");
    printf("Patched Heap Implementation Test (Simple)\n");
    printf("========================================\n\n");
    
    // Test 1: Heap initialization
    TEST("Heap_Init");
    if (Heap_Init() == 0) {
        PASS();
    } else {
        FAIL("Heap_Init returned non-zero");
        return 1;  // Can't continue without heap
    }
    
    // Test 2: Basic allocation
    TEST("Heap_Alloc (1024 bytes)");
    void* p1 = Heap_Alloc(1024);
    if (p1 != NULL) {
        memset(p1, 0xAB, 1024);
        PASS();
    } else {
        FAIL("Allocation returned NULL");
    }
    
    // Test 3: Free memory
    TEST("Heap_Free");
    if (p1 != NULL) {
        if (Heap_Free(p1)) {
            PASS();
        } else {
            FAIL("Heap_Free returned 0");
        }
    } else {
        FAIL("Cannot test - allocation failed");
    }
    
    // Test 4: Free NULL (should succeed)
    TEST("Heap_Free(NULL)");
    if (Heap_Free(NULL)) {
        PASS();
    } else {
        FAIL("Free NULL should succeed");
    }
    
    // Test 5: Multiple allocations
    TEST("Multiple allocations");
    void* blocks[10];
    int all_ok = 1;
    for (int i = 0; i < 10; i++) {
        blocks[i] = Heap_Alloc(256 * (i + 1));
        if (blocks[i] == NULL) {
            all_ok = 0;
            break;
        }
    }
    if (all_ok) {
        for (int i = 0; i < 10; i++) {
            Heap_Free(blocks[i]);
        }
        PASS();
    } else {
        for (int i = 0; i < 10; i++) {
            if (blocks[i]) Heap_Free(blocks[i]);
        }
        FAIL("Some allocations failed");
    }
    
    // Test 6: Realloc
    TEST("Heap_Realloc");
    void* r1 = Heap_Alloc(100);
    if (r1 != NULL) {
        void* r2 = Heap_Realloc(r1, 200);
        if (r2 != NULL) {
            Heap_Free(r2);
            PASS();
        } else {
            Heap_Free(r1);
            FAIL("Realloc failed");
        }
    } else {
        FAIL("Initial alloc failed");
    }
    
    // Test 7: Large allocation
    TEST("Heap_Alloc (1MB)");
    void* large = Heap_Alloc(1024 * 1024);
    if (large != NULL) {
        Heap_Free(large);
        PASS();
    } else {
        FAIL("Large allocation failed");
    }
    
    // Test 8: Cleanup
    TEST("Heap_Cleanup");
    Heap_Cleanup();
    PASS();
    
    // Test 9: Re-init after cleanup
    TEST("Re-init after cleanup");
    if (Heap_Init() == 0) {
        void* p = Heap_Alloc(256);
        if (p != NULL) {
            Heap_Free(p);
            PASS();
        } else {
            FAIL("Allocation after re-init failed");
        }
    } else {
        FAIL("Re-init failed");
    }
    
    // Final cleanup
    Heap_Cleanup();
    
    // Summary
    printf("\n========================================\n");
    printf("Test Summary\n");
    printf("========================================\n");
    printf("Passed: %d\n", g_tests_passed);
    printf("Failed: %d\n", g_tests_failed);
    printf("========================================\n");
    
    if (g_tests_failed == 0) {
        printf("\nALL TESTS PASSED!\n");
        printf("Patched heap implementation is working correctly.\n");
        return 0;
    } else {
        printf("\nSome tests failed.\n");
        return 1;
    }
}
