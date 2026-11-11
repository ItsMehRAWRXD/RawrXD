// Comprehensive heap test suite
#include <stdio.h>
#include <string.h>

extern int Heap_Init(void);
extern void* Heap_Alloc(unsigned long long size);
extern int Sovereign_Heap_Free(void* ptr);
extern void* Sovereign_Heap_Realloc(void* ptr, unsigned long long size);
extern void Heap_Cleanup(void);

static int g_tests_passed = 0;
static int g_tests_failed = 0;

#define TEST(name) printf("  [TEST] %-40s ", name);
#define PASS() do { printf("PASS\n"); g_tests_passed++; } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); g_tests_failed++; } while(0)

int main(void) {
    printf("========================================\n");
    printf("Patched Heap Implementation Test Suite\n");
    printf("========================================\n\n");
    
    // Test 1: Heap initialization
    TEST("Heap_Init");
    if (Heap_Init() == 0) {
        PASS();
    } else {
        FAIL("Heap_Init returned non-zero");
        return 1;
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
    TEST("Sovereign_Heap_Free");
    if (p1 != NULL) {
        if (Sovereign_Heap_Free(p1)) {
            PASS();
        } else {
            FAIL("Sovereign_Heap_Free returned 0");
        }
    } else {
        FAIL("Cannot test - allocation failed");
    }
    
    // Test 4: Free NULL (should succeed)
    TEST("Sovereign_Heap_Free(NULL)");
    if (Sovereign_Heap_Free(NULL)) {
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
            Sovereign_Heap_Free(blocks[i]);
        }
        PASS();
    } else {
        for (int i = 0; i < 10; i++) {
            if (blocks[i]) Sovereign_Heap_Free(blocks[i]);
        }
        FAIL("Some allocations failed");
    }
    
    // Test 6: Realloc
    TEST("Sovereign_Heap_Realloc");
    void* r1 = Heap_Alloc(100);
    if (r1 != NULL) {
        void* r2 = Sovereign_Heap_Realloc(r1, 200);
        if (r2 != NULL) {
            Sovereign_Heap_Free(r2);
            PASS();
        } else {
            Sovereign_Heap_Free(r1);
            FAIL("Realloc returned NULL");
        }
    } else {
        FAIL("Allocation failed");
    }
    
    // Test 7: Large allocation
    TEST("Large allocation (1MB)");
    void* large = Heap_Alloc(1024 * 1024);
    if (large != NULL) {
        memset(large, 0x42, 1024 * 1024);
        Sovereign_Heap_Free(large);
        PASS();
    } else {
        FAIL("Large allocation failed");
    }
    
    // Test 8: Cleanup
    TEST("Heap_Cleanup");
    Heap_Cleanup();
    PASS();
    
    printf("\n========================================\n");
    printf("Test Results\n");
    printf("========================================\n");
    printf("Passed: %d\n", g_tests_passed);
    printf("Failed: %d\n", g_tests_failed);
    printf("Total:  %d\n", g_tests_passed + g_tests_failed);
    
    return g_tests_failed > 0 ? 1 : 0;
}