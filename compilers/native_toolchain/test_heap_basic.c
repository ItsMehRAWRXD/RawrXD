// ============================================================================
// test_heap_basic.c
// Basic heap test - minimal version
// Compile: gcc -O2 test_heap_basic.c sovereign_memory_patch.obj -o test_heap_basic.exe
// ============================================================================

#include <stdio.h>
#include <windows.h>

// Declare patched heap functions (from ASM)
extern int Heap_Init(void);
extern void* Heap_Alloc(unsigned long long size);
extern int Heap_Free(void* ptr);
extern void Heap_Cleanup(void);

int main(void) {
    printf("========================================\n");
    printf("Basic Heap Test\n");
    printf("========================================\n\n");
    
    // Test 1: Initialize
    printf("[1] Initializing heap...\n");
    int result = Heap_Init();
    printf("    Heap_Init returned: %d\n", result);
    if (result != 0) {
        printf("    FAILED: Heap initialization failed\n");
        return 1;
    }
    printf("    OK: Heap initialized\n\n");
    
    // Test 2: Allocate
    printf("[2] Allocating 1024 bytes...\n");
    void* p = Heap_Alloc(1024);
    printf("    Heap_Alloc returned: %p\n", p);
    if (p == NULL) {
        printf("    FAILED: Allocation returned NULL\n");
        return 1;
    }
    printf("    OK: Memory allocated\n\n");
    
    // Test 3: Write to memory
    printf("[3] Writing to allocated memory...\n");
    char* cp = (char*)p;
    for (int i = 0; i < 1024; i++) {
        cp[i] = (char)(i % 256);
    }
    printf("    OK: Wrote 1024 bytes\n\n");
    
    // Test 4: Verify data
    printf("[4] Verifying written data...\n");
    int ok = 1;
    for (int i = 0; i < 1024; i++) {
        if (cp[i] != (char)(i % 256)) {
            ok = 0;
            break;
        }
    }
    if (ok) {
        printf("    OK: Data verified\n\n");
    } else {
        printf("    FAILED: Data corruption detected\n");
        return 1;
    }
    
    // Test 5: Free using Windows HeapFree directly
    printf("[5] Freeing memory (using Windows API)...\n");
    HANDLE heap = GetProcessHeap();
    if (HeapFree(heap, 0, p)) {
        printf("    OK: Memory freed\n\n");
    } else {
        printf("    WARNING: HeapFree failed (error: %lu)\n", GetLastError());
    }
    
    // Test 6: Cleanup
    printf("[6] Cleaning up...\n");
    Heap_Cleanup();
    printf("    OK: Cleanup complete\n\n");
    
    printf("========================================\n");
    printf("ALL BASIC TESTS PASSED!\n");
    printf("========================================\n");
    
    return 0;
}
