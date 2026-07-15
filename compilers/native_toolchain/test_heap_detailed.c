// Detailed heap test - print each step
#include <stdio.h>
#include <windows.h>

extern int Heap_Init(void);
extern void* Heap_Alloc(unsigned long long size);
extern int Heap_Free(void* ptr);

int main(void) {
    printf("Testing patched heap with detailed debug...\n");
    printf("==========================================\n\n");
    
    // Test 1: Init
    printf("Step 1: Heap_Init\n");
    printf("  Calling Heap_Init()...\n");
    fflush(stdout);
    int init_result = Heap_Init();
    printf("  Result: %d\n", init_result);
    if (init_result != 0) {
        printf("  FAIL: Heap_Init returned %d (expected 0)\n", init_result);
        return 1;
    }
    printf("  PASS\n\n");
    
    // Test 2: Alloc
    printf("Step 2: Heap_Alloc\n");
    printf("  Calling Heap_Alloc(1024)...\n");
    fflush(stdout);
    void* p = Heap_Alloc(1024);
    printf("  Result: %p\n", p);
    if (p == NULL) {
        printf("  FAIL: Heap_Alloc returned NULL\n");
        return 1;
    }
    printf("  PASS\n\n");
    
    // Test 3: Free
    printf("Step 3: Heap_Free\n");
    printf("  Calling Heap_Free(%p)...\n", p);
    printf("  About to enter Heap_Free...\n");
    fflush(stdout);
    int free_result = Heap_Free(p);
    printf("  Result: %d\n", free_result);
    if (free_result == 0) {
        printf("  FAIL: Heap_Free returned 0 (expected 1)\n");
        return 1;
    }
    printf("  PASS\n\n");
    
    printf("==========================================\n");
    printf("All tests passed!\n");
    return 0;
}