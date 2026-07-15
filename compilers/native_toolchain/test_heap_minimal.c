// Minimal heap test - just verify basic operations
#include <stdio.h>

extern int Heap_Init(void);
extern void* Heap_Alloc(unsigned long long size);
extern int Sovereign_Heap_Free(void* ptr);

int main(void) {
    printf("Testing patched heap...\n");
    
    // Test 1: Init
    printf("1. Heap_Init: ");
    if (Heap_Init() == 0) {
        printf("PASS\n");
    } else {
        printf("FAIL\n");
        return 1;
    }
    
    // Test 2: Alloc
    printf("2. Heap_Alloc: ");
    void* p = Heap_Alloc(1024);
    if (p != NULL) {
        printf("PASS (ptr=%p)\n", p);
    } else {
        printf("FAIL\n");
        return 1;
    }
    
    // Test 3: Free
    printf("3. Sovereign_Heap_Free: ");
    if (Sovereign_Heap_Free(p)) {
        printf("PASS\n");
    } else {
        printf("FAIL\n");
        return 1;
    }
    
    printf("\nAll tests passed!\n");
    return 0;
}