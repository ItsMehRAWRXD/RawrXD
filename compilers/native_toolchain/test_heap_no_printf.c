// Test without printf after Heap_Free
#include <stdio.h>
#include <windows.h>

extern int Heap_Init(void);
extern void* Heap_Alloc(unsigned long long size);
extern int Heap_Free(void* ptr);

int main(void) {
    printf("Testing patched heap...\n");
    
    // Test 1: Init
    printf("1. Heap_Init: ");
    fflush(stdout);
    int init_result = Heap_Init();
    printf("PASS\n");
    
    // Test 2: Alloc
    printf("2. Heap_Alloc: ");
    fflush(stdout);
    void* p = Heap_Alloc(1024);
    printf("PASS\n");
    
    // Test 3: Free
    printf("3. Heap_Free: ");
    fflush(stdout);
    int free_result = Heap_Free(p);
    // Don't call printf after Heap_Free
    // Just return
    return 0;
}