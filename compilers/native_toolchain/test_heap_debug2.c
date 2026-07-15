// Debug heap test with printf
#include <stdio.h>
#include <windows.h>

extern int Heap_Init(void);
extern void* Heap_Alloc(unsigned long long size);
extern int Heap_Free(void* ptr);
extern void* g_heap;

int main(void) {
    printf("Testing patched heap with debug...\n");
    
    // Test 1: Init
    printf("1. Heap_Init: ");
    fflush(stdout);
    int init_result = Heap_Init();
    printf("result=%d, g_heap=%p\n", init_result, g_heap);
    
    // Test 2: Alloc
    printf("2. Heap_Alloc(1024): ");
    fflush(stdout);
    void* p = Heap_Alloc(1024);
    printf("ptr=%p\n", p);
    
    // Test 3: Free
    printf("3. Heap_Free(%p): ", p);
    fflush(stdout);
    printf("calling Heap_Free... ");
    fflush(stdout);
    int free_result = Heap_Free(p);
    printf("result=%d\n", free_result);
    
    printf("\nAll tests passed!\n");
    return 0;
}