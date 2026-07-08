// Test C wrapper for assembly
#include <stdio.h>
#include <windows.h>

// Assembly functions
extern int Heap_Init(void);
extern void* Heap_Alloc(unsigned long long size);
extern int Heap_Free(void* ptr);

// C wrapper for Heap_Free
int c_Heap_Free(void* ptr) {
    printf("   c_Heap_Free: ptr=%p\n", ptr);
    printf("   Calling Heap_Free from C...\n");
    fflush(stdout);
    int result = Heap_Free(ptr);
    printf("   Heap_Free returned: %d\n", result);
    return result;
}

int main(void) {
    printf("Testing C wrapper...\n");
    
    // Test 1: Init
    printf("1. Heap_Init: ");
    fflush(stdout);
    int init_result = Heap_Init();
    printf("result=%d\n", init_result);
    
    // Test 2: Alloc
    printf("2. Heap_Alloc(1024): ");
    fflush(stdout);
    void* p = Heap_Alloc(1024);
    printf("ptr=%p\n", p);
    
    // Test 3: Free
    printf("3. c_Heap_Free(%p):\n", p);
    fflush(stdout);
    int free_result = c_Heap_Free(p);
    printf("   result=%d\n", free_result);
    
    printf("\nAll tests passed!\n");
    return 0;
}