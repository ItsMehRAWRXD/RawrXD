// Test using renamed function
#include <stdio.h>
#include <windows.h>

// Functions from sovereign_memory_patch_fixed.asm
extern int Heap_Init(void);
extern void* Heap_Alloc(unsigned long long size);
extern int Sovereign_Heap_Free(void* ptr);

int main(void) {
    printf("Testing renamed function...\n");
    
    // Test 1: Init
    printf("1. Heap_Init: ");
    fflush(stdout);
    int init_result = Heap_Init();
    printf("%d\n", init_result);
    
    // Test 2: Alloc
    printf("2. Heap_Alloc(1024): ");
    fflush(stdout);
    void* p = Heap_Alloc(1024);
    printf("%p\n", p);
    
    // Test 3: Free
    printf("3. Sovereign_Heap_Free(%p): ", p);
    fflush(stdout);
    int free_result = Sovereign_Heap_Free(p);
    printf("%d\n", free_result);
    
    printf("\nAll tests passed!\n");
    return 0;
}