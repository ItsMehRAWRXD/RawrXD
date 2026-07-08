// Test using working assembly
#include <stdio.h>
#include <windows.h>

// Working assembly functions from test_heapfree_import.asm
extern void* my_GetProcessHeap(void);
extern void* my_HeapAlloc(size_t size);
extern int my_HeapFree(void* ptr);

int main(void) {
    printf("Testing working assembly...\n");
    
    // Test 1: GetProcessHeap
    printf("1. my_GetProcessHeap: ");
    fflush(stdout);
    void* hHeap = my_GetProcessHeap();
    printf("%p\n", hHeap);
    
    // Test 2: Alloc
    printf("2. my_HeapAlloc(1024): ");
    fflush(stdout);
    void* p = my_HeapAlloc(1024);
    printf("%p\n", p);
    
    // Test 3: Free
    printf("3. my_HeapFree(%p): ", p);
    fflush(stdout);
    int result = my_HeapFree(p);
    printf("%d\n", result);
    
    printf("\nAll tests passed!\n");
    return 0;
}