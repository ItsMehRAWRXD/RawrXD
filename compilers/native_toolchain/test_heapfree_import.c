// Test calling HeapFree directly from assembly
#include <stdio.h>
#include <windows.h>

// Assembly wrapper for HeapFree
extern int my_HeapFree(void* ptr);

// Assembly wrapper for HeapAlloc
extern void* my_HeapAlloc(size_t size);

// Assembly wrapper for GetProcessHeap
extern void* my_GetProcessHeap(void);

int main(void) {
    printf("Testing HeapFree import...\n");
    
    // Get process heap
    printf("1. GetProcessHeap: ");
    void* hHeap = my_GetProcessHeap();
    if (hHeap) {
        printf("PASS (handle=%p)\n", hHeap);
    } else {
        printf("FAIL\n");
        return 1;
    }
    
    // Allocate
    printf("2. HeapAlloc: ");
    void* p = my_HeapAlloc(1024);
    if (p) {
        printf("PASS (ptr=%p)\n", p);
    } else {
        printf("FAIL\n");
        return 1;
    }
    
    // Free
    printf("3. HeapFree: ");
    int result = my_HeapFree(p);
    if (result) {
        printf("PASS\n");
    } else {
        printf("FAIL\n");
        return 1;
    }
    
    printf("\nAll tests passed!\n");
    return 0;
}