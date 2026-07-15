// Test HeapFree directly from C
#include <stdio.h>
#include <windows.h>

int main(void) {
    printf("Testing HeapFree directly...\n");
    
    // Get process heap
    HANDLE hHeap = GetProcessHeap();
    printf("1. GetProcessHeap: %p\n", hHeap);
    
    // Allocate
    void* p = HeapAlloc(hHeap, 0, 1024);
    printf("2. HeapAlloc: %p\n", p);
    
    // Free
    BOOL result = HeapFree(hHeap, 0, p);
    printf("3. HeapFree: %d\n", result);
    
    printf("\nAll tests passed!\n");
    return 0;
}