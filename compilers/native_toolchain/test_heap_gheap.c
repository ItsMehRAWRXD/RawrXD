// Test g_heap access
#include <stdio.h>
#include <windows.h>

extern int Heap_Init(void);
extern void* Heap_Alloc(unsigned long long size);
extern int Heap_Free(void* ptr);
extern void* g_heap;

int main(void) {
    printf("Testing g_heap access...\n");
    
    // Test 1: Init
    printf("1. Heap_Init: ");
    fflush(stdout);
    int init_result = Heap_Init();
    printf("result=%d\n", init_result);
    
    // Check g_heap
    printf("   g_heap = %p\n", g_heap);
    
    // Test 2: Alloc
    printf("2. Heap_Alloc(1024): ");
    fflush(stdout);
    void* p = Heap_Alloc(1024);
    printf("ptr=%p\n", p);
    
    // Check g_heap again
    printf("   g_heap = %p\n", g_heap);
    
    // Test 3: Free
    printf("3. Heap_Free(%p):\n", p);
    printf("   g_heap before call = %p\n", g_heap);
    fflush(stdout);
    
    // Call HeapFree directly to test
    HANDLE hHeap = GetProcessHeap();
    printf("   GetProcessHeap() = %p\n", hHeap);
    printf("   Calling HeapFree directly...\n");
    fflush(stdout);
    BOOL result = HeapFree(hHeap, 0, p);
    printf("   HeapFree result = %d\n", result);
    
    printf("\nAll tests passed!\n");
    return 0;
}