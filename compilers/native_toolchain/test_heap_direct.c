// Direct heap test - call Windows API directly
#include <stdio.h>
#include <windows.h>

int main(void) {
    printf("Testing Windows heap directly...\n");
    
    // Get process heap
    printf("1. GetProcessHeap: ");
    HANDLE hHeap = GetProcessHeap();
    if (hHeap != NULL) {
        printf("PASS (handle=%p)\n", hHeap);
    } else {
        printf("FAIL\n");
        return 1;
    }
    
    // Allocate
    printf("2. HeapAlloc: ");
    void* p = HeapAlloc(hHeap, 0, 1024);
    if (p != NULL) {
        printf("PASS (ptr=%p)\n", p);
    } else {
        printf("FAIL\n");
        return 1;
    }
    
    // Free
    printf("3. HeapFree: ");
    BOOL result = HeapFree(hHeap, 0, p);
    if (result) {
        printf("PASS\n");
    } else {
        printf("FAIL (error=%lu)\n", GetLastError());
        return 1;
    }
    
    printf("\nAll tests passed!\n");
    return 0;
}