/* sovereign_heap_c.c - Fixed Heap Implementation for Sovereign
 * Uses Windows process heap - no custom heap code
 * Compile: cl /O2 /W4 /Fe:sovereign_heap_c.exe sovereign_heap_c.c
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

// Global heap handle
static HANDLE g_heap = NULL;
static BOOL g_heap_owned = FALSE;

// Initialize heap using Windows process heap
int Heap_Init_Fixed(void) {
    // Check if already initialized
    if (g_heap != NULL) {
        return 0;  // Already initialized = success
    }
    
    // Get process heap (always available, already initialized by Windows)
    g_heap = GetProcessHeap();
    if (g_heap == NULL) {
        return 1;  // Failure
    }
    
    // Using process heap - we don't own it, Windows manages it
    g_heap_owned = FALSE;
    
    return 0;  // Success
}

// Allocate memory from heap
void* Heap_Alloc_Fixed(size_t size) {
    // Ensure heap is initialized
    if (g_heap == NULL) {
        if (Heap_Init_Fixed() != 0) {
            return NULL;
        }
    }
    
    // Allocate with zero initialization
    return HeapAlloc(g_heap, HEAP_ZERO_MEMORY, size);
}

// Free allocated memory
BOOL Heap_Free_Fixed(void* ptr) {
    // NULL pointer is valid (no-op)
    if (ptr == NULL) {
        return TRUE;
    }
    
    // Ensure heap is initialized
    if (g_heap == NULL) {
        return FALSE;
    }
    
    // Free the memory
    return HeapFree(g_heap, 0, ptr);
}

// Reallocate memory
void* Heap_Realloc_Fixed(void* ptr, size_t new_size) {
    // Ensure heap is initialized
    if (g_heap == NULL) {
        if (Heap_Init_Fixed() != 0) {
            return NULL;
        }
    }
    
    // Reallocate
    return HeapReAlloc(g_heap, HEAP_ZERO_MEMORY, ptr, new_size);
}

// Cleanup heap (for custom heaps only)
void Heap_Cleanup_Fixed(void) {
    // Only destroy if we own the heap
    if (g_heap_owned && g_heap != NULL) {
        HeapDestroy(g_heap);
    }
    g_heap = NULL;
    g_heap_owned = FALSE;
}

// Test function
int main(void) {
    printf("Sovereign Heap Fix Test\n");
    printf("=======================\n\n");
    
    // Test 1: Initialize heap
    printf("Test 1: Heap initialization... ");
    int result = Heap_Init_Fixed();
    if (result != 0) {
        printf("FAILED (code %d)\n", result);
        return 1;
    }
    printf("PASSED\n");
    
    // Test 2: Allocate memory
    printf("Test 2: Memory allocation... ");
    void* ptr1 = Heap_Alloc_Fixed(1024);
    if (ptr1 == NULL) {
        printf("FAILED (NULL pointer)\n");
        return 2;
    }
    printf("PASSED (ptr=%p)\n", ptr1);
    
    // Test 3: Write to memory
    printf("Test 3: Memory write... ");
    memset(ptr1, 0xAB, 1024);
    printf("PASSED\n");
    
    // Test 4: Allocate more memory
    printf("Test 4: Second allocation... ");
    void* ptr2 = Heap_Alloc_Fixed(4096);
    if (ptr2 == NULL) {
        printf("FAILED\n");
        Heap_Free_Fixed(ptr1);
        return 3;
    }
    printf("PASSED (ptr=%p)\n", ptr2);
    
    // Test 5: Free memory
    printf("Test 5: Free first block... ");
    if (!Heap_Free_Fixed(ptr1)) {
        printf("FAILED\n");
        return 4;
    }
    printf("PASSED\n");
    
    // Test 6: Free second block
    printf("Test 6: Free second block... ");
    if (!Heap_Free_Fixed(ptr2)) {
        printf("FAILED\n");
        return 5;
    }
    printf("PASSED\n");
    
    // Test 7: NULL free (should succeed)
    printf("Test 7: Free NULL pointer... ");
    if (!Heap_Free_Fixed(NULL)) {
        printf("FAILED\n");
        return 6;
    }
    printf("PASSED\n");
    
    // Test 8: Reallocate
    printf("Test 8: Reallocate... ");
    void* ptr3 = Heap_Alloc_Fixed(256);
    if (ptr3 == NULL) {
        printf("FAILED (alloc)\n");
        return 7;
    }
    void* ptr4 = Heap_Realloc_Fixed(ptr3, 512);
    if (ptr4 == NULL) {
        printf("FAILED (realloc)\n");
        Heap_Free_Fixed(ptr3);
        return 8;
    }
    Heap_Free_Fixed(ptr4);
    printf("PASSED\n");
    
    printf("\n=======================\n");
    printf("ALL TESTS PASSED!\n");
    printf("Heap fix is working correctly.\n");
    
    return 0;
}
