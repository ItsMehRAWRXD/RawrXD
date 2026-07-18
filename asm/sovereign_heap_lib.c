/* sovereign_heap_lib.c - Heap Fix Library for Sovereign Engine
 * Compile as library: gcc -c -O2 sovereign_heap_lib.c -o sovereign_heap_lib.o
 * Or: cl /c /O2 sovereign_heap_lib.c /Fo:sovereign_heap_lib.obj
 */

#include <windows.h>

// Global heap handle
static HANDLE g_heap = NULL;
static BOOL g_heap_initialized = FALSE;

// Initialize heap using Windows process heap
// Returns: 0 on success, non-zero on failure
__declspec(dllexport) int Heap_Init(void) {
    if (g_heap_initialized) {
        return 0;  // Already initialized
    }
    
    g_heap = GetProcessHeap();
    if (g_heap == NULL) {
        return 1;  // Failure
    }
    
    g_heap_initialized = TRUE;
    return 0;
}

// Allocate memory from heap
__declspec(dllexport) void* Heap_Alloc(size_t size) {
    if (!g_heap_initialized) {
        if (Heap_Init() != 0) {
            return NULL;
        }
    }
    
    return HeapAlloc(g_heap, HEAP_ZERO_MEMORY, size);
}

// Free allocated memory
__declspec(dllexport) int Heap_Free(void* ptr) {
    if (ptr == NULL) {
        return 1;  // Success (no-op)
    }
    
    if (!g_heap_initialized) {
        return 0;  // Failure - heap not initialized
    }
    
    return HeapFree(g_heap, 0, ptr) ? 1 : 0;
}

// Reallocate memory
__declspec(dllexport) void* Heap_Realloc(void* ptr, size_t new_size) {
    if (!g_heap_initialized) {
        if (Heap_Init() != 0) {
            return NULL;
        }
    }
    
    return HeapReAlloc(g_heap, HEAP_ZERO_MEMORY, ptr, new_size);
}

// Get heap statistics (for debugging)
__declspec(dllexport) void Heap_Stats(DWORD* total_heap_size, DWORD* total_committed) {
    if (!g_heap_initialized) {
        if (total_heap_size) *total_heap_size = 0;
        if (total_committed) *total_committed = 0;
        return;
    }
    
    // HeapCompact(g_heap, 0);  // Optional: compact heap first
    
    PROCESS_HEAP_ENTRY entry;
    DWORD total = 0;
    DWORD committed = 0;
    
    entry.lpData = NULL;
    while (HeapWalk(g_heap, &entry)) {
        if (entry.wFlags & PROCESS_HEAP_ENTRY_BUSY) {
            total += entry.cbData;
        }
        committed += entry.cbData + entry.cbOverhead;
    }
    
    if (total_heap_size) *total_heap_size = total;
    if (total_committed) *total_committed = committed;
}
