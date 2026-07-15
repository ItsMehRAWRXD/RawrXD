// test_heap.c - Test heap initialization for Sovereign Engine diagnostics
// Compile: cl test_heap.c /Fe:test_heap.exe

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

// MSVC SEH support
#ifdef _MSC_VER
#define TRY __try
#define EXCEPT(x) __except(x)
#else
#define TRY if(1)
#define EXCEPT(x) else if(0)
#endif

#define TEST_PASS "[PASS]"
#define TEST_FAIL "[FAIL]"
#define TEST_INFO "[INFO]"

typedef struct {
    const char* name;
    int passed;
    const char* details;
} TestResult;

TestResult results[20];
int result_count = 0;

void add_result(const char* name, int passed, const char* details) {
    if (result_count < 20) {
        results[result_count].name = name;
        results[result_count].passed = passed;
        results[result_count].details = details;
        result_count++;
    }
}

void print_results() {
    printf("\n========================================\n");
    printf("           TEST SUMMARY\n");
    printf("========================================\n");
    
    int passed = 0, failed = 0;
    for (int i = 0; i < result_count; i++) {
        const char* status = results[i].passed ? TEST_PASS : TEST_FAIL;
        printf("%s %s\n", status, results[i].name);
        if (results[i].details) {
            printf("       %s\n", results[i].details);
        }
        if (results[i].passed) passed++;
        else failed++;
    }
    
    printf("\n----------------------------------------\n");
    printf("Total: %d | Passed: %d | Failed: %d\n", result_count, passed, failed);
    printf("========================================\n");
}

int main() {
    printf("Sovereign Engine Heap Diagnostics\n");
    printf("=================================\n\n");
    
    // Test 1: GetProcessHeap
    printf("%s Test 1: GetProcessHeap\n", TEST_INFO);
    HANDLE hProcessHeap = GetProcessHeap();
    if (hProcessHeap != NULL) {
        char details[256];
        snprintf(details, sizeof(details), "Process heap handle: %p", hProcessHeap);
        add_result("GetProcessHeap", 1, details);
    } else {
        add_result("GetProcessHeap", 0, "Failed to get process heap");
    }
    
    // Test 2: HeapCreate
    printf("%s Test 2: HeapCreate\n", TEST_INFO);
    HANDLE hNewHeap = HeapCreate(0, 1024 * 1024, 0);
    if (hNewHeap != NULL) {
        char details[256];
        snprintf(details, sizeof(details), "New heap created: %p", hNewHeap);
        add_result("HeapCreate", 1, details);
    } else {
        DWORD error = GetLastError();
        char details[256];
        snprintf(details, sizeof(details), "Failed with error: %lu", error);
        add_result("HeapCreate", 0, details);
    }
    
    // Test 3: HeapAlloc from process heap
    printf("%s Test 3: HeapAlloc (Process Heap)\n", TEST_INFO);
    if (hProcessHeap) {
        void* ptr = HeapAlloc(hProcessHeap, 0, 1024);
        if (ptr != NULL) {
            char details[256];
            snprintf(details, sizeof(details), "Allocated 1024 bytes at %p", ptr);
            add_result("HeapAlloc (Process)", 1, details);
            HeapFree(hProcessHeap, 0, ptr);
        } else {
            DWORD error = GetLastError();
            char details[256];
            snprintf(details, sizeof(details), "Failed with error: %lu", error);
            add_result("HeapAlloc (Process)", 0, details);
        }
    } else {
        add_result("HeapAlloc (Process)", 0, "Skipped - no process heap");
    }
    
    // Test 4: HeapAlloc from new heap
    printf("%s Test 4: HeapAlloc (New Heap)\n", TEST_INFO);
    if (hNewHeap) {
        void* ptr = HeapAlloc(hNewHeap, 0, 4096);
        if (ptr != NULL) {
            char details[256];
            snprintf(details, sizeof(details), "Allocated 4096 bytes at %p", ptr);
            add_result("HeapAlloc (New)", 1, details);
            
            // Test 5: Memory write/read
            printf("%s Test 5: Memory Access\n", TEST_INFO);
            TRY {
                // Write pattern
                for (int i = 0; i < 1024; i++) {
                    ((char*)ptr)[i] = (char)(i % 256);
                }
                
                // Verify pattern
                int valid = 1;
                for (int i = 0; i < 1024; i++) {
                    if (((char*)ptr)[i] != (char)(i % 256)) {
                        valid = 0;
                        break;
                    }
                }
                
                if (valid) {
                    add_result("Memory Access", 1, "Read/write pattern verified");
                } else {
                    add_result("Memory Access", 0, "Pattern verification failed");
                }
                
                HeapFree(hNewHeap, 0, ptr);
            } EXCEPT(EXCEPTION_EXECUTE_HANDLER) {
                add_result("Memory Access", 0, "Access violation during read/write");
            }
        } else {
            DWORD error = GetLastError();
            char details[256];
            snprintf(details, sizeof(details), "Failed with error: %lu", error);
            add_result("HeapAlloc (New)", 0, details);
        }
        
        // Test 6: HeapDestroy
        printf("%s Test 6: HeapDestroy\n", TEST_INFO);
        if (HeapDestroy(hNewHeap)) {
            add_result("HeapDestroy", 1, "Heap destroyed successfully");
        } else {
            DWORD error = GetLastError();
            char details[256];
            snprintf(details, sizeof(details), "Failed with error: %lu", error);
            add_result("HeapDestroy", 0, details);
        }
    } else {
        add_result("HeapAlloc (New)", 0, "Skipped - no new heap");
        add_result("Memory Access", 0, "Skipped - no allocation");
        add_result("HeapDestroy", 0, "Skipped - no heap to destroy");
    }
    
    // Test 7: malloc/free (CRT)
    printf("%s Test 7: malloc/free (CRT)\n", TEST_INFO);
    void* crt_ptr = malloc(2048);
    if (crt_ptr != NULL) {
        char details[256];
        snprintf(details, sizeof(details), "malloc returned: %p", crt_ptr);
        add_result("malloc", 1, details);
        
        // Test write
        TRY {
            memset(crt_ptr, 0xAB, 2048);
            add_result("malloc write", 1, "Memory write successful");
        } EXCEPT(EXCEPTION_EXECUTE_HANDLER) {
            add_result("malloc write", 0, "Access violation during write");
        }
        
        free(crt_ptr);
        add_result("free", 1, "Memory freed");
    } else {
        add_result("malloc", 0, "malloc returned NULL");
        add_result("malloc write", 0, "Skipped");
        add_result("free", 0, "Skipped");
    }
    
    // Test 8: Large allocation
    printf("%s Test 8: Large Allocation (64MB)\n", TEST_INFO);
    void* large_ptr = HeapAlloc(hProcessHeap, 0, 64 * 1024 * 1024);
    if (large_ptr != NULL) {
        char details[256];
        snprintf(details, sizeof(details), "Allocated 64MB at %p", large_ptr);
        add_result("Large Allocation", 1, details);
        HeapFree(hProcessHeap, 0, large_ptr);
    } else {
        DWORD error = GetLastError();
        char details[256];
        snprintf(details, sizeof(details), "Failed with error: %lu", error);
        add_result("Large Allocation", 0, details);
    }
    
    // Test 9: VirtualAlloc
    printf("%s Test 9: VirtualAlloc\n", TEST_INFO);
    void* virt_ptr = VirtualAlloc(NULL, 1024 * 1024, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (virt_ptr != NULL) {
        char details[256];
        snprintf(details, sizeof(details), "Allocated 1MB at %p", virt_ptr);
        add_result("VirtualAlloc", 1, details);
        VirtualFree(virt_ptr, 0, MEM_RELEASE);
    } else {
        DWORD error = GetLastError();
        char details[256];
        snprintf(details, sizeof(details), "Failed with error: %lu", error);
        add_result("VirtualAlloc", 0, details);
    }
    
    print_results();
    
    // Return number of failures
    int failures = 0;
    for (int i = 0; i < result_count; i++) {
        if (!results[i].passed) failures++;
    }
    
    return failures > 0 ? 1 : 0;
}
