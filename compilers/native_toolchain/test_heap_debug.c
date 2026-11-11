// Debug heap test - print each step
#include <stdio.h>
#include <windows.h>

extern int Heap_Init(void);
extern void* Heap_Alloc(unsigned long long size);
extern int Heap_Free(void* ptr);

int main(void) {
    printf("Testing patched heap with debug...\n");
    
    // Test 1: Init
    printf("1. Heap_Init: ");
    fflush(stdout);
    int init_result = Heap_Init();
    printf("result=%d ", init_result);
    if (init_result == 0) {
        printf("PASS\n");
    } else {
        printf("FAIL\n");
        return 1;
    }
    
    // Test 2: Alloc
    printf("2. Heap_Alloc(1024): ");
    fflush(stdout);
    void* p = Heap_Alloc(1024);
    printf("ptr=%p ", p);
    if (p != NULL) {
        printf("PASS\n");
    } else {
        printf("FAIL\n");
        return 1;
    }
    
    // Test 3: Free
    printf("3. Heap_Free(%p): ", p);
    fflush(stdout);
    printf("calling Heap_Free... ");
    fflush(stdout);
    int free_result = Heap_Free(p);
    printf("result=%d ", free_result);
    if (free_result) {
        printf("PASS\n");
    } else {
        printf("FAIL\n");
        return 1;
    }
    
    printf("\nAll tests passed!\n");
    return 0;
}