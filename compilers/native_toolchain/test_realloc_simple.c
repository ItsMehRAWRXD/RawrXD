#include <stdio.h>
#include <windows.h>

extern int Heap_Init(void);
extern void* Heap_Alloc(unsigned long long size);
extern int Sovereign_Heap_Free(void* ptr);
extern void* Sovereign_Heap_Realloc(void* ptr, unsigned long long size);

int main(void) {
    printf("Testing Realloc...\n");
    
    // Init
    printf("1. Heap_Init: ");
    int init_result = Heap_Init();
    printf("%d\n", init_result);
    
    // Alloc
    printf("2. Heap_Alloc(100): ");
    void* p = Heap_Alloc(100);
    printf("%p\n", p);
    
    // Realloc
    printf("3. Sovereign_Heap_Realloc(%p, 200): ", p);
    void* p2 = Sovereign_Heap_Realloc(p, 200);
    printf("%p\n", p2);
    
    // Free
    printf("4. Sovereign_Heap_Free(%p): ", p2 ? p2 : p);
    int free_result = Sovereign_Heap_Free(p2 ? p2 : p);
    printf("%d\n", free_result);
    
    printf("\nDone!\n");
    return 0;
}
