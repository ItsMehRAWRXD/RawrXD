/*
 * RawrXD Memory Profiler - Tracks allocation patterns and detects leaks
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
    #include <windows.h>
    #include <psapi.h>
#else
    #include <sys/resource.h>
#endif

#define MAX_ALLOCATIONS 10000
#define ALLOCATION_TRACKING 1

/* Allocation tracking */
typedef struct {
    void *ptr;
    size_t size;
    const char *file;
    int line;
    int freed;
} allocation_t;

static allocation_t allocations[MAX_ALLOCATIONS];
static int allocation_count = 0;
static size_t total_allocated = 0;
static size_t total_freed = 0;
static size_t peak_allocated = 0;
static size_t current_allocated = 0;

/* Custom malloc with tracking */
void* tracked_malloc(size_t size, const char *file, int line) {
    void *ptr = malloc(size);
    if (ptr && ALLOCATION_TRACKING) {
        if (allocation_count < MAX_ALLOCATIONS) {
            allocations[allocation_count].ptr = ptr;
            allocations[allocation_count].size = size;
            allocations[allocation_count].file = file;
            allocations[allocation_count].line = line;
            allocations[allocation_count].freed = 0;
            allocation_count++;
        }
        total_allocated += size;
        current_allocated += size;
        if (current_allocated > peak_allocated) {
            peak_allocated = current_allocated;
        }
    }
    return ptr;
}

/* Custom free with tracking */
void tracked_free(void *ptr) {
    if (ptr && ALLOCATION_TRACKING) {
        for (int i = 0; i < allocation_count; i++) {
            if (allocations[i].ptr == ptr && !allocations[i].freed) {
                allocations[i].freed = 1;
                total_freed += allocations[i].size;
                current_allocated -= allocations[i].size;
                break;
            }
        }
    }
    free(ptr);
}

#define TMALLOC(size) tracked_malloc(size, __FILE__, __LINE__)
#define TFREE(ptr) tracked_free(ptr)

/* Get system memory info */
size_t get_system_memory() {
#ifdef _WIN32
    MEMORYSTATUSEX status;
    status.dwLength = sizeof(status);
    GlobalMemoryStatusEx(&status);
    return status.ullTotalPhys;
#else
    long pages = sysconf(_SC_PHYS_PAGES);
    long page_size = sysconf(_SC_PAGE_SIZE);
    return pages * page_size;
#endif
}

/* Get process memory */
size_t get_process_memory() {
#ifdef _WIN32
    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        return pmc.WorkingSetSize;
    }
    return 0;
#else
    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage) == 0) {
        return usage.ru_maxrss * 1024;
    }
    return 0;
#endif
}

/* Simulate memory-intensive operations */
void stress_memory_allocation() {
    /* Pattern 1: Many small allocations */
    void *small_allocs[1000];
    for (int i = 0; i < 1000; i++) {
        small_allocs[i] = TMALLOC(64 + (i % 256));
    }
    for (int i = 0; i < 1000; i++) {
        TFREE(small_allocs[i]);
    }
    
    /* Pattern 2: Few large allocations */
    void *large_allocs[10];
    for (int i = 0; i < 10; i++) {
        large_allocs[i] = TMALLOC(1024 * 1024); /* 1MB each */
    }
    for (int i = 0; i < 10; i++) {
        TFREE(large_allocs[i]);
    }
    
    /* Pattern 3: Mixed sizes */
    void *mixed[100];
    for (int i = 0; i < 100; i++) {
        size_t size = 256 << (i % 8); /* 256B to 32KB */
        mixed[i] = TMALLOC(size);
    }
    for (int i = 0; i < 100; i++) {
        TFREE(mixed[i]);
    }
    
    /* Pattern 4: Allocation stress (allocate and free rapidly) */
    for (int round = 0; round < 100; round++) {
        void *temp = TMALLOC(4096);
        TFREE(temp);
    }
}

/* Simulate kernel memory patterns */
void simulate_kernel_memory() {
    /* Simulate attention mechanism memory pattern */
    int seq_len = 512;
    int head_dim = 128;
    int num_heads = 32;
    
    /* Q, K, V matrices */
    float *Q = TMALLOC(seq_len * head_dim * num_heads * sizeof(float));
    float *K = TMALLOC(seq_len * head_dim * num_heads * sizeof(float));
    float *V = TMALLOC(seq_len * head_dim * num_heads * sizeof(float));
    float *scores = TMALLOC(seq_len * seq_len * num_heads * sizeof(float));
    float *output = TMALLOC(seq_len * head_dim * num_heads * sizeof(float));
    
    /* Simulate computation */
    memset(Q, 0, seq_len * head_dim * num_heads * sizeof(float));
    memset(K, 0, seq_len * head_dim * num_heads * sizeof(float));
    memset(V, 0, seq_len * head_dim * num_heads * sizeof(float));
    
    /* Cleanup */
    TFREE(Q);
    TFREE(K);
    TFREE(V);
    TFREE(scores);
    TFREE(output);
}

/* Check for memory leaks */
int check_leaks() {
    int leaks = 0;
    size_t leaked_bytes = 0;
    
    for (int i = 0; i < allocation_count; i++) {
        if (!allocations[i].freed) {
            leaks++;
            leaked_bytes += allocations[i].size;
        }
    }
    
    if (leaks > 0) {
        printf("\n⚠ MEMORY LEAKS DETECTED:\n");
        printf("  Leaked allocations: %d\n", leaks);
        printf("  Leaked bytes: %zu\n", leaked_bytes);
        
        /* Show first few leaks */
        int shown = 0;
        for (int i = 0; i < allocation_count && shown < 5; i++) {
            if (!allocations[i].freed) {
                printf("  - %p: %zu bytes at %s:%d\n",
                       allocations[i].ptr,
                       allocations[i].size,
                       allocations[i].file,
                       allocations[i].line);
                shown++;
            }
        }
        if (leaks > shown) {
            printf("  ... and %d more\n", leaks - shown);
        }
        return leaks;
    }
    
    return 0;
}

int main() {
    printf("RawrXD Memory Profiler\n");
    printf("======================\n");
    printf("System Memory: %zu MB\n", get_system_memory() / (1024 * 1024));
    printf("\n");
    
    size_t initial_memory = get_process_memory();
    printf("Initial Process Memory: %zu KB\n", initial_memory / 1024);
    printf("\n");
    
    /* Run memory stress tests */
    printf("Running memory stress tests...\n");
    
    printf("  Test 1: Small allocations... ");
    stress_memory_allocation();
    printf("Done\n");
    
    printf("  Test 2: Kernel simulation... ");
    simulate_kernel_memory();
    printf("Done\n");
    
    printf("  Test 3: Repeated patterns... ");
    for (int i = 0; i < 10; i++) {
        stress_memory_allocation();
        simulate_kernel_memory();
    }
    printf("Done\n");
    
    /* Results */
    printf("\n");
    printf("======================\n");
    printf("Memory Profile Results\n");
    printf("======================\n");
    printf("Total Allocations:   %d\n", allocation_count);
    printf("Total Allocated:     %zu KB\n", total_allocated / 1024);
    printf("Total Freed:         %zu KB\n", total_freed / 1024);
    printf("Peak Allocated:      %zu KB\n", peak_allocated / 1024);
    printf("Current Allocated:   %zu KB\n", current_allocated / 1024);
    printf("\n");
    
    size_t final_memory = get_process_memory();
    printf("Final Process Memory:  %zu KB\n", final_memory / 1024);
    printf("Memory Growth:       %zu KB\n", 
           (final_memory > initial_memory) ? (final_memory - initial_memory) / 1024 : 0);
    printf("\n");
    
    /* Check for leaks */
    int leaks = check_leaks();
    
    printf("\n");
    printf("======================\n");
    
    if (leaks == 0) {
        printf("✓ PASS: No memory leaks detected\n");
        printf("  All allocations properly freed\n");
        printf("  Peak usage: %zu KB\n", peak_allocated / 1024);
        return 0;
    } else {
        printf("✗ FAIL: %d memory leak(s) detected\n", leaks);
        return 1;
    }
}
