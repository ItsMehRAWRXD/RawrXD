//=============================================================================
// memory_leak_detector.c - Memory Leak Detector
// Production-ready memory tracking and leak detection
//=============================================================================

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

//=============================================================================
// Memory Tracking Types
//=============================================================================

#define MAX_ALLOCATIONS 10000
#define STACK_DEPTH 16
#define HASH_SIZE 1024

typedef struct Allocation {
    void* address;
    size_t size;
    char file[256];
    int line;
    char function[256];
    char stack_trace[STACK_DEPTH][256];
    int stack_depth;
    time_t timestamp;
    int is_freed;
    struct Allocation* next;
    struct Allocation* prev;
} Allocation;

typedef struct {
    Allocation* allocations[MAX_ALLOCATIONS];
    int count;
    size_t total_allocated;
    size_t total_freed;
    size_t current_used;
    size_t peak_used;
    int leak_count;
    int double_free_count;
    int invalid_free_count;
} MemoryTracker;

typedef struct {
    Allocation* buckets[HASH_SIZE];
    int allocation_count;
    int free_count;
    int leak_count;
    size_t total_leaked_bytes;
    Allocation* leaks[MAX_ALLOCATIONS];
    int leak_list_count;
} LeakReport;

//=============================================================================
// Memory Tracking Implementation
//=============================================================================

static MemoryTracker g_tracker = {0};
static int g_tracking_enabled = 0;

unsigned int hash_ptr(void* ptr) {
    return ((uintptr_t)ptr >> 3) % HASH_SIZE;
}

void memory_tracking_init(void) {
    memset(&g_tracker, 0, sizeof(g_tracker));
    g_tracking_enabled = 1;
}

void memory_tracking_shutdown(void) {
    g_tracking_enabled = 0;
}

void* tracked_malloc(size_t size, const char* file, int line, const char* func) {
    void* ptr = malloc(size);
    if (!ptr || !g_tracking_enabled) return ptr;
    
    if (g_tracker.count >= MAX_ALLOCATIONS) {
        return ptr;  // Tracking limit reached
    }
    
    Allocation* alloc = (Allocation*)calloc(1, sizeof(Allocation));
    alloc->address = ptr;
    alloc->size = size;
    strncpy(alloc->file, file, sizeof(alloc->file) - 1);
    alloc->line = line;
    strncpy(alloc->function, func, sizeof(alloc->function) - 1);
    alloc->timestamp = time(NULL);
    alloc->is_freed = 0;
    
    // Capture simplified stack trace
    alloc->stack_depth = 1;
    strncpy(alloc->stack_trace[0], func, sizeof(alloc->stack_trace[0]) - 1);
    
    g_tracker.allocations[g_tracker.count++] = alloc;
    g_tracker.total_allocated += size;
    g_tracker.current_used += size;
    
    if (g_tracker.current_used > g_tracker.peak_used) {
        g_tracker.peak_used = g_tracker.current_used;
    }
    
    return ptr;
}

void tracked_free(void* ptr, const char* file, int line, const char* func) {
    if (!ptr) return;
    
    if (!g_tracking_enabled) {
        free(ptr);
        return;
    }
    
    // Find allocation
    Allocation* alloc = NULL;
    for (int i = 0; i < g_tracker.count; i++) {
        if (g_tracker.allocations[i] && g_tracker.allocations[i]->address == ptr) {
            alloc = g_tracker.allocations[i];
            break;
        }
    }
    
    if (!alloc) {
        g_tracker.invalid_free_count++;
        printf("[MEMORY] Invalid free at %s:%d - pointer not allocated\n", file, line);
        free(ptr);
        return;
    }
    
    if (alloc->is_freed) {
        g_tracker.double_free_count++;
        printf("[MEMORY] Double free at %s:%d - already freed at %s:%d\n", 
               file, line, alloc->file, alloc->line);
        return;
    }
    
    alloc->is_freed = 1;
    g_tracker.total_freed += alloc->size;
    g_tracker.current_used -= alloc->size;
    
    free(ptr);
}

//=============================================================================
// Leak Detection
//=============================================================================

LeakReport* leak_create_report(void) {
    LeakReport* report = (LeakReport*)calloc(1, sizeof(LeakReport));
    return report;
}

void leak_destroy_report(LeakReport* report) {
    if (!report) return;
    
    // Free allocations
    for (int i = 0; i < g_tracker.count; i++) {
        if (g_tracker.allocations[i]) {
            free(g_tracker.allocations[i]);
            g_tracker.allocations[i] = NULL;
        }
    }
    
    free(report);
}

void detect_leaks(LeakReport* report) {
    report->leak_count = 0;
    report->total_leaked_bytes = 0;
    
    for (int i = 0; i < g_tracker.count; i++) {
        Allocation* alloc = g_tracker.allocations[i];
        if (alloc && !alloc->is_freed) {
            report->leaks[report->leak_list_count++] = alloc;
            report->leak_count++;
            report->total_leaked_bytes += alloc->size;
        }
    }
}

//=============================================================================
// Report Generation
//=============================================================================

void print_memory_summary(void) {
    printf("\n");
    printf("=============================================================================\n");
    printf("  Memory Usage Summary\n");
    printf("=============================================================================\n");
    printf("  Total Allocated:  %zu bytes\n", g_tracker.total_allocated);
    printf("  Total Freed:      %zu bytes\n", g_tracker.total_freed);
    printf("  Current Used:     %zu bytes\n", g_tracker.current_used);
    printf("  Peak Used:        %zu bytes\n", g_tracker.peak_used);
    printf("  Active Allocs:    %d\n", g_tracker.count);
    printf("\n");
    printf("  Errors:\n");
    printf("    Double Frees:   %d\n", g_tracker.double_free_count);
    printf("    Invalid Frees:  %d\n", g_tracker.invalid_free_count);
    printf("=============================================================================\n");
}

void print_leak_report(LeakReport* report) {
    printf("\n");
    printf("=============================================================================\n");
    printf("  Memory Leak Report\n");
    printf("=============================================================================\n");
    printf("  Leaks Found:      %d\n", report->leak_count);
    printf("  Leaked Bytes:     %zu\n", report->total_leaked_bytes);
    
    if (report->leak_count > 0) {
        printf("\n  Leaked Allocations:\n");
        printf("  ---------------------------------------------------------------------------\n");
        
        // Group by location
        for (int i = 0; i < report->leak_list_count && i < 20; i++) {
            Allocation* alloc = report->leaks[i];
            printf("  [%d] %zu bytes at %s:%d in %s\n",
                   i + 1, alloc->size, alloc->file, alloc->line, alloc->function);
        }
        
        if (report->leak_list_count > 20) {
            printf("  ... and %d more leaks\n", report->leak_list_count - 20);
        }
    } else {
        printf("\n  ✅ No memory leaks detected!\n");
    }
    
    printf("=============================================================================\n");
}

void export_leak_json(LeakReport* report, const char* filename) {
    FILE* f = fopen(filename, "w");
    if (!f) return;
    
    fprintf(f, "{\n");
    fprintf(f, "  \"summary\": {\n");
    fprintf(f, "    \"total_allocated\": %zu,\n", g_tracker.total_allocated);
    fprintf(f, "    \"total_freed\": %zu,\n", g_tracker.total_freed);
    fprintf(f, "    \"current_used\": %zu,\n", g_tracker.current_used);
    fprintf(f, "    \"peak_used\": %zu,\n", g_tracker.peak_used);
    fprintf(f, "    \"allocation_count\": %d,\n", g_tracker.count);
    fprintf(f, "    \"double_free_count\": %d,\n", g_tracker.double_free_count);
    fprintf(f, "    \"invalid_free_count\": %d,\n", g_tracker.invalid_free_count);
    fprintf(f, "    \"leak_count\": %d,\n", report->leak_count);
    fprintf(f, "    \"total_leaked_bytes\": %zu\n", report->total_leaked_bytes);
    fprintf(f, "  },\n");
    fprintf(f, "  \"leaks\": [\n");
    
    for (int i = 0; i < report->leak_list_count; i++) {
        Allocation* alloc = report->leaks[i];
        fprintf(f, "    {\n");
        fprintf(f, "      \"address\": \"%p\",\n", alloc->address);
        fprintf(f, "      \"size\": %zu,\n", alloc->size);
        fprintf(f, "      \"file\": \"%s\",\n", alloc->file);
        fprintf(f, "      \"line\": %d,\n", alloc->line);
        fprintf(f, "      \"function\": \"%s\",\n", alloc->function);
        fprintf(f, "      \"timestamp\": %ld\n", (long)alloc->timestamp);
        fprintf(f, "    }%s\n", (i < report->leak_list_count - 1) ? "," : "");
    }
    
    fprintf(f, "  ]\n");
    fprintf(f, "}\n");
    
    fclose(f);
    printf("  Leak report exported: %s\n", filename);
}

//=============================================================================
// Demo/Test Functions
//=============================================================================

void demo_memory_operations(void) {
    // Good allocations
    void* p1 = tracked_malloc(100, __FILE__, __LINE__, "demo_memory_operations");
    void* p2 = tracked_malloc(200, __FILE__, __LINE__, "demo_memory_operations");
    void* p3 = tracked_malloc(300, __FILE__, __LINE__, "demo_memory_operations");
    
    // Free some
    tracked_free(p1, __FILE__, __LINE__, "demo_memory_operations");
    tracked_free(p2, __FILE__, __LINE__, "demo_memory_operations");
    
    // Leak p3 intentionally
    
    // Test double free
    // tracked_free(p1, __FILE__, __LINE__, "demo_memory_operations");  // Would be double free
    
    // Test invalid free
    // int x;
    // tracked_free(&x, __FILE__, __LINE__, "demo_memory_operations");  // Would be invalid
}

//=============================================================================
// Main Entry Point
//=============================================================================

int main(int argc, char* argv[]) {
    printf("RawrXD Memory Leak Detector\n");
    printf("===========================\n\n");
    
    memory_tracking_init();
    
    // Run demo
    printf("Running memory operations demo...\n");
    demo_memory_operations();
    
    // Generate report
    print_memory_summary();
    
    LeakReport* report = leak_create_report();
    detect_leaks(report);
    print_leak_report(report);
    export_leak_json(report, "memory_leak_report.json");
    
    printf("\nMemory leak detection complete!\n");
    
    int exit_code = report->leak_count > 0 ? 1 : 0;
    leak_destroy_report(report);
    memory_tracking_shutdown();
    
    return exit_code;
}
