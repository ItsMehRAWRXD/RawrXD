//=============================================================================
// memory_profiler.c - Memory Profiler
// Production-ready memory profiling with leak detection and heap analysis
//=============================================================================

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <windows.h>

//=============================================================================
// Memory Profiler Types
//=============================================================================

#define MAX_ALLOCATIONS 100000
#define MAX_STACK_DEPTH 32
#define MAX_CATEGORIES 50

typedef enum {
    ALLOC_MALLOC,
    ALLOC_CALLOC,
    ALLOC_REALLOC,
    ALLOC_NEW,
    ALLOC_NEW_ARRAY
} AllocType;

typedef struct {
    void* address;
    size_t size;
    AllocType type;
    char category[64];
    char file[256];
    int line;
    char function[128];
    uint64_t timestamp;
    int is_freed;
    void* stack_trace[MAX_STACK_DEPTH];
    int stack_depth;
} AllocationRecord;

typedef struct {
    char category[64];
    size_t current_bytes;
    size_t peak_bytes;
    uint64_t total_allocations;
    uint64_t active_allocations;
    size_t total_allocated_bytes;
    size_t total_freed_bytes;
} MemoryCategory;

typedef struct {
    AllocationRecord* allocations;
    int alloc_count;
    int alloc_capacity;
    
    MemoryCategory* categories;
    int category_count;
    int category_capacity;
    
    size_t current_bytes;
    size_t peak_bytes;
    uint64_t total_allocations;
    uint64_t total_frees;
    
    int is_tracking;
    int track_stack_traces;
} MemoryProfiler;

//=============================================================================
// Memory Profiler Implementation
//=============================================================================

MemoryProfiler* mem_profiler_create(void) {
    MemoryProfiler* prof = (MemoryProfiler*)calloc(1, sizeof(MemoryProfiler));
    prof->alloc_capacity = MAX_ALLOCATIONS;
    prof->allocations = (AllocationRecord*)calloc(prof->alloc_capacity, sizeof(AllocationRecord));
    prof->category_capacity = MAX_CATEGORIES;
    prof->categories = (MemoryCategory*)calloc(prof->category_capacity, sizeof(MemoryCategory));
    prof->is_tracking = 1;
    return prof;
}

void mem_profiler_destroy(MemoryProfiler* prof) {
    if (!prof) return;
    free(prof->allocations);
    free(prof->categories);
    free(prof);
}

MemoryCategory* get_category(MemoryProfiler* prof, const char* name) {
    for (int i = 0; i < prof->category_count; i++) {
        if (strcmp(prof->categories[i].category, name) == 0) {
            return &prof->categories[i];
        }
    }
    
    if (prof->category_count >= prof->category_capacity) return NULL;
    
    MemoryCategory* cat = &prof->categories[prof->category_count++];
    strncpy(cat->category, name, sizeof(cat->category) - 1);
    return cat;
}

void* tracked_malloc(MemoryProfiler* prof, size_t size, const char* file,
                     int line, const char* func, const char* category) {
    void* ptr = malloc(size);
    if (!ptr || !prof->is_tracking) return ptr;
    
    if (prof->alloc_count >= prof->alloc_capacity) return ptr;
    
    AllocationRecord* rec = &prof->allocations[prof->alloc_count++];
    rec->address = ptr;
    rec->size = size;
    rec->type = ALLOC_MALLOC;
    strncpy(rec->category, category, sizeof(rec->category) - 1);
    strncpy(rec->file, file, sizeof(rec->file) - 1);
    rec->line = line;
    strncpy(rec->function, func, sizeof(rec->function) - 1);
    rec->timestamp = (uint64_t)time(NULL);
    rec->is_freed = 0;
    
    // Update category stats
    MemoryCategory* cat = get_category(prof, category);
    if (cat) {
        cat->current_bytes += size;
        cat->total_allocations++;
        cat->active_allocations++;
        cat->total_allocated_bytes += size;
        if (cat->current_bytes > cat->peak_bytes) {
            cat->peak_bytes = cat->current_bytes;
        }
    }
    
    // Update global stats
    prof->current_bytes += size;
    prof->total_allocations++;
    if (prof->current_bytes > prof->peak_bytes) {
        prof->peak_bytes = prof->current_bytes;
    }
    
    return ptr;
}

void tracked_free(MemoryProfiler* prof, void* ptr) {
    if (!ptr) return;
    
    // Find allocation record
    for (int i = 0; i < prof->alloc_count; i++) {
        AllocationRecord* rec = &prof->allocations[i];
        if (rec->address == ptr && !rec->is_freed) {
            rec->is_freed = 1;
            
            // Update category stats
            MemoryCategory* cat = get_category(prof, rec->category);
            if (cat) {
                cat->current_bytes -= rec->size;
                cat->active_allocations--;
                cat->total_freed_bytes += rec->size;
            }
            
            prof->current_bytes -= rec->size;
            prof->total_frees++;
            break;
        }
    }
    
    free(ptr);
}

//=============================================================================
// Report Generation
//=============================================================================

void print_mem_summary(MemoryProfiler* prof) {
    printf("\n");
    printf("=============================================================================\n");
    printf("  Memory Profile Summary\n");
    printf("=============================================================================\n");
    printf("  Current Allocated:    %zu bytes (%.2f MB)\n",
           prof->current_bytes, prof->current_bytes / (1024.0 * 1024));
    printf("  Peak Allocated:       %zu bytes (%.2f MB)\n",
           prof->peak_bytes, prof->peak_bytes / (1024.0 * 1024));
    printf("  Total Allocations:    %llu\n", prof->total_allocations);
    printf("  Total Frees:          %llu\n", prof->total_frees);
    printf("  Active Allocations:   %llu\n", prof->total_allocations - prof->total_frees);
    printf("=============================================================================\n");
}

void print_category_breakdown(MemoryProfiler* prof) {
    printf("\n");
    printf("=============================================================================\n");
    printf("  Memory by Category\n");
    printf("=============================================================================");
    printf("\n  %-20s %12s %12s %12s %12s\n",
           "Category", "Current", "Peak", "Allocs", "Active");
    printf("  ---------------------------------------------------------------------------\n");
    
    for (int i = 0; i < prof->category_count; i++) {
        MemoryCategory* cat = &prof->categories[i];
        printf("  %-20s %10.2fMB %10.2fMB %10llu %10llu\n",
               cat->category,
               cat->current_bytes / (1024.0 * 1024),
               cat->peak_bytes / (1024.0 * 1024),
               cat->total_allocations,
               cat->active_allocations);
    }
    
    printf("=============================================================================\n");
}

void print_leaks(MemoryProfiler* prof) {
    uint64_t leaks = 0;
    size_t leak_bytes = 0;
    
    for (int i = 0; i < prof->alloc_count; i++) {
        if (!prof->allocations[i].is_freed) {
            leaks++;
            leak_bytes += prof->allocations[i].size;
        }
    }
    
    printf("\n");
    printf("=============================================================================\n");
    printf("  Memory Leaks: %llu allocations, %zu bytes (%.2f MB)\n",
           leaks, leak_bytes, leak_bytes / (1024.0 * 1024));
    printf("=============================================================================\n");
    
    if (leaks > 0) {
        printf("\n  Top 10 Leaks:\n");
        printf("  %-40s %10s %20s\n", "Location", "Size", "Function");
        printf("  ---------------------------------------------------------------------------\n");
        
        int printed = 0;
        for (int i = 0; i < prof->alloc_count && printed < 10; i++) {
            AllocationRecord* rec = &prof->allocations[i];
            if (!rec->is_freed) {
                char location[256];
                snprintf(location, sizeof(location), "%s:%d", rec->file, rec->line);
                printf("  %-40s %10zu %20s\n", location, rec->size, rec->function);
                printed++;
            }
        }
        printf("=============================================================================\n");
    }
}

void export_mem_json(MemoryProfiler* prof, const char* filename) {
    FILE* f = fopen(filename, "w");
    if (!f) return;
    
    fprintf(f, "{\n");
    fprintf(f, "  \"summary\": {\n");
    fprintf(f, "    \"current_bytes\": %zu,\n", prof->current_bytes);
    fprintf(f, "    \"peak_bytes\": %zu,\n", prof->peak_bytes);
    fprintf(f, "    \"total_allocations\": %llu,\n", prof->total_allocations);
    fprintf(f, "    \"total_frees\": %llu\n", prof->total_frees);
    fprintf(f, "  },\n");
    fprintf(f, "  \"categories\": [\n");
    
    for (int i = 0; i < prof->category_count; i++) {
        MemoryCategory* cat = &prof->categories[i];
        fprintf(f, "    {\n");
        fprintf(f, "      \"name\": \"%s\",\n", cat->category);
        fprintf(f, "      \"current_bytes\": %zu,\n", cat->current_bytes);
        fprintf(f, "      \"peak_bytes\": %zu,\n", cat->peak_bytes);
        fprintf(f, "      \"total_allocations\": %llu\n", cat->total_allocations);
        fprintf(f, "    }%s\n", (i < prof->category_count - 1) ? "," : "");
    }
    
    fprintf(f, "  ]\n");
    fprintf(f, "}\n");
    
    fclose(f);
    printf("  Memory profile exported: %s\n", filename);
}

//=============================================================================
// Main Entry Point
//=============================================================================

int main(int argc, char* argv[]) {
    printf("RawrXD Memory Profiler\n");
    printf("=====================\n\n");
    
    MemoryProfiler* prof = mem_profiler_create();
    
    // Simulate allocations
    for (int i = 0; i < 100; i++) {
        void* p1 = tracked_malloc(prof, 1024, __FILE__, __LINE__, "main", "general");
        void* p2 = tracked_malloc(prof, 4096, __FILE__, __LINE__, "main", "buffers");
        
        // Free some
        if (i % 3 == 0) {
            tracked_free(prof, p1);
        }
        if (i % 5 == 0) {
            tracked_free(prof, p2);
        }
    }
    
    // Generate reports
    print_mem_summary(prof);
    print_category_breakdown(prof);
    print_leaks(prof);
    export_mem_json(prof, "memory_profile.json");
    
    printf("\nMemory profiling complete!\n");
    
    mem_profiler_destroy(prof);
    return 0;
}
