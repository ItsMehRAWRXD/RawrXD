//=============================================================================
// profiler.c - Performance Profiler for RawrXD Toolchain
// Production-ready profiling with timing, memory, and call graph analysis
//=============================================================================

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#pragma comment(lib, "psapi.lib")
#else
#include <sys/time.h>
#include <unistd.h>
#endif

//=============================================================================
// Profiler Configuration
//=============================================================================

#define MAX_FUNCTIONS 1024
#define MAX_CALL_DEPTH 256
#define MAX_CALL_EDGES 4096

//=============================================================================
// Data Structures
//=============================================================================

typedef struct {
    char name[256];
    char file[256];
    int line;
    
    // Timing
    uint64_t total_calls;
    uint64_t total_time_ns;
    uint64_t self_time_ns;
    uint64_t min_time_ns;
    uint64_t max_time_ns;
    
    // Memory
    uint64_t total_allocations;
    uint64_t total_bytes_allocated;
    uint64_t peak_memory_bytes;
    
    // Current state
    uint64_t call_start_time;
    uint64_t call_depth;
} FunctionProfile;

typedef struct {
    int caller_idx;
    int callee_idx;
    uint64_t call_count;
} CallEdge;

typedef struct {
    FunctionProfile functions[MAX_FUNCTIONS];
    int function_count;
    
    CallEdge call_graph[MAX_CALL_EDGES];
    int edge_count;
    
    int call_stack[MAX_CALL_DEPTH];
    int stack_depth;
    
    uint64_t program_start_time;
    uint64_t total_samples;
} ProfilerState;

static ProfilerState g_profiler = {0};
static int g_profiler_enabled = 0;

//=============================================================================
// High-Resolution Timing
//=============================================================================

uint64_t profiler_get_time_ns(void) {
#ifdef _WIN32
    LARGE_INTEGER freq, count;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&count);
    return (uint64_t)(count.QuadPart * 1000000000LL / freq.QuadPart);
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
#endif
}

//=============================================================================
// Function Registration
//=============================================================================

int profiler_register_function(const char* name, const char* file, int line) {
    if (!g_profiler_enabled) return -1;
    
    // Check if already registered
    for (int i = 0; i < g_profiler.function_count; i++) {
        if (strcmp(g_profiler.functions[i].name, name) == 0) {
            return i;
        }
    }
    
    if (g_profiler.function_count >= MAX_FUNCTIONS) {
        return -1;
    }
    
    FunctionProfile* func = &g_profiler.functions[g_profiler.function_count];
    strncpy(func->name, name, sizeof(func->name) - 1);
    strncpy(func->file, file, sizeof(func->file) - 1);
    func->line = line;
    func->min_time_ns = UINT64_MAX;
    func->max_time_ns = 0;
    
    return g_profiler.function_count++;
}

//=============================================================================
// Call Graph Management
//=============================================================================

void profiler_record_call(int caller_idx, int callee_idx) {
    if (caller_idx < 0 || callee_idx < 0) return;
    
    // Find or create edge
    for (int i = 0; i < g_profiler.edge_count; i++) {
        if (g_profiler.call_graph[i].caller_idx == caller_idx &&
            g_profiler.call_graph[i].callee_idx == callee_idx) {
            g_profiler.call_graph[i].call_count++;
            return;
        }
    }
    
    if (g_profiler.edge_count < MAX_CALL_EDGES) {
        CallEdge* edge = &g_profiler.call_graph[g_profiler.edge_count++];
        edge->caller_idx = caller_idx;
        edge->callee_idx = callee_idx;
        edge->call_count = 1;
    }
}

//=============================================================================
// Function Entry/Exit
//=============================================================================

void profiler_enter_function(int func_idx) {
    if (!g_profiler_enabled || func_idx < 0) return;
    
    FunctionProfile* func = &g_profiler.functions[func_idx];
    func->call_start_time = profiler_get_time_ns();
    func->call_depth++;
    func->total_calls++;
    
    // Record call edge
    if (g_profiler.stack_depth > 0) {
        int caller_idx = g_profiler.call_stack[g_profiler.stack_depth - 1];
        profiler_record_call(caller_idx, func_idx);
    }
    
    // Push to stack
    if (g_profiler.stack_depth < MAX_CALL_DEPTH) {
        g_profiler.call_stack[g_profiler.stack_depth++] = func_idx;
    }
}

void profiler_exit_function(int func_idx) {
    if (!g_profiler_enabled || func_idx < 0) return;
    
    uint64_t end_time = profiler_get_time_ns();
    FunctionProfile* func = &g_profiler.functions[func_idx];
    
    uint64_t elapsed = end_time - func->call_start_time;
    func->total_time_ns += elapsed;
    func->self_time_ns += elapsed;
    
    if (elapsed < func->min_time_ns) func->min_time_ns = elapsed;
    if (elapsed > func->max_time_ns) func->max_time_ns = elapsed;
    
    func->call_depth--;
    
    // Pop from stack
    if (g_profiler.stack_depth > 0) {
        g_profiler.stack_depth--;
    }
    
    // Subtract from caller's self time
    if (g_profiler.stack_depth > 0) {
        int caller_idx = g_profiler.call_stack[g_profiler.stack_depth - 1];
        g_profiler.functions[caller_idx].self_time_ns -= elapsed;
    }
}

//=============================================================================
// Memory Tracking
//=============================================================================

void profiler_record_allocation(int func_idx, size_t size) {
    if (!g_profiler_enabled || func_idx < 0) return;
    
    FunctionProfile* func = &g_profiler.functions[func_idx];
    func->total_allocations++;
    func->total_bytes_allocated += size;
    
    uint64_t current = func->total_bytes_allocated;  // Simplified
    if (current > func->peak_memory_bytes) {
        func->peak_memory_bytes = current;
    }
}

//=============================================================================
// Profiling Control
//=============================================================================

void profiler_init(void) {
    memset(&g_profiler, 0, sizeof(g_profiler));
    g_profiler.program_start_time = profiler_get_time_ns();
    g_profiler_enabled = 1;
}

void profiler_shutdown(void) {
    g_profiler_enabled = 0;
}

//=============================================================================
// Report Generation
//=============================================================================

void profiler_print_summary(void) {
    uint64_t total_time = profiler_get_time_ns() - g_profiler.program_start_time;
    
    printf("\n");
    printf("=============================================================================\n");
    printf("  Performance Profile Summary\n");
    printf("=============================================================================\n");
    printf("  Total Functions:  %d\n", g_profiler.function_count);
    printf("  Total Time:       %.3f ms\n", total_time / 1000000.0);
    printf("  Call Graph Edges: %d\n", g_profiler.edge_count);
    printf("=============================================================================\n");
}

void profiler_print_functions(void) {
    printf("\n");
    printf("=============================================================================\n");
    printf("  Function Performance\n");
    printf("=============================================================================\n");
    printf("  %-30s %10s %12s %12s %12s\n", 
           "Function", "Calls", "Total(ms)", "Self(ms)", "Avg(us)");
    printf("  ---------------------------------------------------------------------------\n");
    
    // Sort by self time (simple bubble sort)
    for (int i = 0; i < g_profiler.function_count - 1; i++) {
        for (int j = i + 1; j < g_profiler.function_count; j++) {
            if (g_profiler.functions[j].self_time_ns > g_profiler.functions[i].self_time_ns) {
                FunctionProfile temp = g_profiler.functions[i];
                g_profiler.functions[i] = g_profiler.functions[j];
                g_profiler.functions[j] = temp;
            }
        }
    }
    
    for (int i = 0; i < g_profiler.function_count && i < 20; i++) {
        FunctionProfile* func = &g_profiler.functions[i];
        if (func->total_calls == 0) continue;
        
        double total_ms = func->total_time_ns / 1000000.0;
        double self_ms = func->self_time_ns / 1000000.0;
        double avg_us = (func->self_time_ns / func->total_calls) / 1000.0;
        
        printf("  %-30s %10llu %12.3f %12.3f %12.3f\n",
               func->name, func->total_calls, total_ms, self_ms, avg_us);
    }
    
    printf("=============================================================================\n");
}

void profiler_print_call_graph(void) {
    printf("\n");
    printf("=============================================================================\n");
    printf("  Hot Call Paths\n");
    printf("=============================================================================\n");
    printf("  %-30s -> %-30s %10s\n", "Caller", "Callee", "Calls");
    printf("  ---------------------------------------------------------------------------\n");
    
    // Sort by call count
    for (int i = 0; i < g_profiler.edge_count - 1; i++) {
        for (int j = i + 1; j < g_profiler.edge_count; j++) {
            if (g_profiler.call_graph[j].call_count > g_profiler.call_graph[i].call_count) {
                CallEdge temp = g_profiler.call_graph[i];
                g_profiler.call_graph[i] = g_profiler.call_graph[j];
                g_profiler.call_graph[j] = temp;
            }
        }
    }
    
    for (int i = 0; i < g_profiler.edge_count && i < 15; i++) {
        CallEdge* edge = &g_profiler.call_graph[i];
        const char* caller = g_profiler.functions[edge->caller_idx].name;
        const char* callee = g_profiler.functions[edge->callee_idx].name;
        
        printf("  %-30s -> %-30s %10llu\n", caller, callee, edge->call_count);
    }
    
    printf("=============================================================================\n");
}

void profiler_print_memory(void) {
    printf("\n");
    printf("=============================================================================\n");
    printf("  Memory Usage by Function\n");
    printf("=============================================================================\n");
    printf("  %-30s %12s %15s %15s\n", 
           "Function", "Allocations", "Total Bytes", "Peak Bytes");
    printf("  ---------------------------------------------------------------------------\n");
    
    // Sort by peak memory
    for (int i = 0; i < g_profiler.function_count - 1; i++) {
        for (int j = i + 1; j < g_profiler.function_count; j++) {
            if (g_profiler.functions[j].peak_memory_bytes > g_profiler.functions[i].peak_memory_bytes) {
                FunctionProfile temp = g_profiler.functions[i];
                g_profiler.functions[i] = g_profiler.functions[j];
                g_profiler.functions[j] = temp;
            }
        }
    }
    
    for (int i = 0; i < g_profiler.function_count && i < 15; i++) {
        FunctionProfile* func = &g_profiler.functions[i];
        if (func->total_allocations == 0) continue;
        
        printf("  %-30s %12llu %15llu %15llu\n",
               func->name, func->total_allocations, 
               func->total_bytes_allocated, func->peak_memory_bytes);
    }
    
    printf("=============================================================================\n");
}

void profiler_export_json(const char* filename) {
    FILE* f = fopen(filename, "w");
    if (!f) return;
    
    fprintf(f, "{\n");
    fprintf(f, "  \"functions\": [\n");
    
    for (int i = 0; i < g_profiler.function_count; i++) {
        FunctionProfile* func = &g_profiler.functions[i];
        fprintf(f, "    {\n");
        fprintf(f, "      \"name\": \"%s\",\n", func->name);
        fprintf(f, "      \"file\": \"%s\",\n", func->file);
        fprintf(f, "      \"line\": %d,\n", func->line);
        fprintf(f, "      \"calls\": %llu,\n", func->total_calls);
        fprintf(f, "      \"total_time_ns\": %llu,\n", func->total_time_ns);
        fprintf(f, "      \"self_time_ns\": %llu,\n", func->self_time_ns);
        fprintf(f, "      \"min_time_ns\": %llu,\n", func->min_time_ns);
        fprintf(f, "      \"max_time_ns\": %llu,\n", func->max_time_ns);
        fprintf(f, "      \"allocations\": %llu,\n", func->total_allocations);
        fprintf(f, "      \"bytes_allocated\": %llu\n", func->total_bytes_allocated);
        fprintf(f, "    }%s\n", (i < g_profiler.function_count - 1) ? "," : "");
    }
    
    fprintf(f, "  ],\n");
    fprintf(f, "  \"call_graph\": [\n");
    
    for (int i = 0; i < g_profiler.edge_count; i++) {
        CallEdge* edge = &g_profiler.call_graph[i];
        fprintf(f, "    {\n");
        fprintf(f, "      \"caller\": \"%s\",\n", g_profiler.functions[edge->caller_idx].name);
        fprintf(f, "      \"callee\": \"%s\",\n", g_profiler.functions[edge->callee_idx].name);
        fprintf(f, "      \"count\": %llu\n", edge->call_count);
        fprintf(f, "    }%s\n", (i < g_profiler.edge_count - 1) ? "," : "");
    }
    
    fprintf(f, "  ]\n");
    fprintf(f, "}\n");
    
    fclose(f);
    
    printf("  Profile exported to: %s\n", filename);
}

//=============================================================================
// Convenience Macros
//=============================================================================

#define PROFILE_INIT() profiler_init()
#define PROFILE_SHUTDOWN() profiler_shutdown()
#define PROFILE_FUNC() \
    static int __func_idx = -1; \
    if (__func_idx < 0) __func_idx = profiler_register_function(__FUNCTION__, __FILE__, __LINE__); \
    profiler_enter_function(__func_idx); \
    for (int __prof_once = 1; __prof_once; __prof_once = 0, profiler_exit_function(__func_idx))

#define PROFILE_REPORT() do { \
    profiler_print_summary(); \
    profiler_print_functions(); \
    profiler_print_call_graph(); \
    profiler_print_memory(); \
} while(0)

//=============================================================================
// Demo/Main
//=============================================================================

void example_function_a(void) {
    PROFILE_FUNC();
    // Simulate work
    for (volatile int i = 0; i < 1000000; i++);
}

void example_function_b(void) {
    PROFILE_FUNC();
    example_function_a();
    example_function_a();
    for (volatile int i = 0; i < 500000; i++);
}

void example_function_c(void) {
    PROFILE_FUNC();
    void* ptr = malloc(1024);
    profiler_record_allocation(__func_idx, 1024);
    example_function_b();
    free(ptr);
}

int main(int argc, char* argv[]) {
    (void)argc;
    (void)argv;
    
    printf("RawrXD Performance Profiler\n");
    printf("===========================\n\n");
    
    PROFILE_INIT();
    
    // Run some example code
    for (int i = 0; i < 100; i++) {
        example_function_c();
    }
    
    PROFILE_REPORT();
    profiler_export_json("profile.json");
    
    PROFILE_SHUTDOWN();
    
    return 0;
}
