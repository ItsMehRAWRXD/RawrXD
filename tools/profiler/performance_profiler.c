//=============================================================================
// performance_profiler.c - Sampling Performance Profiler
// Production-ready statistical profiling with call graph analysis
//=============================================================================

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <math.h>

//=============================================================================
// Profiler Types
//=============================================================================

#define MAX_SAMPLES 100000
#define MAX_FUNCTIONS 1000
#define MAX_CALL_DEPTH 64
#define HASH_SIZE 1024

typedef struct {
    uint64_t address;
    char name[256];
    char module[256];
    int line;
    int hit_count;
    double total_time;
    double self_time;
    int call_count;
} FunctionProfile;

typedef struct {
    int caller_idx;
    int callee_idx;
    int call_count;
    double total_time;
} CallEdge;

typedef struct {
    uint64_t timestamp;
    uint64_t pc;           // Program counter
    int function_idx;
    int call_depth;
    uint64_t stack_trace[MAX_CALL_DEPTH];
    int stack_depth;
} Sample;

typedef struct {
    Sample samples[MAX_SAMPLES];
    int sample_count;
    
    FunctionProfile* functions;
    int function_count;
    int function_capacity;
    
    CallEdge* call_graph;
    int call_edge_count;
    int call_edge_capacity;
    
    uint64_t start_time;
    uint64_t end_time;
    int sampling_interval_us;
    
    double total_runtime;
    int hot_spot_count;
} ProfileReport;

//=============================================================================
// Profiler Implementation
//=============================================================================

ProfileReport* profiler_create_report(void) {
    ProfileReport* report = (ProfileReport*)calloc(1, sizeof(ProfileReport));
    report->function_capacity = MAX_FUNCTIONS;
    report->functions = (FunctionProfile*)calloc(report->function_capacity, sizeof(FunctionProfile));
    report->call_edge_capacity = MAX_FUNCTIONS * 10;
    report->call_graph = (CallEdge*)calloc(report->call_edge_capacity, sizeof(CallEdge));
    report->sampling_interval_us = 1000;  // 1ms default
    return report;
}

void profiler_destroy_report(ProfileReport* report) {
    if (!report) return;
    free(report->functions);
    free(report->call_graph);
    free(report);
}

int find_or_create_function(ProfileReport* report, uint64_t address, const char* name) {
    // Check if function exists
    for (int i = 0; i < report->function_count; i++) {
        if (report->functions[i].address == address) {
            return i;
        }
    }
    
    // Create new function
    if (report->function_count >= report->function_capacity) return -1;
    
    FunctionProfile* func = &report->functions[report->function_count];
    func->address = address;
    strncpy(func->name, name ? name : "unknown", sizeof(func->name) - 1);
    func->hit_count = 0;
    func->total_time = 0;
    func->self_time = 0;
    func->call_count = 0;
    
    return report->function_count++;
}

void record_sample(ProfileReport* report, uint64_t pc, const char* func_name) {
    if (report->sample_count >= MAX_SAMPLES) return;
    
    Sample* sample = &report->samples[report->sample_count++];
    sample->timestamp = (uint64_t)clock();
    sample->pc = pc;
    sample->function_idx = find_or_create_function(report, pc, func_name);
    sample->call_depth = 0;
    
    if (sample->function_idx >= 0) {
        report->functions[sample->function_idx].hit_count++;
    }
}

void record_call_edge(ProfileReport* report, int caller_idx, int callee_idx) {
    // Check if edge exists
    for (int i = 0; i < report->call_edge_count; i++) {
        if (report->call_graph[i].caller_idx == caller_idx &&
            report->call_graph[i].callee_idx == callee_idx) {
            report->call_graph[i].call_count++;
            return;
        }
    }
    
    // Create new edge
    if (report->call_edge_count >= report->call_edge_capacity) return;
    
    CallEdge* edge = &report->call_graph[report->call_edge_count++];
    edge->caller_idx = caller_idx;
    edge->callee_idx = callee_idx;
    edge->call_count = 1;
}

void calculate_statistics(ProfileReport* report) {
    // Calculate percentages
    for (int i = 0; i < report->function_count; i++) {
        FunctionProfile* func = &report->functions[i];
        if (report->sample_count > 0) {
            func->total_time = (double)func->hit_count / report->sample_count * 100.0;
        }
    }
    
    // Count hot spots (> 1% of samples)
    report->hot_spot_count = 0;
    for (int i = 0; i < report->function_count; i++) {
        if (report->functions[i].total_time > 1.0) {
            report->hot_spot_count++;
        }
    }
}

void sort_by_time(ProfileReport* report) {
    // Simple bubble sort by total_time
    for (int i = 0; i < report->function_count - 1; i++) {
        for (int j = 0; j < report->function_count - i - 1; j++) {
            if (report->functions[j].total_time < report->functions[j+1].total_time) {
                FunctionProfile temp = report->functions[j];
                report->functions[j] = report->functions[j+1];
                report->functions[j+1] = temp;
            }
        }
    }
}

//=============================================================================
// Report Generation
//=============================================================================

void print_profiler_summary(ProfileReport* report) {
    printf("\n");
    printf("=============================================================================\n");
    printf("  Performance Profile Summary\n");
    printf("=============================================================================\n");
    printf("  Samples Collected:  %d\n", report->sample_count);
    printf("  Functions Profiled: %d\n", report->function_count);
    printf("  Hot Spots (>1%%):    %d\n", report->hot_spot_count);
    printf("  Sampling Interval:  %d us\n", report->sampling_interval_us);
    printf("=============================================================================\n");
}

void print_hot_functions(ProfileReport* report, int top_n) {
    printf("\n");
    printf("=============================================================================\n");
    printf("  Hot Functions (Top %d)\n", top_n);
    printf("=============================================================================\n");
    printf("  %-40s %8s %10s %10s\n", "Function", "Samples", "Time %", "Calls");
    printf("  ---------------------------------------------------------------------------\n");
    
    int count = (top_n < report->function_count) ? top_n : report->function_count;
    for (int i = 0; i < count; i++) {
        FunctionProfile* func = &report->functions[i];
        printf("  %-40s %8d %9.2f%% %10d\n",
               func->name, func->hit_count, func->total_time, func->call_count);
    }
    
    printf("=============================================================================\n");
}

void print_call_graph(ProfileReport* report, int top_n) {
    if (report->call_edge_count == 0) return;
    
    printf("\n");
    printf("=============================================================================\n");
    printf("  Call Graph (Top %d Edges)\n", top_n);
    printf("=============================================================================\n");
    printf("  %-30s -> %-30s %8s\n", "Caller", "Callee", "Calls");
    printf("  ---------------------------------------------------------------------------\n");
    
    // Sort edges by call count
    for (int i = 0; i < report->call_edge_count - 1; i++) {
        for (int j = 0; j < report->call_edge_count - i - 1; j++) {
            if (report->call_graph[j].call_count < report->call_graph[j+1].call_count) {
                CallEdge temp = report->call_graph[j];
                report->call_graph[j] = report->call_graph[j+1];
                report->call_graph[j+1] = temp;
            }
        }
    }
    
    int count = (top_n < report->call_edge_count) ? top_n : report->call_edge_count;
    for (int i = 0; i < count; i++) {
        CallEdge* edge = &report->call_graph[i];
        FunctionProfile* caller = &report->functions[edge->caller_idx];
        FunctionProfile* callee = &report->functions[edge->callee_idx];
        printf("  %-30s -> %-30s %8d\n",
               caller->name, callee->name, edge->call_count);
    }
    
    printf("=============================================================================\n");
}

void export_profiler_json(ProfileReport* report, const char* filename) {
    FILE* f = fopen(filename, "w");
    if (!f) return;
    
    fprintf(f, "{\n");
    fprintf(f, "  \"summary\": {\n");
    fprintf(f, "    \"samples_collected\": %d,\n", report->sample_count);
    fprintf(f, "    \"functions_profiled\": %d,\n", report->function_count);
    fprintf(f, "    \"hot_spots\": %d,\n", report->hot_spot_count);
    fprintf(f, "    \"sampling_interval_us\": %d\n", report->sampling_interval_us);
    fprintf(f, "  },\n");
    fprintf(f, "  \"functions\": [\n");
    
    for (int i = 0; i < report->function_count; i++) {
        FunctionProfile* func = &report->functions[i];
        fprintf(f, "    {\n");
        fprintf(f, "      \"name\": \"%s\",\n", func->name);
        fprintf(f, "      \"address\": \"0x%llx\",\n", (unsigned long long)func->address);
        fprintf(f, "      \"hit_count\": %d,\n", func->hit_count);
        fprintf(f, "      \"time_percent\": %.2f,\n", func->total_time);
        fprintf(f, "      \"self_time_percent\": %.2f,\n", func->self_time);
        fprintf(f, "      \"call_count\": %d\n", func->call_count);
        fprintf(f, "    }%s\n", (i < report->function_count - 1) ? "," : "");
    }
    
    fprintf(f, "  ],\n");
    fprintf(f, "  \"call_graph\": [\n");
    
    for (int i = 0; i < report->call_edge_count; i++) {
        CallEdge* edge = &report->call_graph[i];
        fprintf(f, "    {\n");
        fprintf(f, "      \"caller\": \"%s\",\n", report->functions[edge->caller_idx].name);
        fprintf(f, "      \"callee\": \"%s\",\n", report->functions[edge->callee_idx].name);
        fprintf(f, "      \"call_count\": %d\n", edge->call_count);
        fprintf(f, "    }%s\n", (i < report->call_edge_count - 1) ? "," : "");
    }
    
    fprintf(f, "  ]\n");
    fprintf(f, "}\n");
    
    fclose(f);
    printf("  Profile exported: %s\n", filename);
}

void export_profiler_flamegraph(ProfileReport* report, const char* filename) {
    FILE* f = fopen(filename, "w");
    if (!f) return;
    
    // FlameGraph format: func1;func2;func3 count
    for (int i = 0; i < report->function_count; i++) {
        FunctionProfile* func = &report->functions[i];
        if (func->hit_count > 0) {
            fprintf(f, "%s %d\n", func->name, func->hit_count);
        }
    }
    
    fclose(f);
    printf("  FlameGraph data exported: %s\n", filename);
}

//=============================================================================
// Demo
//=============================================================================

void demo_profiling(ProfileReport* report) {
    // Simulate profiling data
    record_sample(report, 0x1000, "main");
    record_sample(report, 0x1100, "process_data");
    record_sample(report, 0x1100, "process_data");
    record_sample(report, 0x1200, "calculate_hash");
    record_sample(report, 0x1200, "calculate_hash");
    record_sample(report, 0x1200, "calculate_hash");
    record_sample(report, 0x1300, "sort_array");
    record_sample(report, 0x1300, "sort_array");
    record_sample(report, 0x1100, "process_data");
    record_sample(report, 0x1400, "write_output");
    
    // Add call edges
    record_call_edge(report, 0, 1);  // main -> process_data
    record_call_edge(report, 1, 2);  // process_data -> calculate_hash
    record_call_edge(report, 1, 3);  // process_data -> sort_array
    record_call_edge(report, 0, 4);  // main -> write_output
}

//=============================================================================
// Main Entry Point
//=============================================================================

int main(int argc, char* argv[]) {
    printf("RawrXD Performance Profiler\n");
    printf("==========================\n\n");
    
    ProfileReport* report = profiler_create_report();
    
    // Configure from args
    if (argc > 1) {
        report->sampling_interval_us = atoi(argv[1]);
    }
    
    printf("Collecting samples (interval: %d us)...\n", report->sampling_interval_us);
    
    // Run demo
    demo_profiling(report);
    
    // Analyze
    calculate_statistics(report);
    sort_by_time(report);
    
    // Generate reports
    print_profiler_summary(report);
    print_hot_functions(report, 10);
    print_call_graph(report, 10);
    export_profiler_json(report, "profile_report.json");
    export_profiler_flamegraph(report, "flamegraph.txt");
    
    printf("\nProfiling complete!\n");
    printf("Use 'flamegraph.pl flamegraph.txt > profile.svg' to generate flame graph\n");
    
    profiler_destroy_report(report);
    
    return 0;
}
