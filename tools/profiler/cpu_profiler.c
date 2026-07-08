//=============================================================================
// cpu_profiler.c - CPU Profiler
// Production-ready CPU profiling with sampling and flame graph support
//=============================================================================

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <windows.h>
#include <dbghelp.h>

#pragma comment(lib, "dbghelp.lib")

//=============================================================================
// Profiler Types
//=============================================================================

#define MAX_SAMPLES 1000000
#define MAX_FUNCTIONS 10000
#define MAX_STACK_DEPTH 64
#define SAMPLE_INTERVAL_MS 10

typedef struct {
    uint64_t address;
    char name[256];
    char module[256];
    char file[512];
    int line;
    int hit_count;
    double total_time_ms;
    double self_time_ms;
} FunctionProfile;

typedef struct {
    uint64_t addresses[MAX_STACK_DEPTH];
    int depth;
    int count;
    double total_time_ms;
} StackTrace;

typedef struct {
    uint64_t timestamp;
    int thread_id;
    StackTrace stack;
    int sample_number;
} Sample;

typedef struct {
    FunctionProfile* functions;
    int function_count;
    int function_capacity;
    
    Sample* samples;
    int sample_count;
    int sample_capacity;
    
    StackTrace* hot_paths;
    int hot_path_count;
    int hot_path_capacity;
    
    // Timing
    LARGE_INTEGER freq;
    LARGE_INTEGER start_time;
    LARGE_INTEGER end_time;
    double duration_ms;
    
    // Statistics
    int total_samples;
    int unique_functions;
    int max_stack_depth;
    double samples_per_second;
    
    // Top consumers
    FunctionProfile* hottest_functions[10];
    int hot_function_count;
} CpuProfileReport;

//=============================================================================
// Symbol Resolution
//=============================================================================

int init_symbol_handler(void) {
    SymSetOptions(SYMOPT_LOAD_LINES | SYMOPT_DEFERRED_LOADS);
    return SymInitialize(GetCurrentProcess(), NULL, TRUE);
}

void cleanup_symbol_handler(void) {
    SymCleanup(GetCurrentProcess());
}

FunctionProfile* get_or_create_function(CpuProfileReport* report, uint64_t addr) {
    // Find existing
    for (int i = 0; i < report->function_count; i++) {
        if (report->functions[i].address == addr) {
            return &report->functions[i];
        }
    }
    
    // Create new
    if (report->function_count >= report->function_capacity) return NULL;
    
    FunctionProfile* func = &report->functions[report->function_count++];
    func->address = addr;
    
    // Resolve symbol
    char symbol_buffer[sizeof(SYMBOL_INFO) + 256] = {0};
    SYMBOL_INFO* symbol = (SYMBOL_INFO*)symbol_buffer;
    symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
    symbol->MaxNameLen = 255;
    
    DWORD64 displacement = 0;
    if (SymFromAddr(GetCurrentProcess(), addr, &displacement, symbol)) {
        strncpy(func->name, symbol->Name, sizeof(func->name) - 1);
        
        // Get module name
        IMAGEHLP_MODULE64 module = {0};
        module.SizeOfStruct = sizeof(module);
        if (SymGetModuleInfo64(GetCurrentProcess(), addr, &module)) {
            strncpy(func->module, module.ModuleName, sizeof(func->module) - 1);
        }
        
        // Get line info
        IMAGEHLP_LINE64 line = {0};
        line.SizeOfStruct = sizeof(line);
        DWORD line_displacement = 0;
        if (SymGetLineFromAddr64(GetCurrentProcess(), addr, &line_displacement, &line)) {
            strncpy(func->file, line.FileName, sizeof(func->file) - 1);
            func->line = line.LineNumber;
        }
    } else {
        snprintf(func->name, sizeof(func->name), "0x%llx", addr);
    }
    
    return func;
}

//=============================================================================
// Sampling Engine
//=============================================================================

CpuProfileReport* cpu_profile_create(void) {
    CpuProfileReport* report = (CpuProfileReport*)calloc(1, sizeof(CpuProfileReport));
    report->function_capacity = MAX_FUNCTIONS;
    report->functions = (FunctionProfile*)calloc(report->function_capacity, sizeof(FunctionProfile));
    report->sample_capacity = MAX_SAMPLES;
    report->samples = (Sample*)calloc(report->sample_capacity, sizeof(Sample));
    report->hot_path_capacity = 1000;
    report->hot_paths = (StackTrace*)calloc(report->hot_path_capacity, sizeof(StackTrace));
    
    QueryPerformanceFrequency(&report->freq);
    
    init_symbol_handler();
    
    return report;
}

void cpu_profile_destroy(CpuProfileReport* report) {
    if (!report) return;
    cleanup_symbol_handler();
    free(report->functions);
    free(report->samples);
    free(report->hot_paths);
    free(report);
}

void capture_stack_trace(CpuProfileReport* report, HANDLE hThread, Sample* sample) {
    CONTEXT context = {0};
    context.ContextFlags = CONTEXT_FULL;
    
    if (!GetThreadContext(hThread, &context)) {
        return;
    }
    
    // Capture stack
    STACKFRAME64 frame = {0};
    frame.AddrPC.Offset = context.Rip;
    frame.AddrPC.Mode = AddrModeFlat;
    frame.AddrFrame.Offset = context.Rbp;
    frame.AddrFrame.Mode = AddrModeFlat;
    frame.AddrStack.Offset = context.Rsp;
    frame.AddrStack.Mode = AddrModeFlat;
    
    int depth = 0;
    while (depth < MAX_STACK_DEPTH) {
        if (!StackWalk64(IMAGE_FILE_MACHINE_AMD64, GetCurrentProcess(), hThread,
                         &frame, &context, NULL, SymFunctionTableAccess64, 
                         SymGetModuleBase64, NULL)) {
            break;
        }
        
        if (frame.AddrPC.Offset == 0) break;
        
        sample->stack.addresses[depth] = frame.AddrPC.Offset;
        
        // Update function hit count
        FunctionProfile* func = get_or_create_function(report, frame.AddrPC.Offset);
        if (func) {
            func->hit_count++;
        }
        
        depth++;
    }
    
    sample->stack.depth = depth;
    if (depth > report->max_stack_depth) {
        report->max_stack_depth = depth;
    }
}

void cpu_profile_start(CpuProfileReport* report) {
    QueryPerformanceCounter(&report->start_time);
    printf("CPU profiling started...\n");
}

void cpu_profile_sample(CpuProfileReport* report) {
    if (report->sample_count >= report->sample_capacity) return;
    
    Sample* sample = &report->samples[report->sample_count++];
    sample->sample_number = report->sample_count;
    sample->thread_id = GetCurrentThreadId();
    
    LARGE_INTEGER timestamp;
    QueryPerformanceCounter(&timestamp);
    sample->timestamp = timestamp.QuadPart;
    
    // Capture current thread's stack
    capture_stack_trace(report, GetCurrentThread(), sample);
    
    report->total_samples++;
}

void cpu_profile_stop(CpuProfileReport* report) {
    QueryPerformanceCounter(&report->end_time);
    report->duration_ms = ((double)(report->end_time.QuadPart - report->start_time.QuadPart) * 1000.0) 
                            / report->freq.QuadPart;
    
    report->samples_per_second = report->total_samples / (report->duration_ms / 1000.0);
    report->unique_functions = report->function_count;
    
    // Find hottest functions
    for (int i = 0; i < report->function_count && report->hot_function_count < 10; i++) {
        FunctionProfile* func = &report->functions[i];
        
        // Insert in sorted order
        int insert_pos = report->hot_function_count;
        for (int j = 0; j < report->hot_function_count; j++) {
            if (func->hit_count > report->hottest_functions[j]->hit_count) {
                insert_pos = j;
                break;
            }
        }
        
        // Shift and insert
        for (int j = report->hot_function_count; j > insert_pos; j--) {
            report->hottest_functions[j] = report->hottest_functions[j - 1];
        }
        report->hottest_functions[insert_pos] = func;
        
        if (report->hot_function_count < 10) {
            report->hot_function_count++;
        }
    }
    
    printf("CPU profiling stopped.\n");
}

//=============================================================================
// Report Generation
//=============================================================================

void print_profile_summary(CpuProfileReport* report) {
    printf("\n");
    printf("=============================================================================\n");
    printf("  CPU Profile Summary\n");
    printf("=============================================================================\n");
    printf("  Duration:               %.2f ms\n", report->duration_ms);
    printf("  Total Samples:          %d\n", report->total_samples);
    printf("  Sample Rate:            %.2f samples/sec\n", report->samples_per_second);
    printf("  Unique Functions:       %d\n", report->unique_functions);
    printf("  Max Stack Depth:        %d\n", report->max_stack_depth);
    printf("=============================================================================\n");
}

void print_hot_functions(CpuProfileReport* report) {
    printf("\n");
    printf("=============================================================================\n");
    printf("  Hot Functions (Top 10)\n");
    printf("=============================================================================\n");
    
    if (report->hot_function_count == 0) {
        printf("\n  No samples collected.\n");
        return;
    }
    
    printf("\n  %-5s %-8s %-40s %-20s\n", "Rank", "Samples", "Function", "Module");
    printf("  %-5s %-8s %-40s %-20s\n", "----", "-------", "--------", "------");
    
    for (int i = 0; i < report->hot_function_count; i++) {
        FunctionProfile* func = report->hottest_functions[i];
        double percentage = (double)func->hit_count / report->total_samples * 100.0;
        
        printf("  %-5d %-8d %-40.40s %-20.20s\n",
               i + 1, func->hit_count, func->name, func->module);
        printf("       %.2f%% - %s:%d\n", percentage, func->file, func->line);
    }
    
    printf("\n=============================================================================\n");
}

void export_flame_graph(CpuProfileReport* report, const char* filename) {
    FILE* f = fopen(filename, "w");
    if (!f) return;
    
    // Flame graph format: stack;stack;stack count
    for (int i = 0; i < report->sample_count; i++) {
        Sample* sample = &report->samples[i];
        
        // Build stack string (reversed - root first)
        for (int j = sample->stack.depth - 1; j >= 0; j--) {
            FunctionProfile* func = get_or_create_function(report, sample->stack.addresses[j]);
            if (func) {
                fprintf(f, "%s", func->name);
                if (j > 0) fprintf(f, ";");
            }
        }
        fprintf(f, " 1\n");
    }
    
    fclose(f);
    printf("  Flame graph data exported: %s\n", filename);
}

void export_profile_json(CpuProfileReport* report, const char* filename) {
    FILE* f = fopen(filename, "w");
    if (!f) return;
    
    fprintf(f, "{\n");
    fprintf(f, "  \"summary\": {\n");
    fprintf(f, "    \"duration_ms\": %.2f,\n", report->duration_ms);
    fprintf(f, "    \"total_samples\": %d,\n", report->total_samples);
    fprintf(f, "    \"sample_rate\": %.2f,\n", report->samples_per_second);
    fprintf(f, "    \"unique_functions\": %d,\n", report->unique_functions);
    fprintf(f, "    \"max_stack_depth\": %d\n", report->max_stack_depth);
    fprintf(f, "  },\n");
    fprintf(f, "  \"hot_functions\": [\n");
    
    for (int i = 0; i < report->hot_function_count; i++) {
        FunctionProfile* func = report->hottest_functions[i];
        fprintf(f, "    {\n");
        fprintf(f, "      \"rank\": %d,\n", i + 1);
        fprintf(f, "      \"name\": \"%s\",\n", func->name);
        fprintf(f, "      \"module\": \"%s\",\n", func->module);
        fprintf(f, "      \"file\": \"%s\",\n", func->file);
        fprintf(f, "      \"line\": %d,\n", func->line);
        fprintf(f, "      \"hit_count\": %d,\n", func->hit_count);
        fprintf(f, "      \"percentage\": %.2f\n", 
                (double)func->hit_count / report->total_samples * 100.0);
        fprintf(f, "    }%s\n", (i < report->hot_function_count - 1) ? "," : "");
    }
    
    fprintf(f, "  ],\n");
    fprintf(f, "  \"all_functions\": [\n");
    
    for (int i = 0; i < report->function_count; i++) {
        FunctionProfile* func = &report->functions[i];
        fprintf(f, "    {\n");
        fprintf(f, "      \"address\": \"0x%llx\",\n", func->address);
        fprintf(f, "      \"name\": \"%s\",\n", func->name);
        fprintf(f, "      \"module\": \"%s\",\n", func->module);
        fprintf(f, "      \"hit_count\": %d\n", func->hit_count);
        fprintf(f, "    }%s\n", (i < report->function_count - 1) ? "," : "");
    }
    
    fprintf(f, "  ]\n");
    fprintf(f, "}\n");
    
    fclose(f);
    printf("  Profile JSON exported: %s\n", filename);
}

//=============================================================================
// Demo Workload
//=============================================================================

void cpu_intensive_work(void) {
    volatile double result = 0.0;
    for (int i = 0; i < 1000000; i++) {
        result += sin(i) * cos(i);
    }
}

void another_function(void) {
    for (int i = 0; i < 500000; i++) {
        cpu_intensive_work();
    }
}

//=============================================================================
// Main Entry Point
//=============================================================================

int main(int argc, char* argv[]) {
    printf("RawrXD CPU Profiler\n");
    printf("===================\n\n");
    
    CpuProfileReport* report = cpu_profile_create();
    
    // Parse duration
    int duration_ms = (argc > 1) ? atoi(argv[1]) : 1000;
    
    // Start profiling
    cpu_profile_start(report);
    
    // Run demo workload with sampling
    LARGE_INTEGER freq, last_sample;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&last_sample);
    
    LARGE_INTEGER sample_interval;
    sample_interval.QuadPart = freq.QuadPart * SAMPLE_INTERVAL_MS / 1000;
    
    LARGE_INTEGER end_time;
    QueryPerformanceCounter(&end_time);
    end_time.QuadPart += freq.QuadPart * duration_ms / 1000;
    
    printf("Profiling for %d ms...\n", duration_ms);
    
    while (1) {
        // Do some work
        cpu_intensive_work();
        another_function();
        
        // Sample if interval passed
        LARGE_INTEGER now;
        QueryPerformanceCounter(&now);
        
        if (now.QuadPart - last_sample.QuadPart >= sample_interval.QuadPart) {
            cpu_profile_sample(report);
            last_sample = now;
        }
        
        if (now.QuadPart >= end_time.QuadPart) break;
    }
    
    // Stop profiling
    cpu_profile_stop(report);
    
    // Generate reports
    print_profile_summary(report);
    print_hot_functions(report);
    export_profile_json(report, "cpu_profile.json");
    export_flame_graph(report, "flame_graph.txt");
    
    printf("\nCPU profiling complete!\n");
    printf("View flame graph at: https://speedscope.app (upload flame_graph.txt)\n");
    
    cpu_profile_destroy(report);
    return 0;
}
