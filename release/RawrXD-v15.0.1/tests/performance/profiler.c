/*
 * RawrXD Performance Profiler
 * Lightweight sampling profiler for kernel optimization
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>

#ifdef _WIN32
    #include <windows.h>
#else
    #include <sys/time.h>
#endif

#define MAX_FUNCTIONS 100
#define MAX_NAME_LEN 64

typedef struct {
    char name[MAX_NAME_LEN];
    double total_time_ms;
    double min_time_ms;
    double max_time_ms;
    int call_count;
    double total_ops;
} profile_entry_t;

typedef struct {
    profile_entry_t entries[MAX_FUNCTIONS];
    int count;
} profiler_t;

static profiler_t g_profiler = {0};

/* High-resolution timer */
static double get_time_ms() {
#ifdef _WIN32
    LARGE_INTEGER freq, count;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&count);
    return (double)count.QuadPart * 1000.0 / (double)freq.QuadPart;
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000.0 + tv.tv_usec / 1000.0;
#endif
}

/* Find or create profile entry */
static profile_entry_t* get_entry(const char* name) {
    for (int i = 0; i < g_profiler.count; i++) {
        if (strcmp(g_profiler.entries[i].name, name) == 0) {
            return &g_profiler.entries[i];
        }
    }
    
    if (g_profiler.count < MAX_FUNCTIONS) {
        profile_entry_t* entry = &g_profiler.entries[g_profiler.count++];
        strncpy(entry->name, name, MAX_NAME_LEN - 1);
        entry->name[MAX_NAME_LEN - 1] = '\0';
        entry->total_time_ms = 0.0;
        entry->min_time_ms = 1e9;
        entry->max_time_ms = 0.0;
        entry->call_count = 0;
        entry->total_ops = 0.0;
        return entry;
    }
    
    return NULL;
}

/* Record function timing */
void profile_record(const char* name, double time_ms, double ops) {
    profile_entry_t* entry = get_entry(name);
    if (!entry) return;
    
    entry->total_time_ms += time_ms;
    entry->total_ops += ops;
    entry->call_count++;
    
    if (time_ms < entry->min_time_ms) entry->min_time_ms = time_ms;
    if (time_ms > entry->max_time_ms) entry->max_time_ms = time_ms;
}

/* Print profiling results */
void profile_print_results() {
    printf("\n");
    printf("╔════════════════════════════════════════════════════════════════╗\n");
    printf("║              RawrXD Performance Profile Results                ║\n");
    printf("╠════════════════════════════════════════════════════════════════╣\n");
    printf("║ %-20s %10s %10s %10s %10s ║\n", 
           "Function", "Calls", "Total(ms)", "Avg(ms)", "GOPS");
    printf("╠════════════════════════════════════════════════════════════════╣\n");
    
    for (int i = 0; i < g_profiler.count; i++) {
        profile_entry_t* e = &g_profiler.entries[i];
        double avg_ms = e->call_count > 0 ? e->total_time_ms / e->call_count : 0;
        double gops = e->total_time_ms > 0 ? 
                      (e->total_ops / (e->total_time_ms / 1000.0)) / 1e9 : 0;
        
        printf("║ %-20s %10d %10.2f %10.3f %10.2f ║\n",
               e->name, e->call_count, e->total_time_ms, avg_ms, gops);
    }
    
    printf("╚════════════════════════════════════════════════════════════════╝\n");
}

/* Profiled matmul */
double profiled_matmul(double* A, double* B, double* C, int dim, int iterations) {
    double start = get_time_ms();
    
    for (int iter = 0; iter < iterations; iter++) {
        for (int i = 0; i < dim; i++) {
            for (int j = 0; j < dim; j++) {
                double sum = 0.0;
                for (int k = 0; k < dim; k++) {
                    sum += A[i * dim + k] * B[k * dim + j];
                }
                C[i * dim + j] = sum;
            }
        }
    }
    
    double end = get_time_ms();
    double time_ms = end - start;
    double ops = 2.0 * dim * dim * dim * iterations;
    
    profile_record("matmul", time_ms, ops);
    return time_ms;
}

/* Profiled softmax */
double profiled_softmax(double* input, double* output, int dim, int iterations) {
    double start = get_time_ms();
    
    for (int iter = 0; iter < iterations; iter++) {
        double max_val = input[0];
        for (int i = 1; i < dim; i++) {
            if (input[i] > max_val) max_val = input[i];
        }
        
        double sum = 0.0;
        for (int i = 0; i < dim; i++) {
            output[i] = exp(input[i] - max_val);
            sum += output[i];
        }
        
        for (int i = 0; i < dim; i++) {
            output[i] /= sum;
        }
    }
    
    double end = get_time_ms();
    double time_ms = end - start;
    double ops = dim * 6.0 * iterations;
    
    profile_record("softmax", time_ms, ops);
    return time_ms;
}

/* Profiled rmsnorm */
double profiled_rmsnorm(double* input, double* output, int dim, int iterations) {
    double eps = 1e-6;
    double start = get_time_ms();
    
    for (int iter = 0; iter < iterations; iter++) {
        double sum_sq = 0.0;
        for (int i = 0; i < dim; i++) {
            sum_sq += input[i] * input[i];
        }
        double rms = sqrt(sum_sq / dim + eps);
        for (int i = 0; i < dim; i++) {
            output[i] = input[i] / rms;
        }
    }
    
    double end = get_time_ms();
    double time_ms = end - start;
    double ops = dim * 4.0 * iterations;
    
    profile_record("rmsnorm", time_ms, ops);
    return time_ms;
}

int main() {
    printf("RawrXD Performance Profiler\n");
    printf("==========================\n\n");
    
    srand((unsigned int)time(NULL));
    
    /* Allocate matrices */
    int dim = 128;
    int iterations = 100;
    
    double* A = (double*)malloc(dim * dim * sizeof(double));
    double* B = (double*)malloc(dim * dim * sizeof(double));
    double* C = (double*)malloc(dim * dim * sizeof(double));
    double* input = (double*)malloc(dim * sizeof(double));
    double* output = (double*)malloc(dim * sizeof(double));
    
    if (!A || !B || !C || !input || !output) {
        printf("Memory allocation failed\n");
        return 1;
    }
    
    /* Initialize */
    for (int i = 0; i < dim * dim; i++) {
        A[i] = (double)rand() / RAND_MAX;
        B[i] = (double)rand() / RAND_MAX;
    }
    for (int i = 0; i < dim; i++) {
        input[i] = (double)rand() / RAND_MAX;
    }
    
    /* Run profiled kernels */
    printf("Profiling kernels (%d iterations each)...\n\n", iterations);
    
    printf("Running matmul (%dx%d)...\n", dim, dim);
    profiled_matmul(A, B, C, dim, iterations);
    
    printf("Running softmax (%d elements)...\n", dim);
    profiled_softmax(input, output, dim, iterations);
    
    printf("Running rmsnorm (%d elements)...\n", dim);
    profiled_rmsnorm(input, output, dim, iterations);
    
    printf("Running gelu (%d elements)...\n", dim);
    profiled_gelu(input, output, dim, iterations);
    
    printf("Running silu (%d elements)...\n", dim);
    profiled_silu(input, output, dim, iterations);
    
    /* Print results */
    profile_print_results();
    
    /* Cleanup */
    free(A); free(B); free(C);
    free(input); free(output);
    
    return 0;
}
