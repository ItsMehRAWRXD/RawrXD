//=============================================================================
// benchmark_harness.c - Performance Benchmark Harness
// Production-ready benchmarking with statistical analysis
//=============================================================================

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <time.h

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/time.h>
#endif

//=============================================================================
// Benchmark Configuration
//=============================================================================

#define MAX_BENCHMARKS 256
#define MAX_ITERATIONS 100000
#define WARMUP_ITERATIONS 10

//=============================================================================
// Data Structures
//=============================================================================

typedef struct {
    double* samples;
    int sample_count;
    int sample_capacity;
    
    double min;
    double max;
    double mean;
    double median;
    double stddev;
    double percentile_95;
    double percentile_99;
} Statistics;

typedef struct {
    char name[256];
    char description[1024];
    
    void (*setup)(void);
    void (*teardown)(void);
    void (*benchmark)(void);
    
    int iterations;
    int warmup_iterations;
    
    Statistics stats;
    double total_time_ms;
    double ops_per_second;
} Benchmark;

typedef struct {
    Benchmark benchmarks[MAX_BENCHMARKS];
    int benchmark_count;
    
    int global_iterations;
    int global_warmup;
    int verbose;
    int json_output;
} BenchmarkSuite;

static BenchmarkSuite g_suite = {0};

//=============================================================================
// High-Resolution Timing
//=============================================================================

uint64_t get_time_ns(void) {
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

double get_time_ms(void) {
    return get_time_ns() / 1000000.0;
}

//=============================================================================
// Statistics Calculation
//=============================================================================

int compare_double(const void* a, const void* b) {
    double da = *(const double*)a;
    double db = *(const double*)b;
    if (da < db) return -1;
    if (da > db) return 1;
    return 0;
}

void calculate_statistics(Statistics* stats) {
    if (stats->sample_count == 0) return;
    
    // Sort for median and percentiles
    qsort(stats->samples, stats->sample_count, sizeof(double), compare_double);
    
    // Min/max
    stats->min = stats->samples[0];
    stats->max = stats->samples[stats->sample_count - 1];
    
    // Mean
    double sum = 0;
    for (int i = 0; i < stats->sample_count; i++) {
        sum += stats->samples[i];
    }
    stats->mean = sum / stats->sample_count;
    
    // Median
    if (stats->sample_count % 2 == 0) {
        stats->median = (stats->samples[stats->sample_count/2 - 1] + 
                         stats->samples[stats->sample_count/2]) / 2.0;
    } else {
        stats->median = stats->samples[stats->sample_count/2];
    }
    
    // Standard deviation
    double variance = 0;
    for (int i = 0; i < stats->sample_count; i++) {
        double diff = stats->samples[i] - stats->mean;
        variance += diff * diff;
    }
    variance /= stats->sample_count;
    stats->stddev = sqrt(variance);
    
    // Percentiles
    int idx_95 = (int)(stats->sample_count * 0.95);
    int idx_99 = (int)(stats->sample_count * 0.99);
    stats->percentile_95 = stats->samples[idx_95];
    stats->percentile_99 = stats->samples[idx_99];
}

//=============================================================================
// Benchmark Registration
//=============================================================================

void benchmark_register(const char* name, const char* description,
                       void (*setup)(void), void (*teardown)(void),
                       void (*benchmark)(void)) {
    if (g_suite.benchmark_count >= MAX_BENCHMARKS) return;
    
    Benchmark* b = &g_suite.benchmarks[g_suite.benchmark_count++];
    strncpy(b->name, name, sizeof(b->name) - 1);
    strncpy(b->description, description, sizeof(b->description) - 1);
    b->setup = setup;
    b->teardown = teardown;
    b->benchmark = benchmark;
    b->iterations = g_suite.global_iterations > 0 ? g_suite.global_iterations : 1000;
    b->warmup_iterations = g_suite.global_warmup > 0 ? g_suite.global_warmup : WARMUP_ITERATIONS;
    
    b->stats.sample_capacity = b->iterations;
    b->stats.samples = (double*)calloc(b->iterations, sizeof(double));
}

//=============================================================================
// Benchmark Execution
//=============================================================================

void run_benchmark(Benchmark* b) {
    if (g_suite.verbose) {
        printf("Running: %s\n", b->name);
        printf("  Description: %s\n", b->description);
        printf("  Iterations: %d (warmup: %d)\n", b->iterations, b->warmup_iterations);
    }
    
    // Warmup
    if (b->setup) b->setup();
    for (int i = 0; i < b->warmup_iterations; i++) {
        b->benchmark();
    }
    if (b->teardown) b->teardown();
    
    // Actual benchmark
    double start_time = get_time_ms();
    
    for (int i = 0; i < b->iterations; i++) {
        if (b->setup) b->setup();
        
        double iter_start = get_time_ms();
        b->benchmark();
        double iter_end = get_time_ms();
        
        b->stats.samples[b->stats.sample_count++] = iter_end - iter_start;
        
        if (b->teardown) b->teardown();
    }
    
    double end_time = get_time_ms();
    b->total_time_ms = end_time - start_time;
    b->ops_per_second = (b->iterations / b->total_time_ms) * 1000.0;
    
    calculate_statistics(&b->stats);
}

//=============================================================================
// Report Generation
//=============================================================================

void print_benchmark_results(Benchmark* b) {
    printf("\n");
    printf("=============================================================================\n");
    printf("  %s\n", b->name);
    printf("=============================================================================\n");
    printf("  Description: %s\n", b->description);
    printf("  Iterations:  %d\n", b->iterations);
    printf("\n");
    printf("  Timing (ms):\n");
    printf("    Total:      %.3f\n", b->total_time_ms);
    printf("    Min:        %.6f\n", b->stats.min);
    printf("    Max:        %.6f\n", b->stats.max);
    printf("    Mean:       %.6f\n", b->stats.mean);
    printf("    Median:     %.6f\n", b->stats.median);
    printf("    StdDev:     %.6f\n", b->stats.stddev);
    printf("    P95:        %.6f\n", b->stats.percentile_95);
    printf("    P99:        %.6f\n", b->stats.percentile_99);
    printf("\n");
    printf("  Throughput: %.2f ops/sec\n", b->ops_per_second);
    printf("=============================================================================\n");
}

void print_summary(void) {
    printf("\n");
    printf("=============================================================================\n");
    printf("  Benchmark Summary\n");
    printf("=============================================================================\n");
    printf("  %-30s %12s %12s %12s\n", "Benchmark", "Mean (ms)", "P95 (ms)", "Ops/sec");
    printf("  ---------------------------------------------------------------------------\n");
    
    for (int i = 0; i < g_suite.benchmark_count; i++) {
        Benchmark* b = &g_suite.benchmarks[i];
        printf("  %-30s %12.6f %12.6f %12.2f\n",
               b->name, b->stats.mean, b->stats.percentile_95, b->ops_per_second);
    }
    
    printf("=============================================================================\n");
}

void export_json(const char* filename) {
    FILE* f = fopen(filename, "w");
    if (!f) return;
    
    fprintf(f, "{\n");
    fprintf(f, "  \"benchmarks\": [\n");
    
    for (int i = 0; i < g_suite.benchmark_count; i++) {
        Benchmark* b = &g_suite.benchmarks[i];
        fprintf(f, "    {\n");
        fprintf(f, "      \"name\": \"%s\",\n", b->name);
        fprintf(f, "      \"description\": \"%s\",\n", b->description);
        fprintf(f, "      \"iterations\": %d,\n", b->iterations);
        fprintf(f, "      \"total_time_ms\": %.3f,\n", b->total_time_ms);
        fprintf(f, "      \"ops_per_second\": %.2f,\n", b->ops_per_second);
        fprintf(f, "      \"statistics\": {\n");
        fprintf(f, "        \"min_ms\": %.6f,\n", b->stats.min);
        fprintf(f, "        \"max_ms\": %.6f,\n", b->stats.max);
        fprintf(f, "        \"mean_ms\": %.6f,\n", b->stats.mean);
        fprintf(f, "        \"median_ms\": %.6f,\n", b->stats.median);
        fprintf(f, "        \"stddev_ms\": %.6f,\n", b->stats.stddev);
        fprintf(f, "        \"p95_ms\": %.6f,\n", b->stats.percentile_95);
        fprintf(f, "        \"p99_ms\": %.6f\n", b->stats.percentile_99);
        fprintf(f, "      }\n");
        fprintf(f, "    }%s\n", (i < g_suite.benchmark_count - 1) ? "," : "");
    }
    
    fprintf(f, "  ]\n");
    fprintf(f, "}\n");
    
    fclose(f);
    printf("  Benchmark results exported to: %s\n", filename);
}

//=============================================================================
// Example Benchmarks
//=============================================================================

void setup_malloc(void) {
    // Setup for memory benchmark
}

void teardown_malloc(void) {
    // Cleanup
}

void benchmark_malloc_free(void) {
    void* ptr = malloc(1024);
    free(ptr);
}

void benchmark_memcpy(void) {
    char src[1024];
    char dst[1024];
    memset(src, 'A', sizeof(src));
    memcpy(dst, src, sizeof(src));
}

void benchmark_strlen(void) {
    const char* str = "Hello, World! This is a test string.";
    volatile size_t len = strlen(str);
    (void)len;
}

//=============================================================================
// Main Entry Point
//=============================================================================

int main(int argc, char* argv[]) {
    printf("RawrXD Benchmark Harness\n");
    printf("========================\n\n");
    
    // Parse arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            g_suite.global_iterations = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-w") == 0 && i + 1 < argc) {
            g_suite.global_warmup = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-v") == 0) {
            g_suite.verbose = 1;
        } else if (strcmp(argv[i], "--json") == 0) {
            g_suite.json_output = 1;
        }
    }
    
    // Register benchmarks
    benchmark_register("malloc_free", "Memory allocation/deallocation",
                       setup_malloc, teardown_malloc, benchmark_malloc_free);
    benchmark_register("memcpy_1kb", "1KB memory copy",
                       NULL, NULL, benchmark_memcpy);
    benchmark_register("strlen", "String length calculation",
                       NULL, NULL, benchmark_strlen);
    
    // Run benchmarks
    printf("Running %d benchmark(s)...\n\n", g_suite.benchmark_count);
    
    for (int i = 0; i < g_suite.benchmark_count; i++) {
        run_benchmark(&g_suite.benchmarks[i]);
        print_benchmark_results(&g_suite.benchmarks[i]);
    }
    
    print_summary();
    
    if (g_suite.json_output) {
        export_json("benchmark_results.json");
    }
    
    // Cleanup
    for (int i = 0; i < g_suite.benchmark_count; i++) {
        free(g_suite.benchmarks[i].stats.samples);
    }
    
    return 0;
}
