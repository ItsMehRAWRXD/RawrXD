//=============================================================================
// performance_benchmark.c - Performance Benchmark Tool
// Production-ready benchmarking with statistical analysis
//=============================================================================

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <math.h>

//=============================================================================
// Benchmark Types
//=============================================================================

#define MAX_ITERATIONS 100000
#define MAX_BENCHMARKS 50
#define MAX_NAME_LEN 256

typedef enum {
    BENCH_CPU,
    BENCH_MEMORY,
    BENCH_IO,
    BENCH_NETWORK,
    BENCH_CUSTOM
} BenchmarkType;

typedef struct {
    char name[MAX_NAME_LEN];
    BenchmarkType type;
    int iterations;
    int warmup_iterations;
    
    double* samples;
    int sample_count;
    int sample_capacity;
    
    double min_time;
    double max_time;
    double mean_time;
    double median_time;
    double std_dev;
    double p95_time;
    double p99_time;
    double total_time;
    
    double ops_per_sec;
    double throughput;
    
    int error_count;
    char error_message[1024];
} Benchmark;

typedef struct {
    Benchmark* benchmarks;
    int benchmark_count;
    int benchmark_capacity;
    
    time_t start_time;
    time_t end_time;
    double total_duration;
    
    int total_iterations;
    int total_errors;
} BenchmarkReport;

//=============================================================================
// Timing Utilities
//=============================================================================

#ifdef _WIN32
#include <windows.h>

double get_time_us(void) {
    LARGE_INTEGER freq, count;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&count);
    return (double)count.QuadPart * 1000000.0 / (double)freq.QuadPart;
}
#else
#include <sys/time.h>

double get_time_us(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (double)tv.tv_sec * 1000000.0 + (double)tv.tv_usec;
}
#endif

double get_time_ms(void) {
    return get_time_us() / 1000.0;
}

//=============================================================================
// Benchmark Implementation
//=============================================================================

BenchmarkReport* benchmark_create_report(void) {
    BenchmarkReport* report = (BenchmarkReport*)calloc(1, sizeof(BenchmarkReport));
    report->benchmark_capacity = MAX_BENCHMARKS;
    report->benchmarks = (Benchmark*)calloc(report->benchmark_capacity, sizeof(Benchmark));
    report->start_time = time(NULL);
    return report;
}

void benchmark_destroy_report(BenchmarkReport* report) {
    if (!report) return;
    
    for (int i = 0; i < report->benchmark_count; i++) {
        free(report->benchmarks[i].samples);
    }
    
    free(report->benchmarks);
    free(report);
}

Benchmark* add_benchmark(BenchmarkReport* report, const char* name, BenchmarkType type) {
    if (report->benchmark_count >= report->benchmark_capacity) return NULL;
    
    Benchmark* bench = &report->benchmarks[report->benchmark_count++];
    strncpy(bench->name, name, sizeof(bench->name) - 1);
    bench->type = type;
    bench->iterations = 1000;
    bench->warmup_iterations = 100;
    bench->sample_capacity = MAX_ITERATIONS;
    bench->samples = (double*)calloc(bench->sample_capacity, sizeof(double));
    bench->min_time = 1e9;
    bench->max_time = 0;
    return bench;
}

void calculate_statistics(Benchmark* bench) {
    if (bench->sample_count == 0) return;
    
    // Calculate mean
    double sum = 0;
    for (int i = 0; i < bench->sample_count; i++) {
        sum += bench->samples[i];
    }
    bench->mean_time = sum / bench->sample_count;
    bench->total_time = sum;
    
    // Calculate min/max
    for (int i = 0; i < bench->sample_count; i++) {
        if (bench->samples[i] < bench->min_time) bench->min_time = bench->samples[i];
        if (bench->samples[i] > bench->max_time) bench->max_time = bench->samples[i];
    }
    
    // Calculate standard deviation
    double variance_sum = 0;
    for (int i = 0; i < bench->sample_count; i++) {
        double diff = bench->samples[i] - bench->mean_time;
        variance_sum += diff * diff;
    }
    bench->std_dev = sqrt(variance_sum / bench->sample_count);
    
    // Sort for percentiles
    for (int i = 0; i < bench->sample_count - 1; i++) {
        for (int j = 0; j < bench->sample_count - i - 1; j++) {
            if (bench->samples[j] > bench->samples[j + 1]) {
                double temp = bench->samples[j];
                bench->samples[j] = bench->samples[j + 1];
                bench->samples[j + 1] = temp;
            }
        }
    }
    
    // Calculate percentiles
    bench->median_time = bench->samples[bench->sample_count / 2];
    bench->p95_time = bench->samples[(int)(bench->sample_count * 0.95)];
    bench->p99_time = bench->samples[(int)(bench->sample_count * 0.99)];
    
    // Calculate throughput
    bench->ops_per_sec = bench->iterations / (bench->total_time / 1000000.0);
}

//=============================================================================
// Benchmark Functions
//=============================================================================

void benchmark_cpu_intensive(Benchmark* bench) {
    // Warmup
    for (int i = 0; i < bench->warmup_iterations; i++) {
        volatile int x = i * i;
        (void)x;
    }
    
    // Benchmark
    for (int i = 0; i < bench->iterations && i < bench->sample_capacity; i++) {
        double start = get_time_us();
        
        // CPU intensive work
        volatile long sum = 0;
        for (int j = 0; j < 1000; j++) {
            sum += j * j;
        }
        (void)sum;
        
        double end = get_time_us();
        bench->samples[bench->sample_count++] = end - start;
    }
}

void benchmark_memory_allocation(Benchmark* bench) {
    // Warmup
    for (int i = 0; i < bench->warmup_iterations; i++) {
        void* ptr = malloc(1024);
        free(ptr);
    }
    
    // Benchmark
    for (int i = 0; i < bench->iterations && i < bench->sample_capacity; i++) {
        double start = get_time_us();
        
        void* ptr = malloc(1024);
        memset(ptr, 0, 1024);
        free(ptr);
        
        double end = get_time_us();
        bench->samples[bench->sample_count++] = end - start;
    }
}

void benchmark_string_operations(Benchmark* bench) {
    char buffer[1024];
    
    // Warmup
    for (int i = 0; i < bench->warmup_iterations; i++) {
        snprintf(buffer, sizeof(buffer), "Iteration %d", i);
    }
    
    // Benchmark
    for (int i = 0; i < bench->iterations && i < bench->sample_capacity; i++) {
        double start = get_time_us();
        
        snprintf(buffer, sizeof(buffer), "Iteration %d with some longer text", i);
        size_t len = strlen(buffer);
        (void)len;
        
        double end = get_time_us();
        bench->samples[bench->sample_count++] = end - start;
    }
}

void benchmark_hash_computation(Benchmark* bench) {
    char data[256];
    memset(data, 'A', sizeof(data));
    
    // Warmup
    for (int i = 0; i < bench->warmup_iterations; i++) {
        unsigned int hash = 0;
        for (size_t j = 0; j < sizeof(data); j++) {
            hash = hash * 31 + data[j];
        }
        (void)hash;
    }
    
    // Benchmark
    for (int i = 0; i < bench->iterations && i < bench->sample_capacity; i++) {
        double start = get_time_us();
        
        unsigned int hash = 0;
        for (size_t j = 0; j < sizeof(data); j++) {
            hash = hash * 31 + data[j];
        }
        (void)hash;
        
        double end = get_time_us();
        bench->samples[bench->sample_count++] = end - start;
    }
}

void run_benchmark(Benchmark* bench) {
    switch (bench->type) {
        case BENCH_CPU:
            benchmark_cpu_intensive(bench);
            break;
        case BENCH_MEMORY:
            benchmark_memory_allocation(bench);
            break;
        case BENCH_IO:
            benchmark_string_operations(bench);
            break;
        case BENCH_NETWORK:
            benchmark_hash_computation(bench);
            break;
        default:
            benchmark_cpu_intensive(bench);
            break;
    }
    
    calculate_statistics(bench);
}

void run_all_benchmarks(BenchmarkReport* report) {
    for (int i = 0; i < report->benchmark_count; i++) {
        printf("Running: %s\n", report->benchmarks[i].name);
        run_benchmark(&report->benchmarks[i]);
        report->total_iterations += report->benchmarks[i].iterations;
    }
    
    report->end_time = time(NULL);
    report->total_duration = difftime(report->end_time, report->start_time);
}

//=============================================================================
// Report Generation
//=============================================================================

void print_benchmark_summary(BenchmarkReport* report) {
    printf("\n");
    printf("=============================================================================\n");
    printf("  Performance Benchmark Summary\n");
    printf("=============================================================================\n");
    printf("  Benchmarks Run:     %d\n", report->benchmark_count);
    printf("  Total Duration:     %.2f seconds\n", report->total_duration);
    printf("  Total Iterations:   %d\n", report->total_iterations);
    printf("=============================================================================\n");
}

void print_benchmark_results(BenchmarkReport* report) {
    printf("\n");
    printf("=============================================================================\n");
    printf("  Benchmark Results\n");
    printf("=============================================================================\n");
    
    for (int i = 0; i < report->benchmark_count; i++) {
        Benchmark* bench = &report->benchmarks[i];
        
        printf("\n  %s\n", bench->name);
        printf("  ---------------------------------------------------------------------------\n");
        printf("    Iterations:       %d\n", bench->iterations);
        printf("    Total Time:         %.2f ms\n", bench->total_time / 1000.0);
        printf("    Mean Time:          %.3f us\n", bench->mean_time);
        printf("    Min Time:           %.3f us\n", bench->min_time);
        printf("    Max Time:           %.3f us\n", bench->max_time);
        printf("    Median Time:        %.3f us\n", bench->median_time);
        printf("    Std Dev:            %.3f us\n", bench->std_dev);
        printf("    P95 Time:           %.3f us\n", bench->p95_time);
        printf("    P99 Time:           %.3f us\n", bench->p99_time);
        printf("    Ops/Sec:            %.0f\n", bench->ops_per_sec);
    }
    
    printf("\n=============================================================================\n");
}

void export_benchmark_json(BenchmarkReport* report, const char* filename) {
    FILE* f = fopen(filename, "w");
    if (!f) return;
    
    fprintf(f, "{\n");
    fprintf(f, "  \"summary\": {\n");
    fprintf(f, "    \"benchmarks_run\": %d,\n", report->benchmark_count);
    fprintf(f, "    \"total_duration\": %.2f,\n", report->total_duration);
    fprintf(f, "    \"total_iterations\": %d\n", report->total_iterations);
    fprintf(f, "  },\n");
    fprintf(f, "  \"benchmarks\": [\n");
    
    for (int i = 0; i < report->benchmark_count; i++) {
        Benchmark* bench = &report->benchmarks[i];
        fprintf(f, "    {\n");
        fprintf(f, "      \"name\": \"%s\",\n", bench->name);
        fprintf(f, "      \"iterations\": %d,\n", bench->iterations);
        fprintf(f, "      \"mean_time_us\": %.3f,\n", bench->mean_time);
        fprintf(f, "      \"min_time_us\": %.3f,\n", bench->min_time);
        fprintf(f, "      \"max_time_us\": %.3f,\n", bench->max_time);
        fprintf(f, "      \"median_time_us\": %.3f,\n", bench->median_time);
        fprintf(f, "      \"std_dev_us\": %.3f,\n", bench->std_dev);
        fprintf(f, "      \"p95_time_us\": %.3f,\n", bench->p95_time);
        fprintf(f, "      \"p99_time_us\": %.3f,\n", bench->p99_time);
        fprintf(f, "      \"ops_per_sec\": %.0f\n", bench->ops_per_sec);
        fprintf(f, "    }%s\n", (i < report->benchmark_count - 1) ? "," : "");
    }
    
    fprintf(f, "  ]\n");
    fprintf(f, "}\n");
    
    fclose(f);
    printf("  Benchmark report exported: %s\n", filename);
}

//=============================================================================
// Main Entry Point
//=============================================================================

int main(int argc, char* argv[]) {
    printf("RawrXD Performance Benchmark Tool\n");
    printf("=================================\n\n");
    
    BenchmarkReport* report = benchmark_create_report();
    
    // Add benchmarks
    printf("Configuring benchmarks...\n");
    
    Benchmark* bench = add_benchmark(report, "CPU Integer Operations", BENCH_CPU);
    bench->iterations = 10000;
    
    bench = add_benchmark(report, "Memory Allocation", BENCH_MEMORY);
    bench->iterations = 10000;
    
    bench = add_benchmark(report, "String Formatting", BENCH_IO);
    bench->iterations = 50000;
    
    bench = add_benchmark(report, "Hash Computation", BENCH_NETWORK);
    bench->iterations = 50000;
    
    // Run benchmarks
    printf("\nRunning benchmarks...\n\n");
    run_all_benchmarks(report);
    
    // Generate reports
    print_benchmark_summary(report);
    print_benchmark_results(report);
    export_benchmark_json(report, "benchmark_report.json");
    
    printf("\nBenchmark complete!\n");
    
    benchmark_destroy_report(report);
    
    return 0;
}
