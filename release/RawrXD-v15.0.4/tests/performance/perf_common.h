/*
 * RawrXD Performance Testing Common Header
 * Milestone 3: Performance Baselines
 */

#ifndef PERF_COMMON_H
#define PERF_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <math.h>
#include <string.h>

#ifdef _WIN32
    #include <windows.h>
    typedef LARGE_INTEGER perf_counter_t;
#else
    #include <sys/time.h>
    typedef struct timeval perf_counter_t;
#endif

/* Performance metrics */
typedef struct {
    double elapsed_ms;
    double throughput_gops;  /* Giga-operations per second */
    double bandwidth_gbps;   /* GB/s memory bandwidth */
    double tokens_per_sec;   /* For generation tasks */
    size_t bytes_processed;
    size_t operations;
    int iterations;
} perf_metrics_t;

/* Timer functions */
static inline void perf_get_time(perf_counter_t* t) {
#ifdef _WIN32
    QueryPerformanceCounter(t);
#else
    gettimeofday(t, NULL);
#endif
}

static inline double perf_get_elapsed_ms(const perf_counter_t* start, const perf_counter_t* end) {
#ifdef _WIN32
    static double freq = 0;
    if (freq == 0) {
        LARGE_INTEGER f;
        QueryPerformanceFrequency(&f);
        freq = (double)f.QuadPart / 1000.0; /* Convert to ms */
    }
    return (double)(end->QuadPart - start->QuadPart) / freq;
#else
    return (end->tv_sec - start->tv_sec) * 1000.0 + 
           (end->tv_usec - start->tv_usec) / 1000.0;
#endif
}

/* Warmup function to stabilize CPU/cache */
static inline void perf_warmup(void* data, size_t size) {
    volatile char* ptr = (volatile char*)data;
    for (size_t i = 0; i < size; i += 64) { /* 64-byte cache line stride */
        ptr[i] = (char)(i & 0xFF);
    }
}

/* Calculate memory bandwidth */
static inline double perf_calc_bandwidth_gbps(size_t bytes, double elapsed_ms) {
    return (bytes / (1024.0 * 1024.0 * 1024.0)) / (elapsed_ms / 1000.0);
}

/* Calculate throughput in GOPS */
static inline double perf_calc_throughput_gops(size_t ops, double elapsed_ms) {
    return (ops / 1e9) / (elapsed_ms / 1000.0);
}

/* Print metrics */
static inline void perf_print_metrics(const char* name, const perf_metrics_t* m) {
    printf("  %s:\n", name);
    printf("    Elapsed:      %.3f ms\n", m->elapsed_ms);
    printf("    Throughput:   %.3f GOPS\n", m->throughput_gops);
    printf("    Bandwidth:    %.3f GB/s\n", m->bandwidth_gbps);
    if (m->tokens_per_sec > 0) {
        printf("    Tokens/sec:   %.2f\n", m->tokens_per_sec);
    }
    printf("    Iterations:   %d\n", m->iterations);
}

/* Save benchmark result to JSON */
static inline int perf_save_result(const char* filename, const char* test_name, 
                                    const perf_metrics_t* m) {
    FILE* f = fopen(filename, "a");
    if (!f) return -1;
    
    fprintf(f, "{\n");
    fprintf(f, "  \"test\": \"%s\",\n", test_name);
    fprintf(f, "  \"elapsed_ms\": %.6f,\n", m->elapsed_ms);
    fprintf(f, "  \"throughput_gops\": %.6f,\n", m->throughput_gops);
    fprintf(f, "  \"bandwidth_gbps\": %.6f,\n", m->bandwidth_gbps);
    fprintf(f, "  \"tokens_per_sec\": %.6f,\n", m->tokens_per_sec);
    fprintf(f, "  \"bytes_processed\": %zu,\n", m->bytes_processed);
    fprintf(f, "  \"operations\": %zu,\n", m->operations);
    fprintf(f, "  \"iterations\": %d\n", m->iterations);
    fprintf(f, "},\n");
    
    fclose(f);
    return 0;
}

/* Baseline comparison */
typedef struct {
    double elapsed_ms_baseline;
    double throughput_gops_baseline;
    double tolerance_percent;
} perf_baseline_t;

static inline int perf_check_regression(const char* name, 
                                         const perf_metrics_t* current,
                                         const perf_baseline_t* baseline) {
    double elapsed_diff = ((current->elapsed_ms - baseline->elapsed_ms_baseline) 
                           / baseline->elapsed_ms_baseline) * 100.0;
    double throughput_diff = ((baseline->throughput_gops_baseline - current->throughput_gops) 
                              / baseline->throughput_gops_baseline) * 100.0;
    
    int regressed = 0;
    
    if (elapsed_diff > baseline->tolerance_percent) {
        printf("  ⚠️  %s REGRESSION: elapsed time +%.1f%% (baseline: %.3f ms, current: %.3f ms)\n",
               name, elapsed_diff, baseline->elapsed_ms_baseline, current->elapsed_ms);
        regressed = 1;
    }
    
    if (throughput_diff > baseline->tolerance_percent) {
        printf("  ⚠️  %s REGRESSION: throughput -%.1f%% (baseline: %.3f GOPS, current: %.3f GOPS)\n",
               name, throughput_diff, baseline->throughput_gops_baseline, current->throughput_gops);
        regressed = 1;
    }
    
    if (!regressed) {
        printf("  ✓ %s within tolerance (elapsed: %+.1f%%, throughput: %+.1f%%)\n",
               name, elapsed_diff, -throughput_diff);
    }
    
    return regressed;
}

#endif /* PERF_COMMON_H */
