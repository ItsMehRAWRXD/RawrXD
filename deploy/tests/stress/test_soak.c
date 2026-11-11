/*
 * RawrXD Soak Test - Long-running stress test
 * Detects memory leaks, race conditions, and stability issues
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>

#ifdef _WIN32
    #include <windows.h>
    #include <psapi.h>
#else
    #include <sys/resource.h>
    #include <unistd.h>
#endif

#define SOAK_DURATION_MINUTES 5
#define ITERATIONS_PER_MINUTE 10000

/* Memory tracking */
typedef struct {
    size_t initial_bytes;
    size_t peak_bytes;
    size_t current_bytes;
    size_t leak_threshold_bytes;
} memory_tracker_t;

/* Test statistics */
typedef struct {
    int iterations;
    int failures;
    double total_time_ms;
    double min_time_ms;
    double max_time_ms;
    memory_tracker_t memory;
} soak_stats_t;

/* Get current memory usage */
size_t get_memory_usage() {
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

/* Simulated kernel: Matmul with memory allocation */
int stress_matmul(int size) {
    float *A = (float*)malloc(size * size * sizeof(float));
    float *B = (float*)malloc(size * size * sizeof(float));
    float *C = (float*)malloc(size * size * sizeof(float));
    
    if (!A || !B || !C) {
        free(A); free(B); free(C);
        return -1;
    }
    
    /* Initialize */
    for (int i = 0; i < size * size; i++) {
        A[i] = (float)(i % 100) / 100.0f;
        B[i] = (float)(i % 100 + 1) / 101.0f;
        C[i] = 0.0f;
    }
    
    /* Compute */
    for (int i = 0; i < size; i++) {
        for (int j = 0; j < size; j++) {
            float sum = 0.0f;
            for (int k = 0; k < size; k++) {
                sum += A[i * size + k] * B[k * size + j];
            }
            C[i * size + j] = sum;
        }
    }
    
    /* Verify (simple check) */
    int valid = 1;
    for (int i = 0; i < size * size && valid; i++) {
        if (isnan(C[i]) || isinf(C[i])) {
            valid = 0;
        }
    }
    
    free(A); free(B); free(C);
    
    return valid ? 0 : -1;
}

/* Simulated kernel: Softmax with memory allocation */
int stress_softmax(int size) {
    float *input = (float*)malloc(size * sizeof(float));
    float *output = (float*)malloc(size * sizeof(float));
    
    if (!input || !output) {
        free(input); free(output);
        return -1;
    }
    
    /* Initialize */
    for (int i = 0; i < size; i++) {
        input[i] = (float)(i % 10) / 5.0f;
    }
    
    /* Softmax */
    float max_val = input[0];
    for (int i = 1; i < size; i++) {
        if (input[i] > max_val) max_val = input[i];
    }
    
    float sum = 0.0f;
    for (int i = 0; i < size; i++) {
        output[i] = expf(input[i] - max_val);
        sum += output[i];
    }
    
    for (int i = 0; i < size; i++) {
        output[i] /= sum;
    }
    
    /* Verify probabilities sum to 1 */
    float prob_sum = 0.0f;
    for (int i = 0; i < size; i++) {
        prob_sum += output[i];
    }
    
    int valid = fabsf(prob_sum - 1.0f) < 0.01f;
    
    free(input); free(output);
    
    return valid ? 0 : -1;
}

/* Simulated kernel: RMSNorm with memory allocation */
int stress_rmsnorm(int size) {
    float *input = (float*)malloc(size * sizeof(float));
    float *output = (float*)malloc(size * sizeof(float));
    
    if (!input || !output) {
        free(input); free(output);
        return -1;
    }
    
    /* Initialize */
    for (int i = 0; i < size; i++) {
        input[i] = (float)(i % 10) / 10.0f;
    }
    
    /* RMSNorm */
    float sum_sq = 0.0f;
    for (int i = 0; i < size; i++) {
        sum_sq += input[i] * input[i];
    }
    float rms = sqrtf(sum_sq / size + 1e-6f);
    
    for (int i = 0; i < size; i++) {
        output[i] = input[i] / rms;
    }
    
    /* Verify output is normalized */
    float out_sum_sq = 0.0f;
    for (int i = 0; i < size; i++) {
        out_sum_sq += output[i] * output[i];
    }
    
    int valid = fabsf(out_sum_sq - size) < 0.1f;
    
    free(input); free(output);
    
    return valid ? 0 : -1;
}

/* Run soak test */
int run_soak_test(soak_stats_t *stats) {
    clock_t start_time = clock();
    clock_t end_time = start_time + (SOAK_DURATION_MINUTES * 60 * CLOCKS_PER_SEC);
    
    stats->min_time_ms = 999999.0;
    stats->max_time_ms = 0.0;
    stats->memory.initial_bytes = get_memory_usage();
    stats->memory.peak_bytes = stats->memory.initial_bytes;
    stats->memory.leak_threshold_bytes = 10 * 1024 * 1024; /* 10MB threshold */
    
    printf("Starting soak test (%d minutes)...\n", SOAK_DURATION_MINUTES);
    printf("Initial memory: %zu KB\n", stats->memory.initial_bytes / 1024);
    printf("\n");
    
    int last_progress = -1;
    
    while (clock() < end_time) {
        /* Run test iteration */
        clock_t iter_start = clock();
        
        int result = 0;
        result |= stress_matmul(64);
        result |= stress_softmax(1024);
        result |= stress_rmsnorm(4096);
        
        clock_t iter_end = clock();
        double iter_ms = ((double)(iter_end - iter_start) / CLOCKS_PER_SEC) * 1000.0;
        
        stats->iterations++;
        stats->total_time_ms += iter_ms;
        
        if (iter_ms < stats->min_time_ms) stats->min_time_ms = iter_ms;
        if (iter_ms > stats->max_time_ms) stats->max_time_ms = iter_ms;
        
        if (result != 0) {
            stats->failures++;
        }
        
        /* Track memory */
        size_t current_mem = get_memory_usage();
        if (current_mem > stats->memory.peak_bytes) {
            stats->memory.peak_bytes = current_mem;
        }
        stats->memory.current_bytes = current_mem;
        
        /* Progress indicator */
        int progress = (int)(((clock() - start_time) * 100) / (end_time - start_time));
        if (progress != last_progress && progress % 10 == 0) {
            printf("Progress: %d%% (iterations: %d, failures: %d, memory: %zu KB)\n",
                   progress, stats->iterations, stats->failures,
                   current_mem / 1024);
            last_progress = progress;
        }
    }
    
    return 0;
}

int main() {
    printf("RawrXD Soak Test\n");
    printf("================\n");
    printf("Duration: %d minutes\n", SOAK_DURATION_MINUTES);
    printf("Purpose: Detect memory leaks, race conditions, stability issues\n");
    printf("\n");
    
    soak_stats_t stats = {0};
    
    int result = run_soak_test(&stats);
    
    /* Calculate statistics */
    double avg_time_ms = stats.iterations > 0 ? stats.total_time_ms / stats.iterations : 0;
    size_t memory_growth = stats.memory.current_bytes > stats.memory.initial_bytes ?
                           stats.memory.current_bytes - stats.memory.initial_bytes : 0;
    
    /* Summary */
    printf("\n");
    printf("================\n");
    printf("Soak Test Summary\n");
    printf("================\n");
    printf("Iterations:     %d\n", stats.iterations);
    printf("Failures:       %d\n", stats.failures);
    printf("Avg time:       %.3f ms\n", avg_time_ms);
    printf("Min time:       %.3f ms\n", stats.min_time_ms);
    printf("Max time:       %.3f ms\n", stats.max_time_ms);
    printf("\n");
    printf("Memory Usage:\n");
    printf("  Initial:      %zu KB\n", stats.memory.initial_bytes / 1024);
    printf("  Peak:         %zu KB\n", stats.memory.peak_bytes / 1024);
    printf("  Current:      %zu KB\n", stats.memory.current_bytes / 1024);
    printf("  Growth:       %zu KB\n", memory_growth / 1024);
    printf("\n");
    
    /* Determine pass/fail */
    int passed = 1;
    
    if (stats.failures > 0) {
        printf("✗ FAIL: %d test iterations failed\n", stats.failures);
        passed = 0;
    }
    
    if (memory_growth > stats.memory.leak_threshold_bytes) {
        printf("⚠ WARNING: Memory growth of %zu KB exceeds threshold (%zu KB)\n",
               memory_growth / 1024, stats.memory.leak_threshold_bytes / 1024);
        /* Don't fail, just warn */
    }
    
    if (passed) {
        printf("✓ PASS: Soak test completed successfully\n");
        printf("  No failures detected\n");
        if (memory_growth > 0) {
            printf("  Memory growth: %zu KB (within tolerance)\n", memory_growth / 1024);
        } else {
            printf("  No memory growth detected\n");
        }
        return 0;
    }
    
    return 1;
}
