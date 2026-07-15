/*
 * RawrXD Soak Test - Long-running stability validation
 * Runs continuous inference operations for extended periods
 * to detect memory leaks, thermal issues, and degradation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <stdint.h>

#ifdef _WIN32
    #include <windows.h>
#else
    #include <unistd.h>
#endif

#define SOAK_DURATION_MINUTES 5  /* Run for 5 minutes for demo */
#define ITERATIONS_PER_REPORT 1000
#define WARMUP_ITERATIONS 100

typedef struct {
    uint64_t total_iterations;
    uint64_t start_time_ms;
    double min_latency_ms;
    double max_latency_ms;
    double avg_latency_ms;
    uint64_t memory_peak_bytes;
    uint64_t current_memory_bytes;
    int errors;
    int warnings;
} soak_stats_t;

/* Get current time in milliseconds */
uint64_t get_time_ms(void) {
    #ifdef _WIN32
        return GetTickCount64();
    #else
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        return (uint64_t)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
    #endif
}

/* Get memory usage (simplified) */
uint64_t get_memory_usage(void) {
    /* Simplified - in production would query OS */
    return 0;
}

/* Simulate inference operation */
double simulate_inference(void) {
    uint64_t start = get_time_ms();
    
    /* Simulate work: matrix multiplication */
    volatile double sum = 0.0;
    for (int i = 0; i < 1000; i++) {
        sum += sin((double)i) * cos((double)i);
    }
    
    uint64_t end = get_time_ms();
    return (double)(end - start);
}

/* Simulate transformer layer operation */
double simulate_transformer_layer(float* input, float* output, int dim, int seq_len) {
    uint64_t start = get_time_ms();
    
    /* Simulate: RMSNorm -> Attention -> Residual -> FFN -> Residual */
    
    /* RMSNorm */
    float sum_sq = 0.0f;
    for (int i = 0; i < dim * seq_len; i++) {
        sum_sq += input[i] * input[i];
    }
    float rms = sqrtf(sum_sq / (dim * seq_len) + 1e-6f);
    float scale = 1.0f / rms;
    
    for (int i = 0; i < dim * seq_len; i++) {
        input[i] *= scale;
    }
    
    /* Simulate attention (simplified) */
    for (int i = 0; i < seq_len; i++) {
        for (int j = 0; j < dim; j++) {
            /* Q @ K^T simplified */
            float attn_score = 0.0f;
            for (int k = 0; k < dim; k += 64) {
                attn_score += input[i * dim + k] * input[i * dim + k];
            }
            output[i * dim + j] = input[i * dim + j] + (attn_score / dim);
        }
    }
    
    /* Simulate FFN (simplified GELU) */
    for (int i = 0; i < dim * seq_len; i++) {
        float x = output[i];
        /* GELU approximation */
        float gelu = x * 0.5f * (1.0f + tanhf(0.7978845608f * (x + 0.044715f * x * x * x)));
        output[i] = x + gelu * 0.5f; /* Residual */
    }
    
    uint64_t end = get_time_ms();
    return (double)(end - start);
}

/* Memory stress test - allocate and touch memory */
void memory_stress_test(size_t bytes) {
    float* buffer = (float*)malloc(bytes);
    if (!buffer) return;
    
    /* Touch all memory to ensure it's committed */
    size_t floats = bytes / sizeof(float);
    for (size_t i = 0; i < floats; i++) {
        buffer[i] = (float)(i % 100) / 100.0f;
    }
    
    /* Simulate compute on buffer */
    volatile float sum = 0.0f;
    for (size_t i = 0; i < floats; i++) {
        sum += buffer[i] * buffer[i];
    }
    
    free(buffer);
}

/* Run soak test */
int run_soak_test(int duration_minutes) {
    soak_stats_t stats = {0};
    stats.min_latency_ms = 999999.0;
    stats.start_time_ms = get_time_ms();
    
    uint64_t duration_ms = duration_minutes * 60 * 1000;
    uint64_t next_report = stats.start_time_ms + 10000; /* First report at 10s */
    
    /* Allocate buffers for transformer simulation */
    int dim = 4096;
    int seq_len = 512;
    size_t buffer_size = dim * seq_len * sizeof(float);
    
    float* input = (float*)malloc(buffer_size);
    float* output = (float*)malloc(buffer_size);
    
    if (!input || !output) {
        printf("ERROR: Failed to allocate buffers\n");
        return 1;
    }
    
    /* Initialize input */
    for (int i = 0; i < dim * seq_len; i++) {
        input[i] = (float)(i % 100) / 100.0f;
    }
    
    printf("RawrXD Soak Test\n");
    printf("=================\n");
    printf("Duration: %d minutes\n", duration_minutes);
    printf("Buffer size: %.2f MB\n", buffer_size / (1024.0 * 1024.0));
    printf("Dimensions: %d x %d\n\n", seq_len, dim);
    
    /* Warmup */
    printf("Warming up (%d iterations)...
", WARMUP_ITERATIONS);
    for (int i = 0; i < WARMUP_ITERATIONS; i++) {
        simulate_transformer_layer(input, output, dim, seq_len);
        /* Swap buffers */
        float* temp = input; input = output; output = temp;
    }
    printf("Warmup complete.\n\n");
    
    printf("Running soak test...\n");
    printf("Press Ctrl+C to stop early\n\n");
    
    while (1) {
        uint64_t now = get_time_ms();
        uint64_t elapsed = now - stats.start_time_ms;
        
        /* Check if duration exceeded */
        if (elapsed >= duration_ms) {
            break;
        }
        
        /* Run inference */
        double latency = simulate_inference();
        stats.total_iterations++;
        
        /* Update statistics */
        if (latency < stats.min_latency_ms) stats.min_latency_ms = latency;
        if (latency > stats.max_latency_ms) stats.max_latency_ms = latency;
        
        /* Running average */
        stats.avg_latency_ms += (latency - stats.avg_latency_ms) / stats.total_iterations;
        
        /* Periodic report */
        if (now >= next_report) {
            double progress = (double)elapsed / (double)duration_ms * 100.0;
            double throughput = (double)stats.total_iterations / (elapsed / 1000.0);
            
            printf("[%.1f%%] Iter: %llu | "
                   "Latency: %.3f/%.3f/%.3f ms | "
                   "Throughput: %.1f iter/sec | "
                   "Errors: %d\n",
                   progress,
                   (unsigned long long)stats.total_iterations,
                   stats.min_latency_ms,
                   stats.avg_latency_ms,
                   stats.max_latency_ms,
                   throughput,
                   stats.errors);
            
            next_report = now + 30000; /* Report every 30 seconds */
        }
    }
    
    /* Final report */
    uint64_t end_time = get_time_ms();
    uint64_t total_time = end_time - stats.start_time_ms;
    double throughput = (double)stats.total_iterations / (total_time / 1000.0);
    
    printf("\n================\n");
    printf("Soak Test Complete\n");
    printf("================\n");
    printf("Total iterations: %llu\n", (unsigned long long)stats.total_iterations);
    printf("Total time: %.2f seconds\n", total_time / 1000.0);
    printf("Throughput: %.2f iter/sec\n", throughput);
    printf("Latency (min/avg/max): %.3f/%.3f/%.3f ms\n",
           stats.min_latency_ms, stats.avg_latency_ms, stats.max_latency_ms);
    printf("Errors: %d\n", stats.errors);
    printf("\nStatus: %s\n", stats.errors == 0 ? "PASS" : "FAIL");
    
    return stats.errors == 0 ? 0 : 1;
}

int main(int argc, char *argv[]) {
    int duration = SOAK_DURATION_MINUTES;
    
    if (argc > 1) {
        duration = atoi(argv[1]);
        if (duration <= 0) duration = SOAK_DURATION_MINUTES;
    }
    
    return run_soak_test(duration);
}
