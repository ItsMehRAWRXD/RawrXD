/*
 * RawrXD Attention Mechanism Performance Test
 * Milestone 3: Performance Baselines
 */

#define _GNU_SOURCE
#include "perf_common.h"
#include <math.h>
#include <string.h>
#include <stdlib.h>

#define HEAD_DIM 128
#define NUM_HEADS 32
#define SEQ_LEN 512

/* Reference attention implementation */
void reference_attention(const float* Q, const float* K, const float* V,
                         float* output, int seq_len, int head_dim) {
    float* scores = (float*)malloc(seq_len * seq_len * sizeof(float));
    
    /* Q @ K^T */
    for (int i = 0; i < seq_len; i++) {
        for (int j = 0; j < seq_len; j++) {
            float sum = 0.0f;
            for (int k = 0; k < head_dim; k++) {
                sum += Q[i * head_dim + k] * K[j * head_dim + k];
            }
            scores[i * seq_len + j] = sum / sqrtf((float)head_dim);
        }
    }
    
    /* Softmax */
    for (int i = 0; i < seq_len; i++) {
        float max_val = scores[i * seq_len];
        for (int j = 1; j < seq_len; j++) {
            if (scores[i * seq_len + j] > max_val) {
                max_val = scores[i * seq_len + j];
            }
        }
        
        float sum = 0.0f;
        for (int j = 0; j < seq_len; j++) {
            scores[i * seq_len + j] = expf(scores[i * seq_len + j] - max_val);
            sum += scores[i * seq_len + j];
        }
        
        for (int j = 0; j < seq_len; j++) {
            scores[i * seq_len + j] /= sum;
        }
    }
    
    /* Softmax @ V */
    for (int i = 0; i < seq_len; i++) {
        for (int k = 0; k < head_dim; k++) {
            float sum = 0.0f;
            for (int j = 0; j < seq_len; j++) {
                sum += scores[i * seq_len + j] * V[j * head_dim + k];
            }
            output[i * head_dim + k] = sum;
        }
    }
    
    free(scores);
}

/* Optimized AVX-512 attention */
#include <immintrin.h>

void optimized_attention(const float* Q, const float* K, const float* V,
                         float* output, int seq_len, int head_dim) {
    float* scores = (float*)aligned_alloc(64, seq_len * seq_len * sizeof(float));
    
    const float scale = 1.0f / sqrtf((float)head_dim);
    const __m512 vscale = _mm512_set1_ps(scale);
    
    /* Q @ K^T with AVX-512 */
    for (int i = 0; i < seq_len; i++) {
        for (int j = 0; j < seq_len; j++) {
            __m512 vsum = _mm512_setzero_ps();
            int k = 0;
            
            /* Vectorized dot product */
            for (; k <= head_dim - 16; k += 16) {
                __m512 vq = _mm512_loadu_ps(&Q[i * head_dim + k]);
                __m512 vk = _mm512_loadu_ps(&K[j * head_dim + k]);
                vsum = _mm512_fmadd_ps(vq, vk, vsum);
            }
            
            /* Horizontal reduction */
            float sum = _mm512_reduce_add_ps(vsum);
            
            /* Scalar tail */
            for (; k < head_dim; k++) {
                sum += Q[i * head_dim + k] * K[j * head_dim + k];
            }
            
            scores[i * seq_len + j] = sum * scale;
        }
    }
    
    /* Softmax with AVX-512 */
    for (int i = 0; i < seq_len; i++) {
        /* Find max */
        __m512 vmax = _mm512_set1_ps(-INFINITY);
        int j = 0;
        for (; j <= seq_len - 16; j += 16) {
            __m512 vs = _mm512_loadu_ps(&scores[i * seq_len + j]);
            vmax = _mm512_max_ps(vmax, vs);
        }
        float max_val = _mm512_reduce_max_ps(vmax);
        for (; j < seq_len; j++) {
            if (scores[i * seq_len + j] > max_val) {
                max_val = scores[i * seq_len + j];
            }
        }
        
        /* Compute exp and sum */
        __m512 vsum = _mm512_setzero_ps();
        __m512 v_max = _mm512_set1_ps(max_val);
        j = 0;
        
        for (; j <= seq_len - 16; j += 16) {
            __m512 vs = _mm512_loadu_ps(&scores[i * seq_len + j]);
            __m512 vshifted = _mm512_sub_ps(vs, v_max);
            /* Store for scalar exp processing */
            _mm512_storeu_ps(&scores[i * seq_len + j], vshifted);
        }
        
        /* Scalar exp for numerical accuracy */
        for (j = 0; j < seq_len; j++) {
            scores[i * seq_len + j] = expf(scores[i * seq_len + j]);
            sum += scores[i * seq_len + j];
        }
        
        float sum = _mm512_reduce_add_ps(vsum);
        for (; j < seq_len; j++) {
            scores[i * seq_len + j] = expf(scores[i * seq_len + j] - max_val);
            sum += scores[i * seq_len + j];
        }
        
        /* Normalize */
        __m512 vsum_inv = _mm512_set1_ps(1.0f / sum);
        j = 0;
        for (; j <= seq_len - 16; j += 16) {
            __m512 vs = _mm512_loadu_ps(&scores[i * seq_len + j]);
            vs = _mm512_mul_ps(vs, vsum_inv);
            _mm512_storeu_ps(&scores[i * seq_len + j], vs);
        }
        for (; j < seq_len; j++) {
            scores[i * seq_len + j] /= sum;
        }
    }
    
    /* Softmax @ V with AVX-512 */
    for (int i = 0; i < seq_len; i++) {
        for (int k = 0; k < head_dim; k++) {
            __m512 vsum = _mm512_setzero_ps();
            int j = 0;
            
            for (; j <= seq_len - 16; j += 16) {
                __m512 vscore = _mm512_loadu_ps(&scores[i * seq_len + j]);
                
                /* Gather V values - need to load 16 separate elements */
                /* For simplicity, using scalar gather or process in chunks */
                /* Full implementation would use _mm512_i32gather_ps */
            }
            
            /* Scalar for now - full gather optimization complex */
            float sum = 0.0f;
            for (j = 0; j < seq_len; j++) {
                sum += scores[i * seq_len + j] * V[j * head_dim + k];
            }
            output[i * head_dim + k] = sum;
        }
    }
    
    free(scores);
}
perf_metrics_t benchmark_attention(int seq_len, int head_dim, int num_heads, int iterations) {
    perf_metrics_t metrics = {0};
    
    size_t size_qkv = seq_len * head_dim * sizeof(float);
    size_t size_out = seq_len * head_dim * sizeof(float);
    
    float* Q = (float*)malloc(size_qkv);
    float* K = (float*)malloc(size_qkv);
    float* V = (float*)malloc(size_qkv);
    float* output = (float*)malloc(size_out);
    
    if (!Q || !K || !V || !output) {
        free(Q); free(K); free(V); free(output);
        return metrics;
    }
    
    /* Initialize */
    for (int i = 0; i < seq_len * head_dim; i++) {
        Q[i] = (float)(i % 10) / 10.0f;
        K[i] = (float)(i % 10 + 1) / 11.0f;
        V[i] = (float)(i % 10 + 2) / 12.0f;
    }
    
    /* Warmup */
    perf_warmup(Q, size_qkv);
    reference_attention(Q, K, V, output, seq_len, head_dim);
    
    /* Benchmark */
    perf_counter_t start, end;
    perf_get_time(&start);
    
    for (int iter = 0; iter < iterations; iter++) {
        reference_attention(Q, K, V, output, seq_len, head_dim);
    }
    
    perf_get_time(&end);
    
    metrics.elapsed_ms = perf_get_elapsed_ms(&start, &end);
    metrics.iterations = iterations;
    metrics.bytes_processed = (size_qkv * 3 + size_out) * iterations;
    /* Attention: Q@K^T (seq^2 * head_dim), softmax (seq^2), @V (seq^2 * head_dim) */
    metrics.operations = (size_t)seq_len * seq_len * head_dim * 4 * iterations;
    metrics.throughput_gops = perf_calc_throughput_gops(metrics.operations, metrics.elapsed_ms);
    metrics.bandwidth_gbps = perf_calc_bandwidth_gbps(metrics.bytes_processed, metrics.elapsed_ms);
    
    /* Calculate tokens per second */
    double total_tokens = (double)seq_len * iterations;
    metrics.tokens_per_sec = total_tokens / (metrics.elapsed_ms / 1000.0);
    
    free(Q);
    free(K);
    free(V);
    free(output);
    
    return metrics;
}

int main() {
    printf("RawrXD Attention Mechanism Performance Test\n");
    printf("=============================================\n\n");
    
    int tests_passed = 0;
    int tests_failed = 0;
    
    /* Test configurations: (seq_len, head_dim, num_heads, iterations) */
    int configs[][4] = {
        {128, 64, 8, 100},      /* Small model */
        {512, 128, 32, 20},     /* Medium model */
        {2048, 128, 32, 5},     /* Large context */
    };
    
    const char* config_names[] = {
        "Small (seq=128, heads=8)",
        "Medium (seq=512, heads=32)",
        "Large Context (seq=2048, heads=32)"
    };
    
    /* Baselines */
    perf_baseline_t baselines[] = {
        {5.0, 2.0, 30.0},    /* Small: 5ms, 2 GOPS, 30% tolerance */
        {50.0, 5.0, 30.0},   /* Medium: 50ms, 5 GOPS, 30% tolerance */
        {500.0, 8.0, 35.0},  /* Large: 500ms, 8 GOPS, 35% tolerance */
    };
    
    printf("Running attention benchmarks...\n\n");
    
    for (int i = 0; i < 3; i++) {
        int seq_len = configs[i][0];
        int head_dim = configs[i][1];
        int num_heads = configs[i][2];
        int iters = configs[i][3];
        
        printf("%s:\n", config_names[i]);
        
        perf_metrics_t metrics = benchmark_attention(seq_len, head_dim, num_heads, iters);
        
        if (metrics.elapsed_ms > 0) {
            perf_print_metrics("attention", &metrics);
            
            if (perf_check_regression("performance", &metrics, &baselines[i]) == 0) {
                tests_passed++;
            } else {
                tests_failed++;
            }
            
            char test_name[64];
            snprintf(test_name, sizeof(test_name), "attention_seq%d_heads%d", seq_len, num_heads);
            perf_save_result("perf_results.json", test_name, &metrics);
        } else {
            printf("  ✗ Benchmark failed\n");
            tests_failed++;
        }
        printf("\n");
    }
    
    /* Summary */
    printf("=============================================\n");
    printf("Performance Test Summary\n");
    printf("=============================================\n");
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_failed);
    printf("Total tests:  %d\n", tests_passed + tests_failed);
    
    if (tests_failed == 0) {
        printf("\n✓ ALL PERFORMANCE TESTS PASSED\n");
        return 0;
    } else {
        printf("\n✗ SOME PERFORMANCE TESTS FAILED\n");
        return 1;
    }
}
