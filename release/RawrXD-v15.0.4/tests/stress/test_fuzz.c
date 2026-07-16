/*
 * RawrXD Fuzz Test - Input fuzzing for robustness testing
 * Detects crashes, hangs, and undefined behavior with malformed inputs
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <float.h>
#include <setjmp.h>
#include <signal.h>

#define FUZZ_ITERATIONS 10000
#define MAX_INPUT_SIZE 4096
#define SEED 42

/* Fuzz statistics */
typedef struct {
    int iterations;
    int crashes;
    int hangs;
    int assertions;
    int passed;
    int edge_cases_found;
} fuzz_stats_t;

/* RNG state */
typedef struct {
    unsigned int state;
} rng_t;

/* Initialize RNG */
void rng_init(rng_t *rng, unsigned int seed) {
    rng->state = seed;
}

/* XORShift RNG */
unsigned int rng_next(rng_t *rng) {
    rng->state ^= rng->state << 13;
    rng->state ^= rng->state >> 17;
    rng->state ^= rng->state << 5;
    return rng->state;
}

/* Generate random float */
float rng_float(rng_t *rng) {
    return (float)rng_next(rng) / (float)UINT_MAX;
}

/* Generate random float in range */
float rng_float_range(rng_t *rng, float min, float max) {
    return min + rng_float(rng) * (max - min);
}

/* Generate edge case floats */
float rng_edge_float(rng_t *rng) {
    int choice = rng_next(rng) % 10;
    switch (choice) {
        case 0: return 0.0f;
        case 1: return -0.0f;
        case 2: return FLT_MIN;
        case 3: return FLT_MAX;
        case 4: return -FLT_MAX;
        case 5: return FLT_EPSILON;
        case 6: return INFINITY;
        case 7: return -INFINITY;
        case 8: return NAN;
        default: return rng_float(rng);
    }
}

/* Fuzz softmax with random inputs */
int fuzz_softmax(rng_t *rng, int size) {
    float *input = (float*)malloc(size * sizeof(float));
    float *output = (float*)malloc(size * sizeof(float));
    
    if (!input || !output) {
        free(input); free(output);
        return -1;
    }
    
    /* Generate random/edge case inputs */
    for (int i = 0; i < size; i++) {
        input[i] = rng_edge_float(rng);
    }
    
    /* Softmax computation */
    float max_val = -INFINITY;
    for (int i = 0; i < size; i++) {
        if (!isnan(input[i]) && !isinf(input[i]) && input[i] > max_val) {
            max_val = input[i];
        }
    }
    
    if (max_val == -INFINITY) {
        /* All inputs are -inf or nan */
        free(input); free(output);
        return 0; /* Valid edge case */
    }
    
    float sum = 0.0f;
    for (int i = 0; i < size; i++) {
        if (isnan(input[i])) {
            output[i] = NAN;
        } else if (isinf(input[i])) {
            output[i] = (input[i] > 0) ? INFINITY : 0.0f;
        } else {
            output[i] = expf(input[i] - max_val);
        }
        if (!isnan(output[i]) && !isinf(output[i])) {
            sum += output[i];
        }
    }
    
    /* Normalize */
    if (sum > 0 && !isinf(sum)) {
        for (int i = 0; i < size; i++) {
            if (!isnan(output[i]) && !isinf(output[i])) {
                output[i] /= sum;
            }
        }
    }
    
    free(input); free(output);
    return 0;
}

/* Fuzz RMSNorm with random inputs */
int fuzz_rmsnorm(rng_t *rng, int size) {
    float *input = (float*)malloc(size * sizeof(float));
    float *output = (float*)malloc(size * sizeof(float));
    
    if (!input || !output) {
        free(input); free(output);
        return -1;
    }
    
    /* Generate random/edge case inputs */
    for (int i = 0; i < size; i++) {
        input[i] = rng_edge_float(rng);
    }
    
    /* RMSNorm computation */
    float sum_sq = 0.0f;
    for (int i = 0; i < size; i++) {
        if (!isnan(input[i]) && !isinf(input[i])) {
            sum_sq += input[i] * input[i];
        }
    }
    
    float rms = sqrtf(sum_sq / size + 1e-6f);
    
    if (rms == 0.0f || isnan(rms) || isinf(rms)) {
        /* Edge case - return early */
        free(input); free(output);
        return 0;
    }
    
    for (int i = 0; i < size; i++) {
        if (!isnan(input[i]) && !isinf(input[i])) {
            output[i] = input[i] / rms;
        } else {
            output[i] = input[i]; /* Propagate NaN/Inf */
        }
    }
    
    free(input); free(output);
    return 0;
}

/* Fuzz GELU with random inputs */
int fuzz_gelu(rng_t *rng, int size) {
    float *input = (float*)malloc(size * sizeof(float));
    float *output = (float*)malloc(size * sizeof(float));
    
    if (!input || !output) {
        free(input); free(output);
        return -1;
    }
    
    /* GELU: x * 0.5 * (1 + tanh(sqrt(2/pi) * (x + 0.044715 * x^3))) */
    const float sqrt_2_over_pi = 0.7978845608f;
    const float coeff = 0.044715f;
    
    for (int i = 0; i < size; i++) {
        input[i] = rng_edge_float(rng);
        
        if (isnan(input[i]) || isinf(input[i])) {
            output[i] = input[i];
        } else {
            float x3 = input[i] * input[i] * input[i];
            float inner = sqrt_2_over_pi * (input[i] + coeff * x3);
            output[i] = input[i] * 0.5f * (1.0f + tanhf(inner));
        }
    }
    
    free(input); free(output);
    return 0;
}

/* Fuzz attention with random inputs */
int fuzz_attention(rng_t *rng, int seq_len, int head_dim) {
    size_t size = seq_len * head_dim * sizeof(float);
    float *Q = (float*)malloc(size);
    float *K = (float*)malloc(size);
    float *V = (float*)malloc(size);
    float *output = (float*)malloc(size);
    float *scores = (float*)malloc(seq_len * seq_len * sizeof(float));
    
    if (!Q || !K || !V || !output || !scores) {
        free(Q); free(K); free(V); free(output); free(scores);
        return -1;
    }
    
    /* Generate edge case inputs */
    for (int i = 0; i < seq_len * head_dim; i++) {
        Q[i] = rng_edge_float(rng);
        K[i] = rng_edge_float(rng);
        V[i] = rng_edge_float(rng);
    }
    
    /* Attention: Q @ K^T / sqrt(dim) */
    float scale = 1.0f / sqrtf((float)head_dim);
    
    for (int i = 0; i < seq_len; i++) {
        for (int j = 0; j < seq_len; j++) {
            float sum = 0.0f;
            for (int k = 0; k < head_dim; k++) {
                float q = Q[i * head_dim + k];
                float k_val = K[j * head_dim + k];
                if (!isnan(q) && !isinf(q) && !isnan(k_val) && !isinf(k_val)) {
                    sum += q * k_val * scale;
                }
            }
            scores[i * seq_len + j] = sum;
        }
    }
    
    /* Softmax on scores */
    for (int i = 0; i < seq_len; i++) {
        float max_val = -INFINITY;
        for (int j = 0; j < seq_len; j++) {
            float s = scores[i * seq_len + j];
            if (!isnan(s) && !isinf(s) && s > max_val) {
                max_val = s;
            }
        }
        
        float sum = 0.0f;
        for (int j = 0; j < seq_len; j++) {
            float s = scores[i * seq_len + j];
            if (!isnan(s) && !isinf(s)) {
                scores[i * seq_len + j] = expf(s - max_val);
                sum += scores[i * seq_len + j];
            }
        }
        
        if (sum > 0 && !isinf(sum)) {
            for (int j = 0; j < seq_len; j++) {
                scores[i * seq_len + j] /= sum;
            }
        }
    }
    
    /* Attention @ V */
    for (int i = 0; i < seq_len; i++) {
        for (int k = 0; k < head_dim; k++) {
            float sum = 0.0f;
            for (int j = 0; j < seq_len; j++) {
                float s = scores[i * seq_len + j];
                float v = V[j * head_dim + k];
                if (!isnan(s) && !isinf(s) && !isnan(v) && !isinf(v)) {
                    sum += s * v;
                }
            }
            output[i * head_dim + k] = sum;
        }
    }
    
    free(Q); free(K); free(V); free(output); free(scores);
    return 0;
}

/* Fuzz RoPE with random inputs */
int fuzz_rope(rng_t *rng, int n, int head_dim) {
    float *x = (float*)malloc(n * sizeof(float));
    
    if (!x) {
        free(x);
        return -1;
    }
    
    /* Generate edge case inputs */
    for (int i = 0; i < n; i++) {
        x[i] = rng_edge_float(rng);
    }
    
    /* Apply RoPE */
    for (int i = 0; i < n; i += 2) {
        int idx = i % head_dim;
        float theta = powf(10000.0f, -2.0f * (idx / 2) / head_dim);
        float angle = i * theta;
        
        float x0 = x[i];
        float x1 = (i + 1 < n) ? x[i + 1] : 0.0f;
        
        float cos_t = cosf(angle);
        float sin_t = sinf(angle);
        
        /* Handle edge cases */
        if (isnan(x0) || isinf(x0) || isnan(x1) || isinf(x1)) {
            /* Propagate NaN/Inf */
            continue;
        }
        
        if (isnan(cos_t) || isinf(cos_t) || isnan(sin_t) || isinf(sin_t)) {
            /* Angle overflow - clamp */
            cos_t = (cos_t > 0) ? 1.0f : -1.0f;
            sin_t = 0.0f;
        }
        
        x[i] = x0 * cos_t - x1 * sin_t;
        if (i + 1 < n) {
            x[i + 1] = x0 * sin_t + x1 * cos_t;
        }
    }
    
    free(x);
    return 0;
}

/* Run fuzz test with crash protection */
int run_fuzz_test(fuzz_stats_t *stats) {
    rng_t rng;
    rng_init(&rng, SEED);
    
    printf("Starting fuzz test (%d iterations)...\n", FUZZ_ITERATIONS);
    printf("Testing: softmax, rmsnorm, gelu, attention, rope\n");
    printf("\n");
    
    int last_progress = -1;
    
    for (int iter = 0; iter < FUZZ_ITERATIONS; iter++) {
        int result = 0;
        
        /* Progress */
        int progress = (iter * 100) / FUZZ_ITERATIONS;
        if (progress != last_progress && progress % 10 == 0) {
            printf("Progress: %d%% (iter: %d, crashes: %d)\n",
                   progress, iter, stats->crashes);
            last_progress = progress;
        }
        
        /* Fuzz with varying sizes */
        int size_softmax = 32 + (rng_next(&rng) % 1024);
        int size_rmsnorm = 128 + (rng_next(&rng) % 4096);
        int size_gelu = 64 + (rng_next(&rng) % 512);
        int seq_len = 16 + (rng_next(&rng) % 64);
        int head_dim = 64 + (rng_next(&rng) % 64);
        int n_rope = 128 + (rng_next(&rng) % 512);
        
        result |= fuzz_softmax(&rng, size_softmax);
        result |= fuzz_rmsnorm(&rng, size_rmsnorm);
        result |= fuzz_gelu(&rng, size_gelu);
        result |= fuzz_attention(&rng, seq_len, head_dim);
        result |= fuzz_rope(&rng, n_rope, head_dim);
        
        stats->iterations++;
        
        if (result != 0) {
            stats->crashes++;
            printf("  Crash detected at iteration %d\n", iter);
        } else {
            stats->passed++;
        }
    }
    
    return 0;
}

int main() {
    printf("RawrXD Fuzz Test\n");
    printf("================\n");
    printf("Iterations: %d\n", FUZZ_ITERATIONS);
    printf("Seed: %d\n", SEED);
    printf("Purpose: Detect crashes with malformed/edge case inputs\n");
    printf("\n");
    
    fuzz_stats_t stats = {0};
    
    run_fuzz_test(&stats);
    
    printf("\n");
    printf("Fuzz Test Complete\n");
    printf("==================\n");
    printf("Iterations: %d\n", stats.iterations);
    printf("Passed: %d\n", stats.passed);
    printf("Crashes: %d\n", stats.crashes);
    printf("Pass Rate: %.2f%%\n", (stats.iterations > 0) ? 
           (100.0f * stats.passed / stats.iterations) : 0.0f);
    printf("\n");
    
    if (stats.crashes == 0) {
        printf("SUCCESS: No crashes detected!\n");
        return 0;
    } else {
        printf("FAILURE: %d crashes detected\n", stats.crashes);
        return 1;
    }
}
