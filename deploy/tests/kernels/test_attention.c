/*
 * RawrXD Validation Framework
 * Kernel Test: Self-Attention
 */

#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#define TEST_NAME "Self-Attention"
#define SEQ_LEN 128
#define HEAD_DIM 64
#define NUM_HEADS 8

typedef float f32;

void softmax_1d(f32* x, int n) {
    f32 max_val = x[0];
    for (int i = 1; i < n; i++) {
        if (x[i] > max_val) max_val = x[i];
    }
    
    f32 sum = 0.0f;
    for (int i = 0; i < n; i++) {
        x[i] = expf(x[i] - max_val);
        sum += x[i];
    }
    
    for (int i = 0; i < n; i++) {
        x[i] /= sum;
    }
}

void attention_ref(const f32* Q, const f32* K, const f32* V, f32* out,
                   int seq_len, int head_dim) {
    /* Scaled dot-product attention */
    f32 scale = 1.0f / sqrtf((f32)head_dim);
    
    for (int i = 0; i < seq_len; i++) {
        /* Compute attention scores for query i */
        f32 scores[SEQ_LEN];
        for (int j = 0; j < seq_len; j++) {
            /* Q[i] dot K[j] */
            f32 dot = 0.0f;
            for (int d = 0; d < head_dim; d++) {
                dot += Q[i * head_dim + d] * K[j * head_dim + d];
            }
            scores[j] = dot * scale;
        }
        
        /* Apply softmax */
        softmax_1d(scores, seq_len);
        
        /* Weighted sum of values */
        for (int d = 0; d < head_dim; d++) {
            f32 sum = 0.0f;
            for (int j = 0; j < seq_len; j++) {
                sum += scores[j] * V[j * head_dim + d];
            }
            out[i * head_dim + d] = sum;
        }
    }
}

void attention_opt(const f32* Q, const f32* K, const f32* V, f32* out,
                   int seq_len, int head_dim) {
    /* Optimized attention */
    /* TODO: Implement AVX-512 version */
    attention_ref(Q, K, V, out, seq_len, head_dim);
}

f32 compute_max_error(const f32* ref, const f32* opt, int n) {
    f32 max_err = 0.0f;
    for (int i = 0; i < n; i++) {
        f32 err = fabsf(ref[i] - opt[i]);
        if (err > max_err) max_err = err;
    }
    return max_err;
}

int main(void) {
    printf("[%s] Starting...\n", TEST_NAME);
    
    int size = SEQ_LEN * HEAD_DIM;
    f32* Q = malloc(size * sizeof(f32));
    f32* K = malloc(size * sizeof(f32));
    f32* V = malloc(size * sizeof(f32));
    f32* ref_out = malloc(size * sizeof(f32));
    f32* opt_out = malloc(size * sizeof(f32));
    
    if (!Q || !K || !V || !ref_out || !opt_out) {
        printf("[%s] FAIL: Memory allocation failed\n", TEST_NAME);
        return 1;
    }
    
    /* Initialize with test values */
    for (int i = 0; i < size; i++) {
        Q[i] = (f32)(i % 10) / 10.0f;
        K[i] = (f32)((i + 5) % 10) / 10.0f;
        V[i] = (f32)((i + 3) % 10) / 10.0f;
    }
    
    attention_ref(Q, K, V, ref_out, SEQ_LEN, HEAD_DIM);
    attention_opt(Q, K, V, opt_out, SEQ_LEN, HEAD_DIM);
    
    f32 max_error = compute_max_error(ref_out, opt_out, size);
    
    printf("[%s] Max error: %e\n", TEST_NAME, max_error);
    
    free(Q);
    free(K);
    free(V);
    free(ref_out);
    free(opt_out);
    
    if (max_error < 1e-5f) {
        printf("[%s] PASS\n", TEST_NAME);
        return 0;
    } else {
        printf("[%s] FAIL\n", TEST_NAME);
        return 1;
    }
}
