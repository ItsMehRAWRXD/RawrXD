/*
 * Truth Gate 003 - Phase 2: Transformer Block Implementation
 * 
 * Implements a complete transformer layer:
 * - RMSNorm
 * - QKV projection
 * - RoPE (Rotary Position Embedding)
 * - Attention (softmax(QK^T/sqrt(d_k)) * V)
 * - KV Cache
 * - SwiGLU FFN
 * - Residual connections
 */

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <math.h>
#include <string.h>

/* Configuration for ministral3 model */
#define HIDDEN_DIM 1024
#define FFN_DIM 4096
#define NUM_HEADS 32
#define HEAD_DIM (HIDDEN_DIM / NUM_HEADS)
#define MAX_SEQ_LEN 4096

/* KV Cache structure */
typedef struct {
    float *k_cache;  /* [MAX_SEQ_LEN, NUM_HEADS, HEAD_DIM] */
    float *v_cache;  /* [MAX_SEQ_LEN, NUM_HEADS, HEAD_DIM] */
    int cache_pos;   /* Current position in cache */
} kv_cache_t;

/* ============== MATH UTILITIES ============== */

/* RMSNorm: x * rsqrt(mean(x^2) + epsilon) */
void rmsnorm(float *x, int n, float eps, float *weight, float *out) {
    /* Calculate mean of squares */
    float sum_sq = 0.0f;
    for (int i = 0; i < n; i++) {
        sum_sq += x[i] * x[i];
    }
    float rms = sqrtf(sum_sq / n + eps);
    float scale = 1.0f / rms;
    
    /* Apply normalization and weight */
    for (int i = 0; i < n; i++) {
        out[i] = x[i] * scale * weight[i];
    }
}

/* Softmax with numerical stability */
void softmax(float *x, int n) {
    /* Find max for stability */
    float max_val = x[0];
    for (int i = 1; i < n; i++) {
        if (x[i] > max_val) max_val = x[i];
    }
    
    /* Compute exp(x - max) and sum */
    float sum = 0.0f;
    for (int i = 0; i < n; i++) {
        x[i] = expf(x[i] - max_val);
        sum += x[i];
    }
    
    /* Normalize */
    for (int i = 0; i < n; i++) {
        x[i] /= sum;
    }
}

/* Matrix multiplication: C = A * B
 * A: [m, k], B: [k, n], C: [m, n]
 */
void matmul(const float *A, const float *B, float *C, int m, int k, int n) {
    for (int i = 0; i < m; i++) {
        for (int j = 0; j < n; j++) {
            float sum = 0.0f;
            for (int l = 0; l < k; l++) {
                sum += A[i * k + l] * B[l * n + j];
            }
            C[i * n + j] = sum;
        }
    }
}

/* ============== ROPE (Rotary Position Embedding) ============== */

/* Apply RoPE to Q and K matrices
 * x: [num_heads, head_dim] - input matrix
 * pos: position in sequence
 * head_dim: dimension per head
 */
void apply_rope(float *x, int num_heads, int head_dim, int pos) {
    /* RoPE base frequency */
    const float theta_base = 10000.0f;
    
    for (int h = 0; h < num_heads; h++) {
        for (int i = 0; i < head_dim / 2; i++) {
            /* Rotation angle */
            float theta = pos * powf(theta_base, -2.0f * i / head_dim);
            float cos_theta = cosf(theta);
            float sin_theta = sinf(theta);
            
            /* Get pair of values */
            float x0 = x[h * head_dim + 2 * i];
            float x1 = x[h * head_dim + 2 * i + 1];
            
            /* Apply rotation */
            x[h * head_dim + 2 * i] = x0 * cos_theta - x1 * sin_theta;
            x[h * head_dim + 2 * i + 1] = x0 * sin_theta + x1 * cos_theta;
        }
    }
}

/* ============== ATTENTION ============== */

/* Multi-head attention with KV cache
 * q: [num_heads, head_dim] - query matrix
 * k_cache: [cache_pos + 1, num_heads, head_dim] - cached keys
 * v_cache: [cache_pos + 1, num_heads, head_dim] - cached values
 * output: [num_heads, head_dim] - attention output
 */
void attention(const float *q, const kv_cache_t *kv_cache, 
               float *output, int num_heads, int head_dim) {
    int seq_len = kv_cache->cache_pos + 1;
    
    /* For each head */
    for (int h = 0; h < num_heads; h++) {
        /* Compute attention scores: Q * K^T / sqrt(d_k) */
        float scores[MAX_SEQ_LEN];
        float scale = 1.0f / sqrtf((float)head_dim);
        
        for (int pos = 0; pos < seq_len; pos++) {
            /* Dot product of Q with K at position pos */
            float dot = 0.0f;
            for (int d = 0; d < head_dim; d++) {
                float k_val = kv_cache->k_cache[pos * num_heads * head_dim + h * head_dim + d];
                dot += q[h * head_dim + d] * k_val;
            }
            scores[pos] = dot * scale;
        }
        
        /* Apply softmax to get attention weights */
        softmax(scores, seq_len);
        
        /* Compute weighted sum of values */
        for (int d = 0; d < head_dim; d++) {
            float sum = 0.0f;
            for (int pos = 0; pos < seq_len; pos++) {
                float v_val = kv_cache->v_cache[pos * num_heads * head_dim + h * head_dim + d];
                sum += scores[pos] * v_val;
            }
            output[h * head_dim + d] = sum;
        }
    }
}

/* ============== SWIGLU FFN ============== */

/* SwiGLU activation: gate * sigmoid(gate) * up
 * gate: [ffn_dim], up: [ffn_dim], output: [ffn_dim]
 */
void swiglu(const float *gate, const float *up, float *out, int n) {
    for (int i = 0; i < n; i++) {
        /* SiLU (Swish) activation: x * sigmoid(x) */
        float sigmoid = 1.0f / (1.0f + expf(-gate[i]));
        float silu = gate[i] * sigmoid;
        out[i] = silu * up[i];
    }
}

/* ============== TRANSFORMER BLOCK ============== */

/* Single transformer block
 * Input: x [hidden_dim]
 * Output: x [hidden_dim] (modified in place with residual)
 */
typedef struct {
    /* Attention weights */
    float *attn_norm;      /* [hidden_dim] */
    float *attn_q;         /* [hidden_dim, hidden_dim] */
    float *attn_k;         /* [hidden_dim, hidden_dim] */
    float *attn_v;         /* [hidden_dim, hidden_dim] */
    float *attn_output;    /* [hidden_dim, hidden_dim] */
    
    /* FFN weights */
    float *ffn_norm;       /* [hidden_dim] */
    float *ffn_gate;       /* [hidden_dim, ffn_dim] */
    float *ffn_up;         /* [hidden_dim, ffn_dim] */
    float *ffn_down;       /* [ffn_dim, hidden_dim] */
} transformer_weights_t;

void transformer_block(float *x, const transformer_weights_t *w, 
                       kv_cache_t *kv_cache, int pos) {
    float temp[HIDDEN_DIM];
    float q[NUM_HEADS * HEAD_DIM];
    float k[NUM_HEADS * HEAD_DIM];
    float v[NUM_HEADS * HEAD_DIM];
    float attn_out[NUM_HEADS * HEAD_DIM];
    float ffn_gate[FFN_DIM];
    float ffn_up[FFN_DIM];
    float ffn_out[FFN_DIM];
    
    /* ===== SELF-ATTENTION ===== */
    
    /* RMSNorm */
    rmsnorm(x, HIDDEN_DIM, 1e-5f, w->attn_norm, temp);
    
    /* QKV projections */
    matmul(temp, w->attn_q, q, 1, HIDDEN_DIM, HIDDEN_DIM);
    matmul(temp, w->attn_k, k, 1, HIDDEN_DIM, HIDDEN_DIM);
    matmul(temp, w->attn_v, v, 1, HIDDEN_DIM, HIDDEN_DIM);
    
    /* Reshape to [num_heads, head_dim] */
    /* (already in flat format) */
    
    /* Apply RoPE to Q and K */
    apply_rope(q, NUM_HEADS, HEAD_DIM, pos);
    apply_rope(k, NUM_HEADS, HEAD_DIM, pos);
    
    /* Store K and V in cache */
    for (int i = 0; i < NUM_HEADS * HEAD_DIM; i++) {
        kv_cache->k_cache[(kv_cache->cache_pos + 1) * NUM_HEADS * HEAD_DIM + i] = k[i];
        kv_cache->v_cache[(kv_cache->cache_pos + 1) * NUM_HEADS * HEAD_DIM + i] = v[i];
    }
    kv_cache->cache_pos++;
    
    /* Attention */
    attention(q, kv_cache, attn_out, NUM_HEADS, HEAD_DIM);
    
    /* Output projection */
    matmul(attn_out, w->attn_output, temp, 1, HIDDEN_DIM, HIDDEN_DIM);
    
    /* Residual connection */
    for (int i = 0; i < HIDDEN_DIM; i++) {
        x[i] += temp[i];
    }
    
    /* ===== FFN ===== */
    
    /* RMSNorm */
    rmsnorm(x, HIDDEN_DIM, 1e-5f, w->ffn_norm, temp);
    
    /* FFN projections */
    matmul(temp, w->ffn_gate, ffn_gate, 1, HIDDEN_DIM, FFN_DIM);
    matmul(temp, w->ffn_up, ffn_up, 1, HIDDEN_DIM, FFN_DIM);
    
    /* SwiGLU */
    swiglu(ffn_gate, ffn_up, ffn_out, FFN_DIM);
    
    /* Down projection */
    matmul(ffn_out, w->ffn_down, temp, 1, FFN_DIM, HIDDEN_DIM);
    
    /* Residual connection */
    for (int i = 0; i < HIDDEN_DIM; i++) {
        x[i] += temp[i];
    }
}

/* ============== TESTING ============== */

void test_transformer_block() {
    printf("Truth Gate 003 - Phase 2: Transformer Block\n");
    printf("===========================================\n\n");
    
    /* Initialize weights with small random values */
    transformer_weights_t w;
    
    w.attn_norm = calloc(HIDDEN_DIM, sizeof(float));
    w.attn_q = calloc(HIDDEN_DIM * HIDDEN_DIM, sizeof(float));
    w.attn_k = calloc(HIDDEN_DIM * HIDDEN_DIM, sizeof(float));
    w.attn_v = calloc(HIDDEN_DIM * HIDDEN_DIM, sizeof(float));
    w.attn_output = calloc(HIDDEN_DIM * HIDDEN_DIM, sizeof(float));
    w.ffn_norm = calloc(HIDDEN_DIM, sizeof(float));
    w.ffn_gate = calloc(HIDDEN_DIM * FFN_DIM, sizeof(float));
    w.ffn_up = calloc(HIDDEN_DIM * FFN_DIM, sizeof(float));
    w.ffn_down = calloc(FFN_DIM * HIDDEN_DIM, sizeof(float));
    
    /* Initialize norm weights to 1.0 */
    for (int i = 0; i < HIDDEN_DIM; i++) {
        w.attn_norm[i] = 1.0f;
        w.ffn_norm[i] = 1.0f;
    }
    
    /* Initialize projection weights with small values */
    for (int i = 0; i < HIDDEN_DIM * HIDDEN_DIM; i++) {
        w.attn_q[i] = ((float)(i % 7) - 3.0f) / 1000.0f;
        w.attn_k[i] = ((float)(i % 7) - 3.0f) / 1000.0f;
        w.attn_v[i] = ((float)(i % 7) - 3.0f) / 1000.0f;
        w.attn_output[i] = ((float)(i % 7) - 3.0f) / 1000.0f;
    }
    
    for (int i = 0; i < HIDDEN_DIM * FFN_DIM; i++) {
        w.ffn_gate[i] = ((float)(i % 7) - 3.0f) / 1000.0f;
        w.ffn_up[i] = ((float)(i % 7) - 3.0f) / 1000.0f;
    }
    
    for (int i = 0; i < FFN_DIM * HIDDEN_DIM; i++) {
        w.ffn_down[i] = ((float)(i % 7) - 3.0f) / 1000.0f;
    }
    
    /* Initialize KV cache */
    kv_cache_t kv_cache;
    kv_cache.k_cache = calloc(MAX_SEQ_LEN * NUM_HEADS * HEAD_DIM, sizeof(float));
    kv_cache.v_cache = calloc(MAX_SEQ_LEN * NUM_HEADS * HEAD_DIM, sizeof(float));
    kv_cache.cache_pos = -1;  /* Will become 0 after first token */
    
    /* Test input */
    float x[HIDDEN_DIM];
    for (int i = 0; i < HIDDEN_DIM; i++) {
        x[i] = ((float)(i % 5) - 2.0f) / 10.0f;  /* Small values */
    }
    
    printf("Test: Single transformer block execution\n");
    printf("  Hidden dim: %d\n", HIDDEN_DIM);
    printf("  FFN dim: %d\n", FFN_DIM);
    printf("  Num heads: %d\n", NUM_HEADS);
    printf("  Head dim: %d\n", HEAD_DIM);
    printf("\n");
    
    /* Run transformer block */
    printf("Executing transformer block at position 0...\n");
    transformer_block(x, &w, &kv_cache, 0);
    
    /* Check output */
    float min_val = x[0], max_val = x[0], mean = 0.0f;
    int nan_count = 0, inf_count = 0;
    
    for (int i = 0; i < HIDDEN_DIM; i++) {
        if (isnan(x[i])) nan_count++;
        if (isinf(x[i])) inf_count++;
        if (x[i] < min_val) min_val = x[i];
        if (x[i] > max_val) max_val = x[i];
        mean += x[i];
    }
    mean /= HIDDEN_DIM;
    
    printf("\nOutput statistics:\n");
    printf("  NaN count: %d\n", nan_count);
    printf("  Inf count: %d\n", inf_count);
    printf("  Min: %.6f\n", min_val);
    printf("  Max: %.6f\n", max_val);
    printf("  Mean: %.6f\n", mean);
    printf("  KV cache position: %d\n", kv_cache.cache_pos);
    
    /* Validation */
    printf("\nValidation:\n");
    int pass = 1;
    
    if (nan_count > 0) {
        printf("  [FAIL] NaN values detected\n");
        pass = 0;
    } else {
        printf("  [PASS] No NaN values\n");
    }
    
    if (inf_count > 0) {
        printf("  [FAIL] Inf values detected\n");
        pass = 0;
    } else {
        printf("  [PASS] No Inf values\n");
    }
    
    if (kv_cache.cache_pos == 0) {
        printf("  [PASS] KV cache updated correctly\n");
    } else {
        printf("  [FAIL] KV cache position incorrect: %d\n", kv_cache.cache_pos);
        pass = 0;
    }
    
    printf("\n===========================================\n");
    printf("Phase 2: Transformer block %s\n", pass ? "PASSED" : "FAILED");
    printf("\nNext: Multi-layer execution with real weights\n");
    
    /* Cleanup */
    free(w.attn_norm);
    free(w.attn_q);
    free(w.attn_k);
    free(w.attn_v);
    free(w.attn_output);
    free(w.ffn_norm);
    free(w.ffn_gate);
    free(w.ffn_up);
    free(w.ffn_down);
    free(kv_cache.k_cache);
    free(kv_cache.v_cache);
}

int main() {
    test_transformer_block();
    return 0;
}
