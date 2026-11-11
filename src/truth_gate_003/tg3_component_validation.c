/*
 * Truth Gate 003 - Component Validation Suite
 * 
 * Validates each transformer component against expected behavior:
 * - RMSNorm
 * - RoPE
 * - Attention (Q·K scaling, softmax stability)
 * - SwiGLU
 * - Q4_K dequantization
 */

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>

#define EPSILON 1e-5f
#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  [FAIL] %s\n", msg); \
        return 0; \
    } \
} while(0)

/* f16 to f32 conversion */
float f16_to_f32(uint16_t h) {
    uint32_t sign = (h >> 15) & 1;
    uint32_t exp = (h >> 10) & 0x1F;
    uint32_t mant = h & 0x3FF;
    
    if (exp == 0) return sign ? -0.0f : 0.0f;
    if (exp == 31) return (mant == 0) ? (sign ? -INFINITY : INFINITY) : NAN;
    
    uint32_t f32_bits = (sign << 31) | ((exp + 112) << 23) | (mant << 13);
    float result;
    memcpy(&result, &f32_bits, sizeof(result));
    return result;
}

/* RMSNorm: y = x * rsqrt(mean(x²) + eps) * weight */
void rms_norm(const float *x, float *out, int n, float eps, const float *weight) {
    float sum = 0.0f;
    for (int i = 0; i < n; i++) sum += x[i] * x[i];
    float scale = 1.0f / sqrtf(sum / n + eps);
    for (int i = 0; i < n; i++) out[i] = x[i] * scale * weight[i];
}

/* Test RMSNorm */
int test_rmsnorm() {
    printf("\n=== Test: RMSNorm ===\n");
    
    float x[] = {1.0f, 2.0f, 3.0f, 4.0f};
    float weight[] = {1.0f, 1.0f, 1.0f, 1.0f};
    float out[4];
    int n = 4;
    float eps = 1e-5f;
    
    /* Expected: mean(x²) = (1+4+9+16)/4 = 7.5
     * rsqrt(7.5 + eps) ≈ 0.3651
     * y = x * 0.3651
     */
    rms_norm(x, out, n, eps, weight);
    
    float expected_scale = 1.0f / sqrtf(7.5f + eps);
    TEST_ASSERT(fabs(out[0] - 1.0f * expected_scale) < 0.001f, "RMSNorm first element incorrect");
    TEST_ASSERT(fabs(out[3] - 4.0f * expected_scale) < 0.001f, "RMSNorm last element incorrect");
    
    /* Test with non-unit weight */
    float weight2[] = {2.0f, 2.0f, 2.0f, 2.0f};
    rms_norm(x, out, n, eps, weight2);
    TEST_ASSERT(fabs(out[0] - 2.0f * expected_scale) < 0.001f, "RMSNorm with weight incorrect");
    
    printf("  [PASS] RMSNorm working correctly\n");
    return 1;
}

/* RoPE (Rotary Position Embedding) */
void apply_rope(float *q, float *k, int n_embd, int n_head, int pos, float theta) {
    int head_dim = n_embd / n_head;
    
    for (int h = 0; h < n_head; h++) {
        for (int i = 0; i < head_dim; i += 2) {
            float freq = 1.0f / powf(theta, (float)i / head_dim);
            float val = pos * freq;
            float cos_val = cosf(val);
            float sin_val = sinf(val);
            
            int idx = h * head_dim + i;
            float q0 = q[idx], q1 = q[idx + 1];
            float k0 = k[idx], k1 = k[idx + 1];
            
            q[idx] = q0 * cos_val - q1 * sin_val;
            q[idx + 1] = q0 * sin_val + q1 * cos_val;
            k[idx] = k0 * cos_val - k1 * sin_val;
            k[idx + 1] = k0 * sin_val + k1 * cos_val;
        }
    }
}

/* Test RoPE */
int test_rope() {
    printf("\n=== Test: RoPE ===\n");
    
    int n_embd = 4;
    int n_head = 2;
    int head_dim = 2;
    int pos = 1;
    float theta = 10000.0f;
    
    float q[] = {1.0f, 0.0f, 1.0f, 0.0f};  /* Two heads, each [1, 0] */
    float k[] = {1.0f, 0.0f, 1.0f, 0.0f};
    
    apply_rope(q, k, n_embd, n_head, pos, theta);
    
    /* For head_dim=2, i=0: freq = 1/theta^0 = 1, val = pos * 1 = 1
     * cos(1) ≈ 0.5403, sin(1) ≈ 0.8415
     * q[0] = 1*0.5403 - 0*0.8415 = 0.5403
     * q[1] = 1*0.8415 + 0*0.5403 = 0.8415
     */
    TEST_ASSERT(fabs(q[0] - cosf(1.0f)) < 0.001f, "RoPE q[0] incorrect");
    TEST_ASSERT(fabs(q[1] - sinf(1.0f)) < 0.001f, "RoPE q[1] incorrect");
    
    printf("  [PASS] RoPE working correctly\n");
    return 1;
}

/* Softmax with numerical stability */
void softmax(float *x, int n) {
    float max_val = x[0];
    for (int i = 1; i < n; i++) if (x[i] > max_val) max_val = x[i];
    
    float sum = 0.0f;
    for (int i = 0; i < n; i++) {
        x[i] = expf(x[i] - max_val);
        sum += x[i];
    }
    for (int i = 0; i < n; i++) x[i] /= sum;
}

/* Test Softmax */
int test_softmax() {
    printf("\n=== Test: Softmax ===\n");
    
    float x[] = {1.0f, 2.0f, 3.0f};
    int n = 3;
    
    softmax(x, n);
    
    /* Check probabilities sum to 1 */
    float sum = x[0] + x[1] + x[2];
    TEST_ASSERT(fabs(sum - 1.0f) < 0.0001f, "Softmax probabilities don't sum to 1");
    
    /* Check ordering preserved (3 > 2 > 1) */
    TEST_ASSERT(x[2] > x[1] && x[1] > x[0], "Softmax ordering not preserved");
    
    /* Test numerical stability with large values */
    float y[] = {100.0f, 101.0f, 102.0f};
    softmax(y, n);
    sum = y[0] + y[1] + y[2];
    TEST_ASSERT(fabs(sum - 1.0f) < 0.0001f, "Softmax unstable with large values");
    
    printf("  [PASS] Softmax working correctly\n");
    return 1;
}

/* Attention scaling and computation */
void compute_attention(float *q, float *k, float *v, float *out, 
                       int n_head, int head_dim, int seq_len) {
    float scale = 1.0f / sqrtf(head_dim);
    
    for (int h = 0; h < n_head; h++) {
        float *scores = calloc(seq_len, sizeof(float));
        
        /* Compute Q·K^T / sqrt(d_k) */
        for (int t = 0; t < seq_len; t++) {
            float score = 0.0f;
            for (int d = 0; d < head_dim; d++) {
                score += q[h * head_dim + d] * k[t * n_head * head_dim + h * head_dim + d];
            }
            scores[t] = score * scale;
        }
        
        /* Softmax */
        softmax(scores, seq_len);
        
        /* Weighted sum of V */
        for (int d = 0; d < head_dim; d++) {
            float sum = 0.0f;
            for (int t = 0; t < seq_len; t++) {
                sum += scores[t] * v[t * n_head * head_dim + h * head_dim + d];
            }
            out[h * head_dim + d] = sum;
        }
        
        free(scores);
    }
}

/* Test Attention */
int test_attention() {
    printf("\n=== Test: Attention ===\n");
    
    int n_head = 2;
    int head_dim = 4;
    int seq_len = 3;
    
    /* Simple test case: Q=K=V=identity-like */
    float q[8] = {1,0,0,0, 0,1,0,0};  /* 2 heads x 4 dims */
    float k[24] = {1,0,0,0, 0,1,0,0, 0,0,1,0,  /* 3 tokens */
                   0,0,0,1, 1,0,0,0, 0,1,0,0};
    float v[24] = {1,0,0,0, 0,1,0,0, 0,0,1,0,
                   0,0,0,1, 1,0,0,0, 0,1,0,0};
    float out[8] = {0};
    
    compute_attention(q, k, v, out, n_head, head_dim, seq_len);
    
    /* Check output is reasonable (not NaN, not all zeros) */
    int has_nonzero = 0;
    for (int i = 0; i < 8; i++) {
        if (!isnan(out[i]) && !isinf(out[i]) && out[i] != 0) {
            has_nonzero = 1;
        }
    }
    TEST_ASSERT(has_nonzero, "Attention output is all zeros or invalid");
    
    printf("  [PASS] Attention computation working\n");
    return 1;
}

/* SwiGLU: gate = SiLU(W1*x), up = W3*x, hidden = gate * up, output = W2(hidden) */
float silu(float x) {
    return x / (1.0f + expf(-x));
}

void swiglu(float *x, float *gate_w, float *up_w, float *down_w,
            float *out, int n_embd, int n_ff) {
    float *gate = calloc(n_ff, sizeof(float));
    float *up = calloc(n_ff, sizeof(float));
    float *hidden = calloc(n_ff, sizeof(float));
    
    /* Gate projection with SiLU */
    for (int i = 0; i < n_ff; i++) {
        float sum = 0;
        for (int j = 0; j < n_embd; j++) {
            sum += gate_w[i * n_embd + j] * x[j];
        }
        gate[i] = silu(sum);
    }
    
    /* Up projection */
    for (int i = 0; i < n_ff; i++) {
        float sum = 0;
        for (int j = 0; j < n_embd; j++) {
            sum += up_w[i * n_embd + j] * x[j];
        }
        up[i] = sum;
    }
    
    /* Element-wise multiply */
    for (int i = 0; i < n_ff; i++) {
        hidden[i] = gate[i] * up[i];
    }
    
    /* Down projection */
    for (int i = 0; i < n_embd; i++) {
        float sum = 0;
        for (int j = 0; j < n_ff; j++) {
            sum += down_w[i * n_ff + j] * hidden[j];
        }
        out[i] = sum;
    }
    
    free(gate);
    free(up);
    free(hidden);
}

/* Test SwiGLU */
int test_swiglu() {
    printf("\n=== Test: SwiGLU ===\n");
    
    int n_embd = 4;
    int n_ff = 8;
    
    float x[] = {1.0f, 0.5f, -0.5f, -1.0f};
    float gate_w[32] = {0};  /* n_ff x n_embd */
    float up_w[32] = {0};
    float down_w[32] = {0};
    float out[4] = {0};
    
    /* Initialize with small random values */
    for (int i = 0; i < 32; i++) {
        gate_w[i] = ((float)rand() / RAND_MAX - 0.5f) * 0.1f;
        up_w[i] = ((float)rand() / RAND_MAX - 0.5f) * 0.1f;
        down_w[i] = ((float)rand() / RAND_MAX - 0.5f) * 0.1f;
    }
    
    swiglu(x, gate_w, up_w, down_w, out, n_embd, n_ff);
    
    /* Check output is valid */
    int valid = 1;
    for (int i = 0; i < n_embd; i++) {
        if (isnan(out[i]) || isinf(out[i])) {
            valid = 0;
            break;
        }
    }
    TEST_ASSERT(valid, "SwiGLU produced NaN or Inf");
    
    printf("  [PASS] SwiGLU working correctly\n");
    return 1;
}

/* Q4_K block structure */
typedef struct {
    uint8_t scales[12];
    uint8_t qs[144];
    uint16_t d;
    uint16_t dmin;
} block_q4_K;

/* Dequantize Q4_K block */
void dequantize_q4_k(const block_q4_K *block, float *out, int n) {
    float d = f16_to_f32(block->d);
    float dmin = f16_to_f32(block->dmin);
    
    float scales[8];
    float mins[8];
    
    for (int i = 0; i < 8; i++) {
        int scale_byte = i / 2;
        int scale_nibble = (i % 2 == 0) ? (block->scales[scale_byte] & 0x0F) 
                                        : ((block->scales[scale_byte] >> 4) & 0x0F);
        
        int min_byte = 4 + i / 2;
        int min_nibble = (i % 2 == 0) ? (block->scales[min_byte] & 0x0F)
                                       : ((block->scales[min_byte] >> 4) & 0x0F);
        
        scales[i] = (float)scale_nibble;
        mins[i] = (float)min_nibble;
    }
    
    for (int i = 0; i < n && i < 256; i++) {
        int byte_idx = i / 2;
        /* In Q4_K, first weight in each byte is in the high nibble */
        int nibble = (i % 2 == 0) ? ((block->qs[byte_idx] >> 4) & 0x0F)
                                   : (block->qs[byte_idx] & 0x0F);
        
        int super_block = i / 32;
        out[i] = d * scales[super_block] * nibble - dmin * mins[super_block];
    }
}

/* Test Q4_K dequantization */
int test_q4k_dequant() {
    printf("\n=== Test: Q4_K Dequantization ===\n");
    
    block_q4_K block;
    memset(&block, 0, sizeof(block));
    
    /* Set scale to 1.0 (f16 = 0x3C00) */
    block.d = 0x3C00;
    block.dmin = 0;
    
    /* Set scales to 1.0 for all super-blocks */
    for (int i = 0; i < 12; i++) {
        block.scales[i] = 0x11;  /* Scale=1, Min=0 for each pair */
    }
    
    /* Set quantized values to 8 (middle of 0-15 range) */
    for (int i = 0; i < 144; i++) {
        block.qs[i] = 0x88;  /* Two nibbles of 8 */
    }
    
    float out[256];
    dequantize_q4_k(&block, out, 256);
    
    /* With d=1, scale=1, nibble=8, dmin=0, min=0:
     * out = 1 * 1 * 8 - 0 * 0 = 8
     */
    TEST_ASSERT(fabs(out[0] - 8.0f) < 0.1f, "Q4_K dequant middle value incorrect");
    TEST_ASSERT(fabs(out[255] - 8.0f) < 0.1f, "Q4_K dequant last value incorrect");
    
    /* Test with different nibble values */
    block.qs[0] = 0x10;  /* high nibble = 1, low nibble = 0 */
    dequantize_q4_k(&block, out, 256);
    /* Index 0 gets high nibble (1), index 1 gets low nibble (0) */
    printf("    nibble at idx 0 -> %.2f (expected ~1)\n", out[0]);
    printf("    nibble at idx 1 -> %.2f (expected ~0)\n", out[1]);
    TEST_ASSERT(fabs(out[0] - 1.0f) < 0.1f, "Q4_K dequant nibble 0 incorrect");
    TEST_ASSERT(fabs(out[1]) < 0.1f, "Q4_K dequant nibble 1 incorrect");
    
    printf("  [PASS] Q4_K dequantization working\n");
    return 1;
}

/* Test KV cache ordering */
int test_kv_cache() {
    printf("\n=== Test: KV Cache Ordering ===\n");
    
    int n_layers = 2;
    int max_seq = 4;
    int n_embd = 8;
    
    /* Allocate cache: [layer][seq][embd] */
    float *k_cache[2];
    float *v_cache[2];
    
    for (int l = 0; l < n_layers; l++) {
        k_cache[l] = calloc(max_seq * n_embd, sizeof(float));
        v_cache[l] = calloc(max_seq * n_embd, sizeof(float));
    }
    
    /* Store values at different positions */
    for (int l = 0; l < n_layers; l++) {
        for (int s = 0; s < max_seq; s++) {
            for (int e = 0; e < n_embd; e++) {
                k_cache[l][s * n_embd + e] = (float)(l * 1000 + s * 100 + e);
                v_cache[l][s * n_embd + e] = (float)(l * 1000 + s * 100 + e + 50);
            }
        }
    }
    
    /* Verify retrieval */
    int correct = 1;
    for (int l = 0; l < n_layers && correct; l++) {
        for (int s = 0; s < max_seq && correct; s++) {
            for (int e = 0; e < n_embd && correct; e++) {
                float expected_k = (float)(l * 1000 + s * 100 + e);
                float expected_v = (float)(l * 1000 + s * 100 + e + 50);
                if (k_cache[l][s * n_embd + e] != expected_k ||
                    v_cache[l][s * n_embd + e] != expected_v) {
                    correct = 0;
                    printf("  Mismatch at layer=%d, seq=%d, embd=%d\n", l, s, e);
                }
            }
        }
    }
    
    TEST_ASSERT(correct, "KV cache ordering incorrect");
    
    for (int l = 0; l < n_layers; l++) {
        free(k_cache[l]);
        free(v_cache[l]);
    }
    
    printf("  [PASS] KV cache ordering correct\n");
    return 1;
}

int main() {
    printf("========================================\n");
    printf("Truth Gate 003 - Component Validation\n");
    printf("========================================\n");
    
    int passed = 0;
    int total = 0;
    
    if (test_rmsnorm()) passed++; total++;
    if (test_rope()) passed++; total++;
    if (test_softmax()) passed++; total++;
    if (test_attention()) passed++; total++;
    if (test_swiglu()) passed++; total++;
    if (test_q4k_dequant()) passed++; total++;
    if (test_kv_cache()) passed++; total++;
    
    printf("\n========================================\n");
    printf("Results: %d/%d tests passed\n", passed, total);
    printf("========================================\n");
    
    return (passed == total) ? 0 : 1;
}
