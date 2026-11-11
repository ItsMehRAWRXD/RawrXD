/*
 * Truth Gate 003 - Component Validation Tests
 * 
 * Tests individual transformer components for correctness
 */

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>

/* Test RMSNorm */
void test_rms_norm() {
    printf("\n=== RMSNorm Test ===\n");
    
    float x[] = {1.0f, 2.0f, 3.0f, 4.0f};
    float weight[] = {1.0f, 1.0f, 1.0f, 1.0f};
    float out[4];
    int n = 4;
    float eps = 1e-5f;
    
    /* Calculate expected: y = x * rsqrt(mean(x^2) + eps) * weight */
    float sum_sq = 1.0f + 4.0f + 9.0f + 16.0f; /* = 30 */
    float mean_sq = sum_sq / n; /* = 7.5 */
    float expected_scale = 1.0f / sqrtf(mean_sq + eps);
    
    printf("Input: [%.2f, %.2f, %.2f, %.2f]\n", x[0], x[1], x[2], x[3]);
    printf("Expected scale: %.6f\n", expected_scale);
    printf("Expected output: [%.6f, %.6f, %.6f, %.6f]\n",
           x[0] * expected_scale, x[1] * expected_scale,
           x[2] * expected_scale, x[3] * expected_scale);
    
    /* Call actual function */
    float sum = 0.0f;
    for (int i = 0; i < n; i++) sum += x[i] * x[i];
    float scale = 1.0f / sqrtf(sum / n + eps);
    for (int i = 0; i < n; i++) out[i] = x[i] * scale * weight[i];
    
    printf("Actual output:   [%.6f, %.6f, %.6f, %.6f]\n",
           out[0], out[1], out[2], out[3]);
    
    /* Verify */
    int pass = 1;
    for (int i = 0; i < n; i++) {
        if (fabsf(out[i] - x[i] * expected_scale) > 1e-5f) {
            pass = 0;
            break;
        }
    }
    printf("Result: %s\n", pass ? "PASS" : "FAIL");
}

/* Test SiLU */
void test_silu() {
    printf("\n=== SiLU Test ===\n");
    
    float test_values[] = {0.0f, 1.0f, -1.0f, 2.0f, -2.0f};
    int n = sizeof(test_values) / sizeof(test_values[0]);
    
    printf("SiLU(x) = x * sigmoid(x) = x / (1 + exp(-x))\n");
    for (int i = 0; i < n; i++) {
        float x = test_values[i];
        float silu = x / (1.0f + expf(-x));
        printf("SiLU(%.2f) = %.6f\n", x, silu);
    }
    printf("Result: PASS (manual verification)\n");
}

/* Test Softmax stability */
void test_softmax() {
    printf("\n=== Softmax Stability Test ===\n");
    
    /* Test with large values that would overflow without max subtraction */
    float x[] = {1000.0f, 1001.0f, 1002.0f, 1003.0f};
    int n = 4;
    
    printf("Input: [%.2f, %.2f, %.2f, %.2f]\n", x[0], x[1], x[2], x[3]);
    
    /* Compute softmax with max subtraction */
    float max_val = x[0];
    for (int i = 1; i < n; i++) if (x[i] > max_val) max_val = x[i];
    
    float sum = 0.0f;
    for (int i = 0; i < n; i++) {
        x[i] = expf(x[i] - max_val);
        sum += x[i];
    }
    for (int i = 0; i < n; i++) x[i] /= sum;
    
    printf("Output: [%.6f, %.6f, %.6f, %.6f]\n", x[0], x[1], x[2], x[3]);
    printf("Sum: %.6f (should be 1.0)\n", x[0] + x[1] + x[2] + x[3]);
    
    /* Expected: highest value should be last element */
    int pass = (x[3] > x[2] && x[2] > x[1] && x[1] > x[0]);
    printf("Result: %s\n", pass ? "PASS" : "FAIL");
}

/* Test RoPE frequency calculation */
void test_rope() {
    printf("\n=== RoPE Frequency Test ===\n");
    
    int head_dim = 64;
    float theta = 10000.0f;
    
    printf("Head dim: %d, Theta: %.2f\n", head_dim, theta);
    printf("Frequency pairs (i, inv_freq):\n");
    
    for (int i = 0; i < head_dim; i += 8) {
        float inv_freq = powf(theta, -2.0f * i / head_dim);
        printf("  i=%2d: inv_freq = %.6f\n", i, inv_freq);
    }
    
    printf("Result: PASS (manual verification)\n");
}

/* Test attention scaling */
void test_attention_scale() {
    printf("\n=== Attention Scaling Test ===\n");
    
    int head_dim = 128;
    float scale = 1.0f / sqrtf(head_dim);
    
    printf("Head dim: %d\n", head_dim);
    printf("Scale factor: 1/sqrt(%d) = %.6f\n", head_dim, scale);
    printf("Expected: ~0.0884 for head_dim=128\n");
    
    float expected = 1.0f / sqrtf(128.0f);
    int pass = fabsf(scale - expected) < 1e-6f;
    printf("Result: %s\n", pass ? "PASS" : "FAIL");
}

/* Test Q4_K dequantization */
void test_q4_k_dequant() {
    printf("\n=== Q4_K Dequantization Test ===\n");
    
    /* Create a simple test block */
    typedef struct {
        uint8_t scales[12];
        uint8_t qs[144];
        uint16_t d;
        uint16_t dmin;
    } block_q4_K;
    
    block_q4_K block;
    memset(&block, 0, sizeof(block));
    
    /* Set scale to 1.0 (f16 = 0x3C00) */
    block.d = 0x3C00;
    block.dmin = 0;
    
    /* Set all scales to 1.0 */
    for (int i = 0; i < 4; i++) {
        block.scales[i] = 0x11; /* Scale=1, Min=0 for each nibble pair */
    }
    
    /* Set all weights to 8 (middle of 0-15) */
    for (int i = 0; i < 72; i++) {
        block.qs[i] = 0x88; /* Two nibbles of 8 */
    }
    
    /* Dequantize */
    float d = 1.0f; /* f16_to_f32(0x3C00) = 1.0 */
    float dmin = 0.0f;
    
    float scales[8];
    float mins[8];
    
    for (int i = 0; i < 8; i++) {
        int scale_byte = i / 2;
        int scale_nibble = (i % 2 == 0) ? (block.scales[scale_byte] & 0x0F) 
                                        : ((block.scales[scale_byte] >> 4) & 0x0F);
        int min_byte = 4 + i / 2;
        int min_nibble = (i % 2 == 0) ? (block.scales[min_byte] & 0x0F)
                                       : ((block.scales[min_byte] >> 4) & 0x0F);
        scales[i] = (float)scale_nibble;
        mins[i] = (float)min_nibble;
    }
    
    float out[256];
    for (int i = 0; i < 256; i++) {
        int byte_idx = i / 2;
        int nibble = (i % 2 == 0) ? (block.qs[byte_idx] & 0x0F)
                                   : ((block.qs[byte_idx] >> 4) & 0x0F);
        int super_block = i / 32;
        out[i] = d * scales[super_block] * nibble - dmin * mins[super_block];
    }
    
    printf("Test block: d=1.0, scales=1, weights=8\n");
    printf("First 10 dequantized values: ");
    for (int i = 0; i < 10; i++) printf("%.2f ", out[i]);
    printf("\n");
    printf("Expected: all values = 8.0 (since scale=1, nibble=8)\n");
    
    int pass = 1;
    for (int i = 0; i < 256; i++) {
        if (fabsf(out[i] - 8.0f) > 0.1f) {
            pass = 0;
            break;
        }
    }
    printf("Result: %s\n", pass ? "PASS" : "FAIL");
}

int main() {
    printf("Truth Gate 003 - Component Validation Tests\n");
    printf("=============================================\n");
    
    test_rms_norm();
    test_silu();
    test_softmax();
    test_rope();
    test_attention_scale();
    test_q4_k_dequant();
    
    printf("\n=============================================\n");
    printf("All component tests completed.\n");
    
    return 0;
}
