/* tg002_transformer_ops.c - Phase 3: Transformer Operations
 * Core mathematical operations for transformer inference
 * Compile: gcc -O2 -Wall tg002_transformer_ops.c -o tg002_transformer_ops.exe -lm
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <stdbool.h>

/* ============================================================================
 * RMSNorm (Root Mean Square Normalization)
 * Used in Llama, Mistral, and other modern LLMs
 * Formula: output = x / sqrt(mean(x^2) + epsilon) * weight
 * ============================================================================ */
void rmsnorm(const float* input, const float* weight, float* output, 
             int n_elements, float epsilon) {
    /* Calculate RMS */
    float sum_sq = 0.0f;
    for (int i = 0; i < n_elements; i++) {
        sum_sq += input[i] * input[i];
    }
    float rms = sqrtf(sum_sq / n_elements + epsilon);
    
    /* Normalize and scale */
    for (int i = 0; i < n_elements; i++) {
        output[i] = input[i] / rms * weight[i];
    }
}

/* ============================================================================
 * Layer Normalization (traditional)
 * Formula: output = (x - mean) / sqrt(var + epsilon) * weight + bias
 * ============================================================================ */
void layernorm(const float* input, const float* weight, const float* bias,
               float* output, int n_elements, float epsilon) {
    /* Calculate mean */
    float mean = 0.0f;
    for (int i = 0; i < n_elements; i++) {
        mean += input[i];
    }
    mean /= n_elements;
    
    /* Calculate variance */
    float var = 0.0f;
    for (int i = 0; i < n_elements; i++) {
        float diff = input[i] - mean;
        var += diff * diff;
    }
    var /= n_elements;
    
    /* Normalize and scale */
    float inv_std = 1.0f / sqrtf(var + epsilon);
    for (int i = 0; i < n_elements; i++) {
        output[i] = (input[i] - mean) * inv_std * weight[i] + bias[i];
    }
}

/* ============================================================================
 * Softmax
 * Formula: softmax(x_i) = exp(x_i) / sum(exp(x_j))
 * Numerically stable version
 * ============================================================================ */
void softmax(const float* input, float* output, int n_elements) {
    /* Find max for numerical stability */
    float max_val = input[0];
    for (int i = 1; i < n_elements; i++) {
        if (input[i] > max_val) max_val = input[i];
    }
    
    /* Compute exp(x - max) and sum */
    float sum = 0.0f;
    for (int i = 0; i < n_elements; i++) {
        output[i] = expf(input[i] - max_val);
        sum += output[i];
    }
    
    /* Normalize */
    float inv_sum = 1.0f / sum;
    for (int i = 0; i < n_elements; i++) {
        output[i] *= inv_sum;
    }
}

/* ============================================================================
 * Matrix Multiplication: C = A * B
 * A: [M x K], B: [K x N], C: [M x N]
 * Simple implementation - can be optimized with SIMD
 * ============================================================================ */
void matmul(const float* A, const float* B, float* C,
            int M, int N, int K) {
    for (int m = 0; m < M; m++) {
        for (int n = 0; n < N; n++) {
            float sum = 0.0f;
            for (int k = 0; k < K; k++) {
                sum += A[m * K + k] * B[k * N + n];
            }
            C[m * N + n] = sum;
        }
    }
}

/* ============================================================================
 * Matrix-Vector Multiplication: y = A * x
 * A: [M x N], x: [N], y: [M]
 * ============================================================================ */
void matvec(const float* A, const float* x, float* y, int M, int N) {
    for (int m = 0; m < M; m++) {
        float sum = 0.0f;
        for (int n = 0; n < N; n++) {
            sum += A[m * N + n] * x[n];
        }
        y[m] = sum;
    }
}

/* ============================================================================
 * RoPE (Rotary Position Embeddings)
 * Used in Llama, Mistral, etc.
 * Rotates pairs of dimensions by position-dependent angles
 * ============================================================================ */
void rope(float* vec, int dim, int pos, float theta) {
    for (int i = 0; i < dim; i += 2) {
        float x0 = vec[i];
        float x1 = vec[i + 1];
        
        /* Calculate rotation angle */
        float inv_freq = 1.0f / powf(theta, (float)i / dim);
        float angle = pos * inv_freq;
        
        float cos_a = cosf(angle);
        float sin_a = sinf(angle);
        
        /* Apply rotation */
        vec[i] = x0 * cos_a - x1 * sin_a;
        vec[i + 1] = x0 * sin_a + x1 * cos_a;
    }
}

/* ============================================================================
 * SiLU (Sigmoid Linear Unit) Activation
 * Formula: silu(x) = x * sigmoid(x) = x / (1 + exp(-x))
 * ============================================================================ */
float silu(float x) {
    return x / (1.0f + expf(-x));
}

/* ============================================================================
 * GELU Activation
 * Formula: gelu(x) = 0.5 * x * (1 + tanh(sqrt(2/pi) * (x + 0.044715 * x^3)))
 * ============================================================================ */
float gelu(float x) {
    const float sqrt_2_over_pi = 0.7978845608f;
    const float coeff = 0.044715f;
    float x3 = x * x * x;
    float inner = sqrt_2_over_pi * (x + coeff * x3);
    return 0.5f * x * (1.0f + tanhf(inner));
}

/* ============================================================================
 * SwiGLU (Swish-Gated Linear Unit)
 * Used in Llama FFN
 * Formula: swiglu(a, b) = silu(a) * b
 * ============================================================================ */
void swiglu(const float* a, const float* b, float* output, int n) {
    for (int i = 0; i < n; i++) {
        output[i] = silu(a[i]) * b[i];
    }
}

/* ============================================================================
 * Attention Mechanism
 * Q, K, V: [seq_len x head_dim]
 * Output: [seq_len x head_dim]
 * ============================================================================ */
void attention(const float* Q, const float* K, const float* V,
               float* output, int seq_len, int head_dim) {
    float* scores = (float*)malloc(seq_len * seq_len * sizeof(float));
    float* attn_weights = (float*)malloc(seq_len * seq_len * sizeof(float));
    
    /* Compute Q * K^T / sqrt(head_dim) */
    float scale = 1.0f / sqrtf((float)head_dim);
    for (int i = 0; i < seq_len; i++) {
        for (int j = 0; j < seq_len; j++) {
            float dot = 0.0f;
            for (int k = 0; k < head_dim; k++) {
                dot += Q[i * head_dim + k] * K[j * head_dim + k];
            }
            scores[i * seq_len + j] = dot * scale;
        }
    }
    
    /* Apply softmax to each row */
    for (int i = 0; i < seq_len; i++) {
        softmax(&scores[i * seq_len], &attn_weights[i * seq_len], seq_len);
    }
    
    /* Compute attention_weights * V */
    for (int i = 0; i < seq_len; i++) {
        for (int k = 0; k < head_dim; k++) {
            float sum = 0.0f;
            for (int j = 0; j < seq_len; j++) {
                sum += attn_weights[i * seq_len + j] * V[j * head_dim + k];
            }
            output[i * head_dim + k] = sum;
        }
    }
    
    free(scores);
    free(attn_weights);
}

/* ============================================================================
 * Test Functions
 * ============================================================================ */

void test_rmsnorm() {
    printf("Testing RMSNorm...\n");
    
    float input[4] = {1.0f, 2.0f, 3.0f, 4.0f};
    float weight[4] = {1.0f, 1.0f, 1.0f, 1.0f};
    float output[4];
    
    rmsnorm(input, weight, output, 4, 1e-6f);
    
    printf("  Input:  [%.2f, %.2f, %.2f, %.2f]\n", input[0], input[1], input[2], input[3]);
    printf("  Output: [%.4f, %.4f, %.4f, %.4f]\n", output[0], output[1], output[2], output[3]);
    
    /* Verify output has expected RMS of 1 */
    float rms = 0.0f;
    for (int i = 0; i < 4; i++) {
        rms += output[i] * output[i];
    }
    rms = sqrtf(rms / 4);
    printf("  Output RMS: %.4f (expected ~1.0)\n\n", rms);
}

void test_softmax() {
    printf("Testing Softmax...\n");
    
    float input[4] = {1.0f, 2.0f, 3.0f, 4.0f};
    float output[4];
    
    softmax(input, output, 4);
    
    printf("  Input:  [%.2f, %.2f, %.2f, %.2f]\n", input[0], input[1], input[2], input[3]);
    printf("  Output: [%.4f, %.4f, %.4f, %.4f]\n", output[0], output[1], output[2], output[3]);
    
    /* Verify sum is 1 */
    float sum = 0.0f;
    for (int i = 0; i < 4; i++) sum += output[i];
    printf("  Sum: %.4f (expected 1.0)\n\n", sum);
}

void test_matmul() {
    printf("Testing Matrix Multiplication...\n");
    
    /* A: 2x3, B: 3x2, C: 2x2 */
    float A[6] = {1, 2, 3, 4, 5, 6};  /* [[1,2,3], [4,5,6]] */
    float B[6] = {7, 8, 9, 10, 11, 12}; /* [[7,8], [9,10], [11,12]] */
    float C[4];
    
    matmul(A, B, C, 2, 2, 3);
    
    printf("  A: [[1,2,3], [4,5,6]]\n");
    printf("  B: [[7,8], [9,10], [11,12]]\n");
    printf("  C: [[%.0f,%.0f], [%.0f,%.0f]]\n", C[0], C[1], C[2], C[3]);
    printf("  Expected: [[58,64], [139,154]]\n\n");
}

void test_rope() {
    printf("Testing RoPE...\n");
    
    float vec[4] = {1.0f, 0.0f, 1.0f, 0.0f};
    int dim = 4;
    int pos = 1;
    float theta = 10000.0f;
    
    printf("  Input:  [%.2f, %.2f, %.2f, %.2f]\n", vec[0], vec[1], vec[2], vec[3]);
    
    rope(vec, dim, pos, theta);
    
    printf("  Output: [%.4f, %.4f, %.4f, %.4f]\n", vec[0], vec[1], vec[2], vec[3]);
    printf("  (Values should be rotated by position-dependent angles)\n\n");
}

void test_activations() {
    printf("Testing Activations...\n");
    
    float x = 1.0f;
    printf("  silu(%.2f) = %.4f\n", x, silu(x));
    printf("  gelu(%.2f) = %.4f\n", x, gelu(x));
    printf("\n");
}

/* ============================================================================
 * Main
 * ============================================================================ */
int main() {
    printf("========================================\n");
    printf("Truth Gate 002 - Phase 3: Transformer Operations\n");
    printf("========================================\n\n");
    
    test_rmsnorm();
    test_softmax();
    test_matmul();
    test_rope();
    test_activations();
    
    printf("========================================\n");
    printf("All tests completed!\n");
    printf("========================================\n");
    
    return 0;
}
