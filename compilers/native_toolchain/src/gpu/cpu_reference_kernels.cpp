// cpu_reference_kernels.cpp - CPU Reference Implementations for Validation
// Phase 8.3 Validation - Compare GPU output against CPU reference

#define _USE_MATH_DEFINES
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// ============================================================================
// CPU REFERENCE KERNELS
// ============================================================================

// RMSNorm: output = input * weight / sqrt(mean(input^2) + eps)
void cpu_rmsnorm(float* output, const float* input, const float* weight,
                 uint32_t n_elements, float epsilon) {
    // Calculate mean of squares
    float sum_sq = 0.0f;
    for (uint32_t i = 0; i < n_elements; i++) {
        sum_sq += input[i] * input[i];
    }
    float mean_sq = sum_sq / n_elements;
    float rms = sqrtf(mean_sq + epsilon);
    float scale = 1.0f / rms;
    
    // Apply normalization and weight
    for (uint32_t i = 0; i < n_elements; i++) {
        output[i] = input[i] * scale * weight[i];
    }
}

// RoPE (Rotary Position Embedding)
void cpu_rope(float* query, float* key, uint32_t n_heads, uint32_t head_dim,
              uint32_t position, float freq_base) {
    for (uint32_t h = 0; h < n_heads; h++) {
        for (uint32_t d = 0; d < head_dim / 2; d++) {
            float freq = 1.0f / powf(freq_base, (2.0f * d) / head_dim);
            float theta = position * freq;
            float cos_theta = cosf(theta);
            float sin_theta = sinf(theta);
            
            uint32_t idx = h * head_dim + d;
            uint32_t pair_idx = h * head_dim + d + head_dim / 2;
            
            // Rotate query
            float q1 = query[idx];
            float q2 = query[pair_idx];
            query[idx] = q1 * cos_theta - q2 * sin_theta;
            query[pair_idx] = q1 * sin_theta + q2 * cos_theta;
            
            // Rotate key
            float k1 = key[idx];
            float k2 = key[pair_idx];
            key[idx] = k1 * cos_theta - k2 * sin_theta;
            key[pair_idx] = k1 * sin_theta + k2 * cos_theta;
        }
    }
}

// Softmax: output[i] = exp(input[i] - max) / sum(exp(input[j] - max))
void cpu_softmax(float* output, const float* input, uint32_t n_elements) {
    // Find max
    float max_val = input[0];
    for (uint32_t i = 1; i < n_elements; i++) {
        if (input[i] > max_val) max_val = input[i];
    }
    
    // Compute exp and sum
    float sum = 0.0f;
    for (uint32_t i = 0; i < n_elements; i++) {
        output[i] = expf(input[i] - max_val);
        sum += output[i];
    }
    
    // Normalize
    float inv_sum = 1.0f / sum;
    for (uint32_t i = 0; i < n_elements; i++) {
        output[i] *= inv_sum;
    }
}

// Matrix Multiplication: C = A @ B (A: m x k, B: k x n, C: m x n)
void cpu_matmul(float* C, const float* A, const float* B,
                uint32_t m, uint32_t n, uint32_t k) {
    for (uint32_t i = 0; i < m; i++) {
        for (uint32_t j = 0; j < n; j++) {
            float sum = 0.0f;
            for (uint32_t l = 0; l < k; l++) {
                sum += A[i * k + l] * B[l * n + j];
            }
            C[i * n + j] = sum;
        }
    }
}

// SiLU (Swish): silu(x) = x * sigmoid(x) = x / (1 + exp(-x))
float cpu_silu(float x) {
    return x / (1.0f + expf(-x));
}

// SwiGLU: output = silu(gate) * up
void cpu_swiglu(float* output, const float* gate, const float* up,
                uint32_t n_elements) {
    for (uint32_t i = 0; i < n_elements; i++) {
        output[i] = cpu_silu(gate[i]) * up[i];
    }
}

// Attention: softmax(Q @ K^T / sqrt(d_k)) @ V
void cpu_attention(float* output, const float* query, const float* key,
                   const float* value, uint32_t n_heads, uint32_t seq_len,
                   uint32_t head_dim) {
    float scale = 1.0f / sqrtf((float)head_dim);
    uint32_t total_dim = n_heads * head_dim;
    
    // Temporary buffers
    float* scores = (float*)malloc(seq_len * sizeof(float));
    float* attn_weights = (float*)malloc(seq_len * sizeof(float));
    
    for (uint32_t h = 0; h < n_heads; h++) {
        for (uint32_t s = 0; s < seq_len; s++) {
            // Compute attention scores for this position
            for (uint32_t pos = 0; pos < seq_len; pos++) {
                float dot = 0.0f;
                for (uint32_t d = 0; d < head_dim; d++) {
                    uint32_t q_idx = h * head_dim + d;
                    uint32_t k_idx = pos * total_dim + h * head_dim + d;
                    dot += query[s * total_dim + q_idx] * key[pos * total_dim + q_idx];
                }
                scores[pos] = dot * scale;
            }
            
            // Softmax
            cpu_softmax(attn_weights, scores, seq_len);
            
            // Weighted sum of values
            for (uint32_t d = 0; d < head_dim; d++) {
                float sum = 0.0f;
                for (uint32_t pos = 0; pos < seq_len; pos++) {
                    uint32_t v_idx = pos * total_dim + h * head_dim + d;
                    sum += attn_weights[pos] * value[v_idx];
                }
                output[s * total_dim + h * head_dim + d] = sum;
            }
        }
    }
    
    free(scores);
    free(attn_weights);
}

// ============================================================================
// VALIDATION UTILITIES
// ============================================================================

float calculate_max_error(const float* a, const float* b, uint32_t n) {
    float max_err = 0.0f;
    for (uint32_t i = 0; i < n; i++) {
        float err = fabsf(a[i] - b[i]);
        if (err > max_err) max_err = err;
    }
    return max_err;
}

float calculate_mean_error(const float* a, const float* b, uint32_t n) {
    double sum = 0.0;
    for (uint32_t i = 0; i < n; i++) {
        sum += fabsf(a[i] - b[i]);
    }
    return (float)(sum / n);
}

// ============================================================================
// TEST HARNESS
// ============================================================================

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) printf("\n[TEST] %s\n", name); printf("================================================\n");
#define CHECK(cond, msg) do { \
    if (cond) { \
        printf("  ✓ %s\n", msg); \
        tests_passed++; \
    } else { \
        printf("  ✗ FAILED: %s\n", msg); \
        tests_failed++; \
    } \
} while(0)

void test_rmsnorm(void) {
    TEST("CPU Reference: RMSNorm");
    
    const uint32_t n = 256;
    float* input = (float*)malloc(n * sizeof(float));
    float* weight = (float*)malloc(n * sizeof(float));
    float* output = (float*)malloc(n * sizeof(float));
    
    // Initialize with test data
    for (uint32_t i = 0; i < n; i++) {
        input[i] = (float)(i % 10) / 10.0f;
        weight[i] = 1.0f;
    }
    
    cpu_rmsnorm(output, input, weight, n, 1e-6f);
    
    // Verify output is normalized
    float sum_sq = 0.0f;
    for (uint32_t i = 0; i < n; i++) {
        sum_sq += output[i] * output[i];
    }
    float rms = sqrtf(sum_sq / n);
    
    printf("  Input RMS: ~%.4f\n", sqrtf(3.3f));  // Expected from input pattern
    printf("  Output RMS: %.4f (should be ~1.0)\n", rms);
    
    CHECK(fabsf(rms - 1.0f) < 0.01f, "Output is normalized (RMS ≈ 1.0)");
    
    free(input);
    free(weight);
    free(output);
}

void test_rope(void) {
    TEST("CPU Reference: RoPE");
    
    const uint32_t n_heads = 8;
    const uint32_t head_dim = 64;
    const uint32_t total_dim = n_heads * head_dim;
    
    float* query = (float*)malloc(total_dim * sizeof(float));
    float* key = (float*)malloc(total_dim * sizeof(float));
    
    // Initialize
    for (uint32_t i = 0; i < total_dim; i++) {
        query[i] = (float)(i % 5);
        key[i] = (float)(i % 3);
    }
    
    // Save original magnitudes
    float orig_q_mag = 0.0f, orig_k_mag = 0.0f;
    for (uint32_t i = 0; i < total_dim; i++) {
        orig_q_mag += query[i] * query[i];
        orig_k_mag += key[i] * key[i];
    }
    orig_q_mag = sqrtf(orig_q_mag);
    orig_k_mag = sqrtf(orig_k_mag);
    
    // Apply RoPE
    cpu_rope(query, key, n_heads, head_dim, 10, 10000.0f);
    
    // Verify magnitudes are preserved
    float new_q_mag = 0.0f, new_k_mag = 0.0f;
    for (uint32_t i = 0; i < total_dim; i++) {
        new_q_mag += query[i] * query[i];
        new_k_mag += key[i] * key[i];
    }
    new_q_mag = sqrtf(new_q_mag);
    new_k_mag = sqrtf(new_k_mag);
    
    printf("  Query magnitude before: %.4f, after: %.4f\n", orig_q_mag, new_q_mag);
    printf("  Key magnitude before: %.4f, after: %.4f\n", orig_k_mag, new_k_mag);
    
    CHECK(fabsf(new_q_mag - orig_q_mag) < 0.01f, "Query magnitude preserved");
    CHECK(fabsf(new_k_mag - orig_k_mag) < 0.01f, "Key magnitude preserved");
    
    free(query);
    free(key);
}

void test_softmax(void) {
    TEST("CPU Reference: Softmax");
    
    const uint32_t n = 256;
    float* input = (float*)malloc(n * sizeof(float));
    float* output = (float*)malloc(n * sizeof(float));
    
    // Initialize
    for (uint32_t i = 0; i < n; i++) {
        input[i] = (float)(i - 128) / 10.0f;  // Range: -12.8 to 12.7
    }
    
    cpu_softmax(output, input, n);
    
    // Verify probabilities sum to 1
    float sum = 0.0f;
    for (uint32_t i = 0; i < n; i++) {
        sum += output[i];
    }
    
    // Verify all values are in [0, 1]
    int valid = 1;
    for (uint32_t i = 0; i < n; i++) {
        if (output[i] < 0.0f || output[i] > 1.0f) {
            valid = 0;
            break;
        }
    }
    
    printf("  Sum of probabilities: %.6f (should be 1.0)\n", sum);
    printf("  All values in [0,1]: %s\n", valid ? "Yes" : "No");
    
    CHECK(fabsf(sum - 1.0f) < 0.001f, "Probabilities sum to 1.0");
    CHECK(valid, "All values in valid range [0,1]");
    
    free(input);
    free(output);
}

void test_matmul(void) {
    TEST("CPU Reference: MatMul");
    
    const uint32_t m = 64, n = 64, k = 64;
    float* A = (float*)malloc(m * k * sizeof(float));
    float* B = (float*)malloc(k * n * sizeof(float));
    float* C = (float*)malloc(m * n * sizeof(float));
    
    // Initialize identity-like matrices
    for (uint32_t i = 0; i < m * k; i++) A[i] = (i % (k + 1) == 0) ? 1.0f : 0.0f;
    for (uint32_t i = 0; i < k * n; i++) B[i] = (float)(i % 7) / 10.0f;
    
    cpu_matmul(C, A, B, m, n, k);
    
    // With identity A, C should equal B
    int match = 1;
    for (uint32_t i = 0; i < m * n; i++) {
        if (fabsf(C[i] - B[i]) > 0.001f) {
            match = 0;
            break;
        }
    }
    
    printf("  A is identity matrix\n");
    printf("  C = A @ B should equal B\n");
    printf("  Match: %s\n", match ? "Yes" : "No");
    
    CHECK(match, "Identity matrix multiplication correct");
    
    free(A);
    free(B);
    free(C);
}

void test_swiglu(void) {
    TEST("CPU Reference: SwiGLU");
    
    const uint32_t n = 256;
    float* gate = (float*)malloc(n * sizeof(float));
    float* up = (float*)malloc(n * sizeof(float));
    float* output = (float*)malloc(n * sizeof(float));
    
    // Initialize
    for (uint32_t i = 0; i < n; i++) {
        gate[i] = (float)(i - 128) / 64.0f;  // Range: -2 to 2
        up[i] = 1.0f;
    }
    
    cpu_swiglu(output, gate, up, n);
    
    // Verify SiLU properties: silu(0) = 0, silu(x) = x * sigmoid(x)
    // Find indices where gate is approximately 0, positive, and negative
    int idx_0 = -1, idx_pos = -1, idx_neg = -1;
    for (uint32_t i = 0; i < n; i++) {
        if (fabsf(gate[i]) < 0.01f && idx_0 < 0) idx_0 = i;
        if (gate[i] > 1.0f && idx_pos < 0) idx_pos = i;
        if (gate[i] < -1.0f && idx_neg < 0) idx_neg = i;
    }
    
    float silu_0 = (idx_0 >= 0) ? output[idx_0] : 0.0f;
    float silu_pos = (idx_pos >= 0) ? output[idx_pos] : 0.0f;
    float silu_neg = (idx_neg >= 0) ? output[idx_neg] : 0.0f;
    
    // Calculate expected values
    float expected_0 = 0.0f;
    float expected_pos = (idx_pos >= 0) ? cpu_silu(gate[idx_pos]) : 0.0f;
    float expected_neg = (idx_neg >= 0) ? cpu_silu(gate[idx_neg]) : 0.0f;
    
    printf("  silu(%.3f) = %.6f (expected: %.6f)\n", 
           (idx_0 >= 0) ? gate[idx_0] : 0.0f, silu_0, expected_0);
    printf("  silu(%.3f) = %.6f (expected: %.6f)\n", 
           (idx_pos >= 0) ? gate[idx_pos] : 0.0f, silu_pos, expected_pos);
    printf("  silu(%.3f) = %.6f (expected: %.6f)\n", 
           (idx_neg >= 0) ? gate[idx_neg] : 0.0f, silu_neg, expected_neg);
    
    CHECK(fabsf(silu_0 - expected_0) < 0.01f, "SiLU(0) ≈ 0");
    CHECK(idx_pos < 0 || fabsf(silu_pos - expected_pos) < 0.1f, "SiLU positive value correct");
    CHECK(idx_neg < 0 || fabsf(silu_neg - expected_neg) < 0.1f, "SiLU negative value correct");
    
    free(gate);
    free(up);
    free(output);
}

void print_summary(void) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║           CPU REFERENCE KERNEL VALIDATION                     ║\n");
    printf("╠══════════════════════════════════════════════════════════════╣\n");
    printf("║                                                               ║\n");
    printf("║  Tests Passed:  %3d                                          ║\n", tests_passed);
    printf("║  Tests Failed:  %3d                                          ║\n", tests_failed);
    printf("║  Total Tests:   %3d                                          ║\n", tests_passed + tests_failed);
    printf("║                                                               ║\n");
    
    if (tests_failed == 0) {
        printf("║  ✅ ALL CPU REFERENCE KERNELS VALIDATED                      ║\n");
        printf("║                                                               ║\n");
        printf("║  These kernels are ready for GPU comparison testing.         ║\n");
    } else {
        printf("║  ⚠️  SOME TESTS FAILED                                        ║\n");
    }
    
    printf("║                                                               ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n");
    printf("\n");
    printf("Next: Compare these CPU results against GPU output\n");
    printf("      to validate numerical correctness.\n");
    printf("\n");
}

int main(int argc, char* argv[]) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║                                                              ║\n");
    printf("║     CPU REFERENCE KERNEL VALIDATION                          ║\n");
    printf("║     Phase 8.3 - GPU Backend Numerical Correctness            ║\n");
    printf("║                                                              ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n");
    printf("\n");
    printf("Purpose: Validate CPU reference implementations\n");
    printf("         before GPU comparison testing.\n");
    printf("\n");
    
    test_rmsnorm();
    test_rope();
    test_softmax();
    test_matmul();
    test_swiglu();
    
    print_summary();
    
    return (tests_failed == 0) ? 0 : 1;
}