// cpu_ref_kernels.cpp - CPU Reference Implementations (kernels only)
// Phase 8.3 Validation - Compare GPU output against CPU reference

#define _USE_MATH_DEFINES
#include <math.h>
#include <stdlib.h>
#include <stdint.h>

// ============================================================================
// CPU REFERENCE KERNELS
// ============================================================================

// RMSNorm: output = input * weight / sqrt(mean(input^2) + eps)
extern "C" void cpu_rmsnorm(float* output, const float* input, const float* weight,
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
extern "C" void cpu_rope(float* query, float* key, uint32_t n_heads, uint32_t head_dim,
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
extern "C" void cpu_softmax(float* output, const float* input, uint32_t n_elements) {
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
extern "C" void cpu_matmul(float* C, const float* A, const float* B,
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
extern "C" void cpu_swiglu(float* output, const float* gate, const float* up,
                uint32_t n_elements) {
    for (uint32_t i = 0; i < n_elements; i++) {
        output[i] = cpu_silu(gate[i]) * up[i];
    }
}

// Attention: softmax(Q @ K^T / sqrt(d_k)) @ V
extern "C" void cpu_attention(float* output, const float* query, const float* key,
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
