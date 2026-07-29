//============================================================================
// nevm_determinism_safeguards.cpp
// RawrXD N-EVM - Determinism Safeguards Implementation
//============================================================================

#include "nevm_determinism_safeguards.hpp"
#include <math>

namespace RawrXD {
namespace NEVM {

//============================================================================
// Deterministic Reduction
//============================================================================

float DeterministicReduction::TreeSum(const float* data, size_t count) {
    if (count == 0) return 0.0f;
    if (count == 1) return data[0];
    
    // Tree-based reduction for deterministic parallel summation
    std::vector<float> temp((count + 1) / 2);
    size_t temp_count = 0;
    
    // Pairwise summation
    for (size_t i = 0; i < count; i += 2) {
        if (i + 1 < count) {
            temp[temp_count++] = data[i] + data[i + 1];
        } else {
            temp[temp_count++] = data[i];
        }
    }
    
    // Recursively reduce
    return TreeSum(temp.data(), temp_count);
}

float DeterministicReduction::KahanSum(const float* data, size_t count) {
    float sum = 0.0f;
    float compensation = 0.0f;
    
    for (size_t i = 0; i < count; ++i) {
        float y = data[i] - compensation;
        float t = sum + y;
        compensation = (t - sum) - y;
        sum = t;
    }
    
    return sum;
}

float DeterministicReduction::SequentialSum(const float* data, size_t count) {
    float sum = 0.0f;
    for (size_t i = 0; i < count; ++i) {
        sum += data[i];
    }
    return sum;
}

//============================================================================
// Deterministic SoftMax
//============================================================================

void DeterministicSoftMax::Compute(const float* input, float* output, size_t count) {
    if (count == 0) return;
    
    // Find max for numerical stability (deterministic)
    float max_val = input[0];
    for (size_t i = 1; i < count; ++i) {
        if (input[i] > max_val) {
            max_val = input[i];
        }
    }
    
    // Compute exponentials and sum
    std::vector<float> exp_values(count);
    float sum = 0.0f;
    
    for (size_t i = 0; i < count; ++i) {
        exp_values[i] = std::exp(input[i] - max_val);
        sum += exp_values[i];
    }
    
    // Normalize
    for (size_t i = 0; i < count; ++i) {
        output[i] = exp_values[i] / sum;
    }
}

void DeterministicSoftMax::ComputeKahan(const float* input, float* output, size_t count) {
    if (count == 0) return;
    
    // Find max for numerical stability
    float max_val = input[0];
    for (size_t i = 1; i < count; ++i) {
        if (input[i] > max_val) {
            max_val = input[i];
        }
    }
    
    // Compute exponentials
    std::vector<float> exp_values(count);
    for (size_t i = 0; i < count; ++i) {
        exp_values[i] = std::exp(input[i] - max_val);
    }
    
    // Kahan summation for sum
    float sum = 0.0f;
    float compensation = 0.0f;
    
    for (size_t i = 0; i < count; ++i) {
        float y = exp_values[i] - compensation;
        float t = sum + y;
        compensation = (t - sum) - y;
        sum = t;
    }
    
    // Normalize
    for (size_t i = 0; i < count; ++i) {
        output[i] = exp_values[i] / sum;
    }
}

//============================================================================
// Deterministic GEMM
//============================================================================

void DeterministicGEMM::Multiply(const float* A, const float* B, float* C,
                                  size_t M, size_t N, size_t K,
                                  bool use_kahan) {
    // C[M][N] = A[M][K] * B[K][N]
    
    for (size_t i = 0; i < M; ++i) {
        for (size_t j = 0; j < N; ++j) {
            if (use_kahan) {
                // Kahan summation for dot product
                float sum = 0.0f;
                float compensation = 0.0f;
                
                for (size_t k = 0; k < K; ++k) {
                    float product = A[i * K + k] * B[k * N + j];
                    float y = product - compensation;
                    float t = sum + y;
                    compensation = (t - sum) - y;
                    sum = t;
                }
                
                C[i * N + j] = sum;
            } else {
                // Sequential dot product
                float sum = 0.0f;
                for (size_t k = 0; k < K; ++k) {
                    sum += A[i * K + k] * B[k * N + j];
                }
                C[i * N + j] = sum;
            }
        }
    }
}

} // namespace NEVM
} // namespace RawrXD
