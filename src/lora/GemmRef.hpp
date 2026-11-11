// ============================================================================
// GemmRef.cpp - C++ Reference GEMM Implementation
// ============================================================================
// Simple, correct reference implementation for validating MASM kernel
// C = A × B where A is M×K, B is K×N, C is M×N
// ============================================================================

#pragma once

#include <cstddef>
#include <cstring>

namespace RawrXD {

// Simple reference GEMM: C = A × B + C (accumulate)
// A: M×K matrix (row-major)
// B: K×N matrix (row-major)  
// C: M×N matrix (row-major)
inline void GemmRef(
    const float* A,
    const float* B,
    float* C,
    int M,
    int N,
    int K,
    float alpha = 1.0f,
    float beta = 0.0f
) {
    // C = beta * C + alpha * (A × B)
    for (int m = 0; m < M; m++) {
        for (int n = 0; n < N; n++) {
            float acc = 0.0f;
            for (int k = 0; k < K; k++) {
                acc += A[m * K + k] * B[k * N + n];
            }
            C[m * N + n] = beta * C[m * N + n] + alpha * acc;
        }
    }
}

// Simplified version: C = A × B (no accumulate, no scaling)
inline void GemmRefSimple(
    const float* A,
    const float* B,
    float* C,
    int M,
    int N,
    int K
) {
    // Initialize C to zero
    for (int i = 0; i < M * N; i++) {
        C[i] = 0.0f;
    }
    
    // C = A × B
    for (int m = 0; m < M; m++) {
        for (int n = 0; n < N; n++) {
            float acc = 0.0f;
            for (int k = 0; k < K; k++) {
                acc += A[m * K + k] * B[k * N + n];
            }
            C[m * N + n] = acc;
        }
    }
}

// Validate MASM kernel result against reference
inline bool ValidateGemmResult(
    const float* result,
    const float* A,
    const float* B,
    int M,
    int N,
    int K,
    float tolerance = 0.001f
) {
    for (int m = 0; m < M; m++) {
        for (int n = 0; n < N; n++) {
            float expected = 0.0f;
            for (int k = 0; k < K; k++) {
                expected += A[m * K + k] * B[k * N + n];
            }
            float actual = result[m * N + n];
            if (std::abs(actual - expected) > tolerance) {
                return false;
            }
        }
    }
    return true;
}

} // namespace RawrXD
