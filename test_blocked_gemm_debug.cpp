// ============================================================================
// test_blocked_gemm_debug.cpp - Debug Blocked GEMM
// ============================================================================

#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <cmath>
#include "src/lora/BlockedGemm.hpp"

extern "C" int Gemm_8x8_Microkernel(
    const float* A_packed,
    const float* B,
    float* C,
    size_t K
);

int main() {
    printf("Debug Blocked GEMM\n");
    printf("====================\n\n");
    
    // Simple 8×8×8 test
    const int M = 8, N = 8, K = 8;
    
    float* A = RawrXD::aligned_alloc<float>(M * K);
    float* B = RawrXD::aligned_alloc<float>(K * N);
    float* C = RawrXD::aligned_alloc<float>(M * N);
    
    // Initialize with simple pattern
    for (int i = 0; i < M * K; i++) A[i] = 1.0f;
    for (int i = 0; i < K * N; i++) B[i] = 1.0f;
    for (int i = 0; i < M * N; i++) C[i] = 0.0f;
    
    printf("A (8×8, all 1s):\n");
    for (int m = 0; m < M; m++) {
        printf("  Row %d: ", m);
        for (int k = 0; k < K; k++) {
            printf("%.0f ", A[m * K + k]);
        }
        printf("\n");
    }
    
    printf("\nB (8×8, all 1s):\n");
    for (int k = 0; k < K; k++) {
        printf("  Row %d: ", k);
        for (int n = 0; n < N; n++) {
            printf("%.0f ", B[k * N + n]);
        }
        printf("\n");
    }
    
    // Pack A
    float* A_packed = RawrXD::aligned_alloc<float>(M * K);
    RawrXD::PackAPanel(A, A_packed, M, K, K);
    
    printf("\nA_packed (should be 8×8 with A[0,k], A[1,k], ... A[7,k] consecutive):\n");
    for (int k = 0; k < K; k++) {
        printf("  K=%d: ", k);
        for (int m = 0; m < M; m++) {
            printf("%.0f ", A_packed[k * 8 + m]);
        }
        printf("\n");
    }
    
    // Call microkernel directly
    printf("\nCalling microkernel directly...\n");
    alignas(32) float C_tile[64];
    Gemm_8x8_Microkernel(A_packed, B, C_tile, K);
    
    printf("\nC_tile result (should be all 8s):\n");
    for (int m = 0; m < M; m++) {
        printf("  Row %d: ", m);
        for (int n = 0; n < N; n++) {
            printf("%.2f ", C_tile[m * 8 + n]);
        }
        printf("\n");
    }
    
    // Expected: each element should be sum of 8 products (1*1) = 8
    bool pass = true;
    for (int i = 0; i < 64; i++) {
        if (std::abs(C_tile[i] - 8.0f) > 0.01f) {
            printf("\nFAIL: C_tile[%d] = %.4f, expected 8.0\n", i, C_tile[i]);
            pass = false;
            break;
        }
    }
    
    if (pass) {
        printf("\nPASS: Microkernel working correctly!\n");
    }
    
    RawrXD::aligned_free(A);
    RawrXD::aligned_free(B);
    RawrXD::aligned_free(C);
    RawrXD::aligned_free(A_packed);
    
    return pass ? 0 : 1;
}
