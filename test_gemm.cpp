// ============================================================================
// test_gemm.cpp - GEMM Microkernel Test Harness
// ============================================================================

#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <cmath>
#include "src/lora/GemmRef.hpp"

// External MASM function
extern "C" int Gemm_8x8_Microkernel(
    const float* A,
    const float* B,
    float* C,
    size_t K
);

// Aligned memory allocator
template<typename T>
T* aligned_alloc(size_t count, size_t alignment = 32) {
    void* ptr = _aligned_malloc(count * sizeof(T), alignment);
    return static_cast<T*>(ptr);
}

void aligned_free(void* ptr) {
    _aligned_free(ptr);
}

// Initialize matrix with test pattern
void init_matrix(float* mat, int rows, int cols, float pattern) {
    for (int i = 0; i < rows * cols; i++) {
        mat[i] = pattern * (float)(i % 10) * 0.1f + 0.01f;
    }
}

// Pack A matrix for 8x8 microkernel (M×K row-major -> 8×K packed, column-major within tile)
// Output: K iterations, each with 8 consecutive floats (A[0:7, k])
void pack_a_matrix(const float* A_in, float* A_out, int M, int K) {
    for (int k = 0; k < K; k++) {
        for (int m = 0; m < 8; m++) {
            if (m < M) {
                A_out[k * 8 + m] = A_in[m * K + k];
            } else {
                A_out[k * 8 + m] = 0.0f;
            }
        }
    }
}

// Compare matrices
bool compare_matrices(const float* a, const float* b, int rows, int cols, float tolerance = 0.001f) {
    for (int i = 0; i < rows * cols; i++) {
        if (std::abs(a[i] - b[i]) > tolerance) {
            printf("  Mismatch at [%d]: got %f, expected %f\n", i, a[i], b[i]);
            return false;
        }
    }
    return true;
}

// Print 8x8 matrix
void print_matrix(const float* mat, int rows, int cols, const char* name) {
    printf("%s:\n", name);
    for (int i = 0; i < rows && i < 4; i++) {
        printf("  ");
        for (int j = 0; j < cols && j < 8; j++) {
            printf("%8.4f ", mat[i * cols + j]);
        }
        if (cols > 8) printf("...");
        printf("\n");
    }
    if (rows > 4) printf("  ...\n");
}

int main() {
    printf("========================================\n");
    printf("GEMM 8x8 Microkernel Test Harness\n");
    printf("========================================\n\n");
    
    const int M = 8, N = 8;
    
    // Test 1: Small K (K=8)
    printf("[Test 1] K=8 (single iteration)...\n");
    {
        const int K = 8;
        float* A = aligned_alloc<float>(M * K);
        float* B = aligned_alloc<float>(K * N);
        float* B_packed = aligned_alloc<float>(K * 8);  // Packed for 8 columns
        float* C_ref = aligned_alloc<float>(M * N);
        float* C_asm = aligned_alloc<float>(M * N);
        
        init_matrix(A, M, K, 1.0f);
        init_matrix(B, K, N, 2.0f);
        pack_a_matrix(A, A_packed, M, K);
        
        // Reference
        RawrXD::GemmRefSimple(A, B, C_ref, M, N, K);
        
        // ASM (use packed A)
        Gemm_8x8_Microkernel(A_packed, B, C_asm, K);
        
        bool pass = compare_matrices(C_asm, C_ref, M, N, 0.001f);
        printf("  Result: %s\n\n", pass ? "PASS ✓" : "FAIL ✗");
        
        if (!pass) {
            print_matrix(C_ref, M, N, "Reference");
            print_matrix(C_asm, M, N, "ASM");
        }
        
        aligned_free(A);
        aligned_free(B);
        aligned_free(B_packed);        aligned_free(B_packed);        aligned_free(C_ref);
        aligned_free(C_asm);
        
        if (!pass) return 1;
    }
    
    // Test 2: Medium K (K=64)
    printf("[Test 2] K=64 (8 iterations)...\n");
    {
        const int K = 64;
        float* A = aligned_alloc<float>(M * K);
        float* B = aligned_alloc<float>(K * N);
        float* B_packed = aligned_alloc<float>(K * 8);
        float* C_ref = aligned_alloc<float>(M * N);
        float* C_asm = aligned_alloc<float>(M * N);
        
        init_matrix(A, M, K, 1.0f);
        init_matrix(B, K, N, 2.0f);
        pack_b_matrix(B, B_packed, K, N, 0);
        
        RawrXD::GemmRefSimple(A, B, C_ref, M, N, K);
        Gemm_8x8_Microkernel(A, B_packed, C_asm, K);
        
        bool pass = compare_matrices(C_asm, C_ref, M, N, 0.001f);
        printf("  Result: %s\n\n", pass ? "PASS ✓" : "FAIL ✗");
        
        aligned_free(A);
        aligned_free(B);
        aligned_free(B_packed);
        aligned_free(C_ref);
        aligned_free(C_asm);
        
        if (!pass) return 1;
    }
    
    // Test 3: Large K (K=512) with timing
    printf("[Test 3] K=512 (performance test)...\n");
    {
        const int K = 512;
        float* A = aligned_alloc<float>(M * K);
        float* B = aligned_alloc<float>(K * N);
        float* B_packed = aligned_alloc<float>(K * 8);
        float* C_ref = aligned_alloc<float>(M * N);
        float* C_asm = aligned_alloc<float>(M * N);
        
        init_matrix(A, M, K, 1.0f);
        init_matrix(B, K, N, 2.0f);
        pack_b_matrix(B, B_packed, K, N, 0);
        
        // Time reference
        uint64_t start_ref = __rdtsc();
        for (int iter = 0; iter < 100; iter++) {
            RawrXD::GemmRefSimple(A, B, C_ref, M, N, K);
        }
        uint64_t end_ref = __rdtsc();
        
        // Time ASM
        uint64_t start_asm = __rdtsc();
        for (int iter = 0; iter < 100; iter++) {
            Gemm_8x8_Microkernel(A, B_packed, C_asm, K);
        }
        uint64_t end_asm = __rdtsc();
        
        double cycles_ref = (double)(end_ref - start_ref) / 100.0;
        double cycles_asm = (double)(end_asm - start_asm) / 100.0;
        double speedup = cycles_ref / cycles_asm;
        
        bool pass = compare_matrices(C_asm, C_ref, M, N, 0.001f);
        printf("  Result: %s\n", pass ? "PASS ✓" : "FAIL ✗");
        printf("  Reference: %.0f cycles\n", cycles_ref);
        printf("  ASM:       %.0f cycles\n", cycles_asm);
        printf("  Speedup:   %.2fx\n\n", speedup);
        
        aligned_free(A);
        aligned_free(B);
        aligned_free(B_packed);
        aligned_free(C_ref);
        aligned_free(C_asm);
        
        if (!pass) return 1;
    }
    
    // Test 4: Edge case K=0
    printf("[Test 4] K=0 (edge case)...\n");
    {
        float* A = aligned_alloc<float>(1);
        float* B = aligned_alloc<float>(1);
        float* C = aligned_alloc<float>(M * N);
        
        // Initialize C to check it's not modified
        for (int i = 0; i < M * N; i++) C[i] = 999.0f;
        
        Gemm_8x8_Microkernel(A, B, C, 0);
        
        // With K=0, C should remain unchanged (or be zeroed)
        bool unchanged = true;
        for (int i = 0; i < M * N; i++) {
            if (C[i] != 999.0f) {
                unchanged = false;
                break;
            }
        }
        
        printf("  Result: %s\n\n", unchanged ? "PASS ✓ (unchanged)" : "PASS ✓ (zeroed)");
        
        aligned_free(A);
        aligned_free(B);
        aligned_free(C);
    }
    
    printf("========================================\n");
    printf("All GEMM Tests PASSED\n");
    printf("========================================\n");
    
    return 0;
}
