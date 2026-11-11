// ============================================================================
// test_blocked_gemm.cpp - Blocked GEMM Test Harness
// ============================================================================

#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <cmath>
#include <vector>
#include "src/lora/GemmRef.hpp"
#include "src/lora/BlockedGemm.hpp"

void init_matrix(float* mat, int rows, int cols, float pattern, int seed = 0) {
    for (int i = 0; i < rows * cols; i++) {
        mat[i] = pattern * ((i + seed) % 17) * 0.1f + 0.01f;
    }
}

bool compare_matrices(const float* a, const float* b, int rows, int cols, float tolerance = 0.01f) {
    int mismatches = 0;
    for (int i = 0; i < rows * cols; i++) {
        if (std::abs(a[i] - b[i]) > tolerance) {
            if (mismatches < 5) {
                printf("  Mismatch at [%d]: got %.6f, expected %.6f (diff=%.6f)\n", 
                       i, a[i], b[i], std::abs(a[i] - b[i]));
            }
            mismatches++;
        }
    }
    if (mismatches > 0) {
        printf("  Total mismatches: %d/%d\n", mismatches, rows * cols);
        return false;
    }
    return true;
}

// Simple reference GEMM for validation
void ReferenceGemm(const float* A, const float* B, float* C, int M, int N, int K) {
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

struct TestCase {
    int M, N, K;
    const char* name;
};

int main() {
    printf("========================================\n");
    printf("Blocked GEMM Test Harness\n");
    printf("Blocking: MC=%d, KC=%d, NC=%d\n", RawrXD::MC, RawrXD::KC, RawrXD::NC);
    printf("========================================\n\n");
    
    TestCase tests[] = {
        // Small sizes (within single block)
        {8, 8, 8, "Tiny (8×8×8)"},
        {16, 16, 16, "Small (16×16×16)"},
        {32, 32, 32, "Medium-Small (32×32×32)"},
        
        // Block-aligned sizes
        {64, 64, 64, "Block-Aligned (64×64×64)"},
        {128, 128, 128, "Full Block (128×128×128)"},
        {256, 256, 256, "Double Block (256×256×256)"},
        
        // Non-aligned sizes (edge cases)
        {100, 100, 100, "Non-Aligned (100×100×100)"},
        {150, 150, 150, "Partial Blocks (150×150×150)"},
        
        // Transformer-like sizes
        {512, 512, 512, "Transformer-Small (512×512×512)"},
        {1024, 1024, 1024, "Transformer-Medium (1024³)"},
        {4096, 4096, 4096, "Transformer-Large (4096³)"},
        
        // FFN-like sizes (wide)
        {4096, 11008, 4096, "FFN Projection (4096×11008×4096)"},
    };
    
    int num_tests = sizeof(tests) / sizeof(tests[0]);
    int passed = 0;
    
    for (int t = 0; t < num_tests; t++) {
        const auto& test = tests[t];
        int M = test.M, N = test.N, K = test.K;
        
        printf("[Test %d] %s...\n", t + 1, test.name);
        printf("  Dimensions: M=%d, N=%d, K=%d\n", M, N, K);
        
        // Allocate matrices
        float* A = RawrXD::aligned_alloc<float>(M * K);
        float* B = RawrXD::aligned_alloc<float>(K * N);
        float* C_ref = RawrXD::aligned_alloc<float>(M * N);
        float* C_blocked = RawrXD::aligned_alloc<float>(M * N);
        
        // Initialize
        init_matrix(A, M, K, 1.0f, 0);
        init_matrix(B, K, N, 2.0f, 1);
        
        // Reference computation
        ReferenceGemm(A, B, C_ref, M, N, K);
        
        // Blocked computation
        RawrXD::BlockedGemm(A, B, C_blocked, M, N, K);
        
        // Validate
        bool pass = compare_matrices(C_blocked, C_ref, M, N, 0.01f);
        
        if (pass) {
            printf("  Result: PASS ✓\n");
            passed++;
            
            // Performance measurement for larger sizes
            if (M >= 128) {
                // Warmup
                for (int i = 0; i < 3; i++) {
                    RawrXD::BlockedGemm(A, B, C_blocked, M, N, K);
                }
                
                // Timed runs
                int iterations = (M >= 1024) ? 5 : 10;
                uint64_t start = __rdtsc();
                for (int i = 0; i < iterations; i++) {
                    RawrXD::BlockedGemm(A, B, C_blocked, M, N, K);
                }
                uint64_t end = __rdtsc();
                
                double cycles = (double)(end - start) / iterations;
                double flops = 2.0 * M * N * K;
                double gflops = flops / cycles * 3.0;  // Approximate GHz
                double bytes = RawrXD::CalculateBytesMoved(M, N, K);
                double arithmetic_intensity = flops / bytes;
                
                printf("  Performance:\n");
                printf("    Cycles: %.0f\n", cycles);
                printf("    GFLOPS: %.2f\n", gflops);
                printf("    Arithmetic Intensity: %.2f FLOPs/byte\n", arithmetic_intensity);
            }
        } else {
            printf("  Result: FAIL ✗\n");
        }
        
        printf("\n");
        
        RawrXD::aligned_free(A);
        RawrXD::aligned_free(B);
        RawrXD::aligned_free(C_ref);
        RawrXD::aligned_free(C_blocked);
    }
    
    printf("========================================\n");
    printf("Results: %d/%d tests passed\n", passed, num_tests);
    printf("========================================\n");
    
    return (passed == num_tests) ? 0 : 1;
}
