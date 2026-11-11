#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <cmath>

extern "C" int Gemm_8x8_Microkernel(
    const float* A_packed,
    const float* B,
    float* C,
    size_t K
);

template<typename T>
T* aligned_alloc(size_t count, size_t alignment = 32) {
    void* ptr = _aligned_malloc(count * sizeof(T), alignment);
    return static_cast<T*>(ptr);
}

void aligned_free(void* ptr) { _aligned_free(ptr); }

int main() {
    const int M = 8, N = 8, K = 8;
    
    float* A_packed = aligned_alloc<float>(K * 8);
    float* B = aligned_alloc<float>(K * N);
    float* C = aligned_alloc<float>(M * N);
    
    // Initialize A_packed with identity pattern: A[m,k] = m*10 + k
    // So A_packed[k*8+m] = m*10 + k
    for (int k = 0; k < K; k++) {
        for (int m = 0; m < 8; m++) {
            A_packed[k * 8 + m] = (float)(m * 10 + k);
        }
    }
    
    // Initialize B with pattern: B[k,n] = 1.0 (simple)
    for (int k = 0; k < K; k++) {
        for (int n = 0; n < N; n++) {
            B[k * N + n] = 1.0f;
        }
    }
    
    // Zero C
    for (int i = 0; i < M * N; i++) C[i] = 0.0f;
    
    // Call kernel
    Gemm_8x8_Microkernel(A_packed, B, C, K);
    
    // Print result
    printf("C = A_packed x B (B is all 1s):\n");
    printf("Expected: Each row m should sum to sum_k(A[m,k])\n\n");
    
    for (int m = 0; m < M; m++) {
        float expected = 0.0f;
        for (int k = 0; k < K; k++) {
            expected += (float)(m * 10 + k);
        }
        float actual = C[m * N];  // First element of row m
        printf("Row %d: expected %.1f, got %.1f %s\n", 
               m, expected, actual, (std::abs(expected-actual) < 0.1f) ? "OK" : "FAIL");
    }
    
    printf("\nFull C matrix:\n");
    for (int m = 0; m < M; m++) {
        printf("Row %d: ", m);
        for (int n = 0; n < N; n++) {
            printf("%6.1f ", C[m * N + n]);
        }
        printf("\n");
    }
    
    aligned_free(A_packed);
    aligned_free(B);
    aligned_free(C);
    
    return 0;
}
