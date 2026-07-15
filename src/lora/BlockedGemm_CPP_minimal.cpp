#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>

// Simple aligned allocation functions
static void* aligned_alloc(size_t alignment, size_t size) {
    void* ptr;
    #ifdef _WIN32
        ptr = _aligned_malloc(size, alignment);
    #else
        if (posix_memalign(&ptr, alignment, size) != 0) {
            return nullptr;
        }
    #endif
    return ptr;
}

static void aligned_free(void* ptr) {
    #ifdef _WIN32
        _aligned_free(ptr);
    #else
        free(ptr);
    #endif
}

// Block sizes for cache blocking
constexpr size_t MC = 128;  // Cache block size for M dimension
constexpr size_t KC = 256;  // Cache block size for K dimension  
constexpr size_t NC = 128;  // Cache block size for N dimension

// Forward declaration of the microkernel
extern "C" void Gemm_8x8_Microkernel(
    const float* A, const float* B, float* C,
    size_t ldc, float alpha, float beta
);

extern "C" int BlockedGemm_CPP(
    const float* A,
    const float* B,
    float* C,
    size_t M,
    size_t N,
    size_t K,
    float alpha,
    float beta
) {
    std::cout << "BlockedGemm_CPP called with M=" << M << ", N=" << N << ", K=" << K << std::endl;
    // Allocate packed buffers with alignment for SIMD
    float* A_packed = (float*)aligned_alloc(64, MC * KC * sizeof(float));
    float* B_packed = (float*)aligned_alloc(64, KC * NC * sizeof(float));
    
    if (!A_packed || !B_packed) {
        if (A_packed) aligned_free(A_packed);
        if (B_packed) aligned_free(B_packed);
        return 1; // Allocation failure
    }
    
    // Initialize C if beta == 0, else scale existing C
    if (beta == 0.0f) {
        for (size_t i = 0; i < M * N; i++) {
            C[i] = 0.0f;
        }
    } else if (beta != 1.0f) {
        for (size_t i = 0; i < M * N; i++) {
            C[i] *= beta;
        }
    }
    
    // Main blocked GEMM loop
    for (size_t mc = 0; mc < M; mc += MC) {
        size_t m_actual = (M - mc) > MC ? MC : M - mc;
        
        for (size_t nc = 0; nc < N; nc += NC) {
            size_t n_actual = (N - nc) > NC ? NC : N - nc;
            
            for (size_t kc = 0; kc < K; kc += KC) {
                size_t k_actual = (K - kc) > KC ? KC : K - kc;
                
                // Pack A block (mc:mc+m_actual, kc:kc+k_actual)
                // Pack B block (kc:kc+k_actual, nc:nc+n_actual)
                // Call microkernel
                
                // For now, just do a simple matrix multiplication
                for (size_t i = 0; i < m_actual; i++) {
                    for (size_t j = 0; j < n_actual; j++) {
                        float sum = 0.0f;
                        for (size_t k = 0; k < k_actual; k++) {
                            sum += A[(mc + i) * K + (kc + k)] * 
                                   B[(kc + k) * N + (nc + j)];
                        }
                        C[(mc + i) * N + (nc + j)] += alpha * sum;
                    }
                }
            }
        }
    }
    
    aligned_free(A_packed);
    aligned_free(B_packed);
    return 0; // Success
}