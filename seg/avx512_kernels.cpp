// ============================================================================
// AVX-512 Kernel Implementations
// ============================================================================

#include "avx512_kernels.hpp"
#include <cstring>
#include <cmath>

// MSVC intrinsics
#ifdef _MSC_VER
#include <intrin.h>
#else
#include <immintrin.h>
#include <cpuid.h>
#endif

namespace SEG {

// ============================================================================
// CPU Feature Detection
// ============================================================================

CPUFeatures CPUFeatures::Detect() {
    CPUFeatures features;
    
    unsigned int eax, ebx, ecx, edx;
    
    // Get vendor string and basic features
    __get_cpuid(0, &eax, &ebx, &ecx, &edx);
    unsigned int nIds = eax;
    
    // Get features
    __get_cpuid(1, &eax, &ebx, &ecx, &edx);
    features.hasAVX2 = (ecx & (1 << 5)) != 0;
    features.hasFMA = (ecx & (1 << 12)) != 0;
    
    // Get extended features
    if (nIds >= 7) {
        __get_cpuid(7, &eax, &ebx, &ecx, &edx);
        features.hasAVX512F = (ebx & (1 << 16)) != 0;
        features.hasAVX512DQ = (ebx & (1 << 17)) != 0;
        features.hasAVX512VL = (ebx & (1 << 31)) != 0;
    }
    
    return features;
}

const CPUFeatures& CPUFeatures::Get() {
    static CPUFeatures features = Detect();
    return features;
}

// ============================================================================
// Scalar Fallback Implementations
// ============================================================================

static void MatMulF32_Scalar(const float* A, const float* B, float* C,
                              size_t M, size_t N, size_t K) {
    std::memset(C, 0, M * N * sizeof(float));
    
    for (size_t i = 0; i < M; ++i) {
        for (size_t k = 0; k < K; ++k) {
            float a = A[i * K + k];
            for (size_t j = 0; j < N; ++j) {
                C[i * N + j] += a * B[k * N + j];
            }
        }
    }
}

static float VecDotF32_Scalar(const float* A, const float* B, size_t N) {
    float sum = 0.0f;
    for (size_t i = 0; i < N; ++i) {
        sum += A[i] * B[i];
    }
    return sum;
}

static void VecAddF32_Scalar(const float* A, const float* B, float* C, size_t N) {
    for (size_t i = 0; i < N; ++i) {
        C[i] = A[i] + B[i];
    }
}

static void VecScaleF32_Scalar(const float* X, float scale, float* Y, size_t N) {
    for (size_t i = 0; i < N; ++i) {
        Y[i] = X[i] * scale;
    }
}

static void VecMulF32_Scalar(const float* A, const float* B, float* C, size_t N) {
    for (size_t i = 0; i < N; ++i) {
        C[i] = A[i] * B[i];
    }
}

static void SiLUF32_Scalar(const float* X, float* Y, size_t N) {
    for (size_t i = 0; i < N; ++i) {
        float x = X[i];
        Y[i] = x * (1.0f / (1.0f + std::exp(-x)));
    }
}

static void RMSNormF32_Scalar(const float* X, const float* weight, float eps,
                                float* Y, size_t N) {
    float sum = 0.0f;
    for (size_t i = 0; i < N; ++i) {
        sum += X[i] * X[i];
    }
    float scale = 1.0f / std::sqrt(sum / N + eps);
    for (size_t i = 0; i < N; ++i) {
        Y[i] = X[i] * scale * weight[i];
    }
}

// ============================================================================
// AVX-512 Implementations
// ============================================================================

#ifdef __AVX512F__

// Tiled matrix multiplication for better cache utilization
// Tile sizes chosen to fit in L1/L2 cache
// Optimized for transformer dimensions (4096, 14336)
static constexpr size_t TILE_M = 64;  // Rows of A/C per tile - larger for better reuse
static constexpr size_t TILE_N = 128; // Columns of B/C per tile - matches AVX-512 width
static constexpr size_t TILE_K = 64;  // Columns of A / Rows of B per tile

void MatMulF32_AVX512_Tiled(const float* A, const float* B, float* C,
                             size_t M, size_t N, size_t K) {
    std::memset(C, 0, M * N * sizeof(float));
    
    // Tiled loop structure for cache efficiency
    for (size_t tile_i = 0; tile_i < M; tile_i += TILE_M) {
        size_t max_i = std::min(tile_i + TILE_M, M);
        
        for (size_t tile_j = 0; tile_j < N; tile_j += TILE_N) {
            size_t max_j = std::min(tile_j + TILE_N, N);
            
            for (size_t tile_k = 0; tile_k < K; tile_k += TILE_K) {
                size_t max_k = std::min(tile_k + TILE_K, K);
                
                // Process this tile
                for (size_t i = tile_i; i < max_i; ++i) {
                    for (size_t k = tile_k; k < max_k; ++k) {
                        float a_val = A[i * K + k];
                        __m512 a_vec = _mm512_set1_ps(a_val);
                        
                        size_t j = tile_j;
                        // Process 16 elements at a time
                        for (; j + 16 <= max_j; j += 16) {
                            __m512 b_vec = _mm512_loadu_ps(&B[k * N + j]);
                            __m512 c_vec = _mm512_loadu_ps(&C[i * N + j]);
                            c_vec = _mm512_fmadd_ps(a_vec, b_vec, c_vec);
                            _mm512_storeu_ps(&C[i * N + j], c_vec);
                        }
                        
                        // Scalar remainder
                        for (; j < max_j; ++j) {
                            C[i * N + j] += a_val * B[k * N + j];
                        }
                    }
                }
            }
        }
    }
}

void MatMulF32_AVX512(const float* A, const float* B, float* C,
                       size_t M, size_t N, size_t K) {
    // Use tiled version for large matrices, simple version for small
    if (M >= 64 || N >= 128 || K >= 128) {
        MatMulF32_AVX512_Tiled(A, B, C, M, N, K);
    } else {
        // Simple version for small matrices
        std::memset(C, 0, M * N * sizeof(float));
        
        for (size_t i = 0; i < M; ++i) {
            for (size_t k = 0; k < K; ++k) {
                float a_val = A[i * K + k];
                __m512 a_vec = _mm512_set1_ps(a_val);
                
                size_t j = 0;
                for (; j + 16 <= N; j += 16) {
                    __m512 b_vec = _mm512_loadu_ps(&B[k * N + j]);
                    __m512 c_vec = _mm512_loadu_ps(&C[i * N + j]);
                    c_vec = _mm512_fmadd_ps(a_vec, b_vec, c_vec);
                    _mm512_storeu_ps(&C[i * N + j], c_vec);
                }
                
                for (; j < N; ++j) {
                    C[i * N + j] += a_val * B[k * N + j];
                }
            }
        }
    }
}

void MatMulAccumulateF32_AVX512(const float* A, const float* B, float* C,
                                 size_t M, size_t N, size_t K) {
    // Same as MatMulF32_AVX512 since we accumulate
    MatMulF32_AVX512(A, B, C, M, N, K);
}

float VecDotF32_AVX512(const float* A, const float* B, size_t N) {
    __m512 sum_vec = _mm512_setzero_ps();
    size_t i = 0;
    
    // Process 16 elements at a time
    for (; i + 16 <= N; i += 16) {
        __m512 a = _mm512_loadu_ps(&A[i]);
        __m512 b = _mm512_loadu_ps(&B[i]);
        sum_vec = _mm512_fmadd_ps(a, b, sum_vec);
    }
    
    // Horizontal sum
    float sum = _mm512_reduce_add_ps(sum_vec);
    
    // Scalar remainder
    for (; i < N; ++i) {
        sum += A[i] * B[i];
    }
    
    return sum;
}

void VecAddF32_AVX512(const float* A, const float* B, float* C, size_t N) {
    size_t i = 0;
    
    for (; i + 16 <= N; i += 16) {
        __m512 a = _mm512_loadu_ps(&A[i]);
        __m512 b = _mm512_loadu_ps(&B[i]);
        __m512 c = _mm512_add_ps(a, b);
        _mm512_storeu_ps(&C[i], c);
    }
    
    for (; i < N; ++i) {
        C[i] = A[i] + B[i];
    }
}

void VecScaleF32_AVX512(const float* X, float scale, float* Y, size_t N) {
    __m512 scale_vec = _mm512_set1_ps(scale);
    size_t i = 0;
    
    for (; i + 16 <= N; i += 16) {
        __m512 x = _mm512_loadu_ps(&X[i]);
        __m512 y = _mm512_mul_ps(x, scale_vec);
        _mm512_storeu_ps(&Y[i], y);
    }
    
    for (; i < N; ++i) {
        Y[i] = X[i] * scale;
    }
}

void VecMulF32_AVX512(const float* A, const float* B, float* C, size_t N) {
    size_t i = 0;
    
    for (; i + 16 <= N; i += 16) {
        __m512 a = _mm512_loadu_ps(&A[i]);
        __m512 b = _mm512_loadu_ps(&B[i]);
        __m512 c = _mm512_mul_ps(a, b);
        _mm512_storeu_ps(&C[i], c);
    }
    
    for (; i < N; ++i) {
        C[i] = A[i] * B[i];
    }
}

void SiLUF32_AVX512(const float* X, float* Y, size_t N) {
    // SiLU(x) = x * sigmoid(x) = x / (1 + exp(-x))
    // Note: exp is expensive, using scalar fallback for now
    // TODO: Implement fast exp approximation
    for (size_t i = 0; i < N; ++i) {
        float x = X[i];
        Y[i] = x / (1.0f + std::exp(-x));
    }
}

void RMSNormF32_AVX512(const float* X, const float* weight, float eps,
                        float* Y, size_t N) {
    // Compute sum of squares
    __m512 sum_vec = _mm512_setzero_ps();
    size_t i = 0;
    
    for (; i + 16 <= N; i += 16) {
        __m512 x = _mm512_loadu_ps(&X[i]);
        sum_vec = _mm512_fmadd_ps(x, x, sum_vec);
    }
    
    float sum = _mm512_reduce_add_ps(sum_vec);
    
    for (; i < N; ++i) {
        sum += X[i] * X[i];
    }
    
    float scale = 1.0f / std::sqrt(sum / N + eps);
    __m512 scale_vec = _mm512_set1_ps(scale);
    
    // Apply normalization
    i = 0;
    for (; i + 16 <= N; i += 16) {
        __m512 x = _mm512_loadu_ps(&X[i]);
        __m512 w = _mm512_loadu_ps(&weight[i]);
        __m512 y = _mm512_mul_ps(_mm512_mul_ps(x, scale_vec), w);
        _mm512_storeu_ps(&Y[i], y);
    }
    
    for (; i < N; ++i) {
        Y[i] = X[i] * scale * weight[i];
    }
}

#else // No AVX-512 support

void MatMulF32_AVX512(const float* A, const float* B, float* C,
                       size_t M, size_t N, size_t K) {
    MatMulF32_Scalar(A, B, C, M, N, K);
}

void MatMulAccumulateF32_AVX512(const float* A, const float* B, float* C,
                                 size_t M, size_t N, size_t K) {
    MatMulF32_Scalar(A, B, C, M, N, K);
}

float VecDotF32_AVX512(const float* A, const float* B, size_t N) {
    return VecDotF32_Scalar(A, B, N);
}

void VecAddF32_AVX512(const float* A, const float* B, float* C, size_t N) {
    VecAddF32_Scalar(A, B, C, N);
}

void VecScaleF32_AVX512(const float* X, float scale, float* Y, size_t N) {
    VecScaleF32_Scalar(X, scale, Y, N);
}

void VecMulF32_AVX512(const float* A, const float* B, float* C, size_t N) {
    VecMulF32_Scalar(A, B, C, N);
}

void SiLUF32_AVX512(const float* X, float* Y, size_t N) {
    SiLUF32_Scalar(X, Y, N);
}

void RMSNormF32_AVX512(const float* X, const float* weight, float eps,
                        float* Y, size_t N) {
    RMSNormF32_Scalar(X, weight, eps, Y, N);
}

#endif // __AVX512F__

// ============================================================================
// Dispatch Layer Implementation
// ============================================================================

void KernelDispatch::Initialize() {
    // Features are auto-detected on first use
}

void KernelDispatch::MatMulF32(const float* A, const float* B, float* C,
                                size_t M, size_t N, size_t K) {
#ifdef __AVX512F__
    if (CPUFeatures::Get().hasAVX512F) {
        MatMulF32_AVX512(A, B, C, M, N, K);
        return;
    }
#endif
    MatMulF32_Scalar(A, B, C, M, N, K);
}

void KernelDispatch::MatMulAccumulateF32(const float* A, const float* B, float* C,
                                           size_t M, size_t N, size_t K) {
#ifdef __AVX512F__
    if (CPUFeatures::Get().hasAVX512F) {
        MatMulAccumulateF32_AVX512(A, B, C, M, N, K);
        return;
    }
#endif
    MatMulF32_Scalar(A, B, C, M, N, K);
}

float KernelDispatch::VecDotF32(const float* A, const float* B, size_t N) {
#ifdef __AVX512F__
    if (CPUFeatures::Get().hasAVX512F) {
        return VecDotF32_AVX512(A, B, N);
    }
#endif
    return VecDotF32_Scalar(A, B, N);
}

void KernelDispatch::VecAddF32(const float* A, const float* B, float* C, size_t N) {
#ifdef __AVX512F__
    if (CPUFeatures::Get().hasAVX512F) {
        VecAddF32_AVX512(A, B, C, N);
        return;
    }
#endif
    VecAddF32_Scalar(A, B, C, N);
}

void KernelDispatch::VecScaleF32(const float* X, float scale, float* Y, size_t N) {
#ifdef __AVX512F__
    if (CPUFeatures::Get().hasAVX512F) {
        VecScaleF32_AVX512(X, scale, Y, N);
        return;
    }
#endif
    VecScaleF32_Scalar(X, scale, Y, N);
}

void KernelDispatch::VecMulF32(const float* A, const float* B, float* C, size_t N) {
#ifdef __AVX512F__
    if (CPUFeatures::Get().hasAVX512F) {
        VecMulF32_AVX512(A, B, C, N);
        return;
    }
#endif
    VecMulF32_Scalar(A, B, C, N);
}

void KernelDispatch::SiLUF32(const float* X, float* Y, size_t N) {
#ifdef __AVX512F__
    if (CPUFeatures::Get().hasAVX512F) {
        SiLUF32_AVX512(X, Y, N);
        return;
    }
#endif
    SiLUF32_Scalar(X, Y, N);
}

void KernelDispatch::GELUF32(const float* X, float* Y, size_t N) {
    // TODO: Implement GELU
    for (size_t i = 0; i < N; ++i) {
        Y[i] = X[i];
    }
}

void KernelDispatch::RMSNormF32(const float* X, const float* weight, float eps,
                                   float* Y, size_t N) {
#ifdef __AVX512F__
    if (CPUFeatures::Get().hasAVX512F) {
        RMSNormF32_AVX512(X, weight, eps, Y, N);
        return;
    }
#endif
    RMSNormF32_Scalar(X, weight, eps, Y, N);
}

void KernelDispatch::SoftmaxF32(const float* X, float* Y, size_t N) {
    // TODO: Implement AVX-512 softmax
    float max_val = X[0];
    for (size_t i = 1; i < N; ++i) {
        max_val = std::max(max_val, X[i]);
    }
    
    float sum = 0.0f;
    for (size_t i = 0; i < N; ++i) {
        Y[i] = std::exp(X[i] - max_val);
        sum += Y[i];
    }
    
    for (size_t i = 0; i < N; ++i) {
        Y[i] /= sum;
    }
}

void KernelDispatch::AttentionQKF32(const float* Q, const float* K, float* scores,
                                    size_t seq_len, size_t head_dim, float scale) {
    // TODO: Implement AVX-512 attention
    for (size_t i = 0; i < seq_len; ++i) {
        for (size_t j = 0; j < seq_len; ++j) {
            float dot = 0.0f;
            for (size_t k = 0; k < head_dim; ++k) {
                dot += Q[i * head_dim + k] * K[j * head_dim + k];
            }
            scores[i * seq_len + j] = dot * scale;
        }
    }
}

void KernelDispatch::AttentionSoftmaxVF32(const float* scores, const float* V,
                                           float* output, size_t seq_len, size_t head_dim) {
    // TODO: Implement AVX-512 attention
    for (size_t i = 0; i < seq_len; ++i) {
        for (size_t d = 0; d < head_dim; ++d) {
            float sum = 0.0f;
            for (size_t j = 0; j < seq_len; ++j) {
                sum += scores[i * seq_len + j] * V[j * head_dim + d];
            }
            output[i * head_dim + d] = sum;
        }
    }
}

} // namespace SEG
