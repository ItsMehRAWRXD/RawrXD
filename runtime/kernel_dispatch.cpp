#include "kernel_dispatch.hpp"
#include <immintrin.h>
#include <cstring>
#include <cmath>

namespace RawrXD {
namespace Runtime {

// ============================================================================
// CPU Feature Detection
// ============================================================================

#ifdef _WIN32
#include <intrin.h>
#else
#include <cpuid.h>
#endif

static void cpuid(int info[4], int function_id) {
#ifdef _WIN32
    __cpuid(info, function_id);
#else
    __cpuid(function_id, info[0], info[1], info[2], info[3]);
#endif
}

KernelCapabilities KernelCapabilities::Detect() {
    KernelCapabilities caps;
    
    int info[4];
    cpuid(info, 1);
    
    // Check AVX2 (bit 5 of EBX)
    caps.hasAVX2 = (info[2] & (1 << 5)) != 0;
    
    // Check FMA (bit 12 of ECX)
    caps.hasFMA = (info[2] & (1 << 12)) != 0;
    
    // Check AVX512F (bit 16 of EBX from extended info)
    cpuid(info, 7);
    caps.hasAVX512F = (info[1] & (1 << 16)) != 0;
    caps.hasAVX512DQ = (info[1] & (1 << 17)) != 0;
    caps.hasAVX512VL = (info[1] & (1 << 31)) != 0;
    
    return caps;
}

const KernelCapabilities& KernelCapabilities::Get() {
    static KernelCapabilities caps = Detect();
    return caps;
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

static void SoftmaxF32_Scalar(const float* X, float* Y, size_t N) {
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

static void SiLUF32_Scalar(const float* X, float* Y, size_t N) {
    for (size_t i = 0; i < N; ++i) {
        Y[i] = X[i] * (1.0f / (1.0f + std::exp(-X[i])));
    }
}

static void GELUF32_Scalar(const float* X, float* Y, size_t N) {
    const float sqrt_2_over_pi = 0.7978845608f;
    const float coeff = 0.044715f;
    for (size_t i = 0; i < N; ++i) {
        float x = X[i];
        float tanh_arg = sqrt_2_over_pi * (x + coeff * x * x * x);
        Y[i] = 0.5f * x * (1.0f + std::tanh(tanh_arg));
    }
}

static void AttentionQKF32_Scalar(const float* Q, const float* K, float* scores,
                                   size_t seq_len, size_t head_dim, float scale) {
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

static void AttentionSoftmaxVF32_Scalar(const float* scores, const float* V,
                                           float* output, size_t seq_len, size_t head_dim) {
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

// ============================================================================
// AVX512 Implementations (16 floats per vector)
// ============================================================================

#ifdef __AVX512F__

static void MatMulF32_AVX512(const float* A, const float* B, float* C,
                              size_t M, size_t N, size_t K) {
    std::memset(C, 0, M * N * sizeof(float));
    
    for (size_t i = 0; i < M; ++i) {
        for (size_t k = 0; k < K; ++k) {
            float a = A[i * K + k];
            __m512 a_vec = _mm512_set1_ps(a);
            
            size_t j = 0;
            for (; j + 16 <= N; j += 16) {
                __m512 b_vec = _mm512_loadu_ps(&B[k * N + j]);
                __m512 c_vec = _mm512_loadu_ps(&C[i * N + j]);
                c_vec = _mm512_fmadd_ps(a_vec, b_vec, c_vec);
                _mm512_storeu_ps(&C[i * N + j], c_vec);
            }
            
            // Scalar remainder
            for (; j < N; ++j) {
                C[i * N + j] += a * B[k * N + j];
            }
        }
    }
}

static float VecDotF32_AVX512(const float* A, const float* B, size_t N) {
    __m512 sum_vec = _mm512_setzero_ps();
    size_t i = 0;
    
    for (; i + 16 <= N; i += 16) {
        __m512 a = _mm512_loadu_ps(&A[i]);
        __m512 b = _mm512_loadu_ps(&B[i]);
        sum_vec = _mm512_fmadd_ps(a, b, sum_vec);
    }
    
    float sum = _mm512_reduce_add_ps(sum_vec);
    
    for (; i < N; ++i) {
        sum += A[i] * B[i];
    }
    
    return sum;
}

static void VecAddF32_AVX512(const float* A, const float* B, float* C, size_t N) {
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

static void VecScaleF32_AVX512(const float* X, float scale, float* Y, size_t N) {
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

static void VecMulF32_AVX512(const float* A, const float* B, float* C, size_t N) {
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

#endif // __AVX512F__

// ============================================================================
// Dispatch Implementation
// ============================================================================

void KernelDispatch::MatMulF32(
    const float* A, const float* B, float* C,
    size_t M, size_t N, size_t K) {
    
#ifdef __AVX512F__
    if (KernelCapabilities::Get().hasAVX512F) {
        MatMulF32_AVX512(A, B, C, M, N, K);
        return;
    }
#endif
    MatMulF32_Scalar(A, B, C, M, N, K);
}

float KernelDispatch::VecDotF32(
    const float* A, const float* B, size_t N) {
    
#ifdef __AVX512F__
    if (KernelCapabilities::Get().hasAVX512F) {
        return VecDotF32_AVX512(A, B, N);
    }
#endif
    return VecDotF32_Scalar(A, B, N);
}

void KernelDispatch::VecAddF32(
    const float* A, const float* B, float* C, size_t N) {
    
#ifdef __AVX512F__
    if (KernelCapabilities::Get().hasAVX512F) {
        VecAddF32_AVX512(A, B, C, N);
        return;
    }
#endif
    VecAddF32_Scalar(A, B, C, N);
}

void KernelDispatch::VecScaleF32(
    const float* X, float scale, float* Y, size_t N) {
    
#ifdef __AVX512F__
    if (KernelCapabilities::Get().hasAVX512F) {
        VecScaleF32_AVX512(X, scale, Y, N);
        return;
    }
#endif
    VecScaleF32_Scalar(X, scale, Y, N);
}

void KernelDispatch::VecMulF32(
    const float* A, const float* B, float* C, size_t N) {
    
#ifdef __AVX512F__
    if (KernelCapabilities::Get().hasAVX512F) {
        VecMulF32_AVX512(A, B, C, N);
        return;
    }
#endif
    VecMulF32_Scalar(A, B, C, N);
}

void KernelDispatch::SoftmaxF32(
    const float* X, float* Y, size_t N) {
    SoftmaxF32_Scalar(X, Y, N);  // TODO: AVX512 softmax
}

void KernelDispatch::RMSNormF32(
    const float* X, const float* weight, float eps,
    float* Y, size_t N) {
    RMSNormF32_Scalar(X, weight, eps, Y, N);  // TODO: AVX512 RMSNorm
}

void KernelDispatch::SiLUF32(
    const float* X, float* Y, size_t N) {
    SiLUF32_Scalar(X, Y, N);  // TODO: AVX512 SiLU
}

void KernelDispatch::GELUF32(
    const float* X, float* Y, size_t N) {
    GELUF32_Scalar(X, Y, N);  // TODO: AVX512 GELU
}

void KernelDispatch::AttentionQKF32(
    const float* Q, const float* K, float* scores,
    size_t seq_len, size_t head_dim, float scale) {
    AttentionQKF32_Scalar(Q, K, scores, seq_len, head_dim, scale);  // TODO: AVX512
}

void KernelDispatch::AttentionSoftmaxVF32(
    const float* scores, const float* V, float* output,
    size_t seq_len, size_t head_dim) {
    AttentionSoftmaxVF32_Scalar(scores, V, output, seq_len, head_dim);  // TODO: AVX512
}

} // namespace Runtime
} // namespace RawrXD
