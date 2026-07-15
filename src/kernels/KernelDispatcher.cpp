//=============================================================================
// RawrXD KernelDispatcher Implementation
// Phase 21 - Runtime CPU Detection + Zero-Overhead Dispatch
//=============================================================================
#include "RawrXD_Kernels.hpp"
#include <intrin.h>
#include <windows.h>
#include <cmath>

namespace RawrXD {
namespace Kernels {

//=============================================================================
// CPU Feature Detection
//=============================================================================

void KernelDispatcher::detect_cpu_features() {
    if (m_initialized) return;

    int cpuInfo[4] = {0};
    
    // Check max supported function
    __cpuid(cpuInfo, 0);
    int nIds = cpuInfo[0];
    
    if (nIds >= 1) {
        __cpuid(cpuInfo, 1);
        m_has_avx2 = (cpuInfo[2] & (1 << 28)) != 0;  // AVX
        m_has_fma  = (cpuInfo[2] & (1 << 12)) != 0;  // FMA3
    }
    
    if (nIds >= 7) {
        __cpuidex(cpuInfo, 7, 0);
        m_has_avx512 = (cpuInfo[1] & (1 << 16)) != 0;  // AVX-512F
    }
    
    // OS support check for AVX-512
    if (m_has_avx512) {
        // Verify OS has enabled AVX-512 state
        ULONG64 featureMask = GetEnabledXStateFeatures();
        if ((featureMask & XSTATE_MASK_AVX512) == 0) {
            m_has_avx512 = false;
        }
    }
    
    m_initialized = true;
}

KernelDispatcher& KernelDispatcher::instance() {
    static KernelDispatcher dispatcher;
    return dispatcher;
}

//=============================================================================
// LoRA Dispatch
//=============================================================================

void KernelDispatcher::apply_lora(
    float* output,
    const float* input,
    const float* weights,
    int32_t rows,
    int32_t cols,
    float alpha,
    KernelVariant variant
) {
    // Validate alignment
    if ((reinterpret_cast<uintptr_t>(output) & 63) != 0 ||
        (reinterpret_cast<uintptr_t>(input) & 63) != 0 ||
        (reinterpret_cast<uintptr_t>(weights) & 63) != 0) {
        // Fall back to C++ implementation for unaligned buffers
        for (int i = 0; i < rows * cols; ++i) {
            output[i] = input[i] + alpha * weights[i];
        }
        return;
    }
    
    // Dispatch based on variant and CPU features
    switch (variant) {
        case KernelVariant::Optimized:
            ApplyLoRA_Fixed(output, input, weights, rows, cols, alpha);
            break;
            
        case KernelVariant::Baseline:
            ApplyLoRA(output, input, weights, rows, cols, alpha);
            break;
            
        case KernelVariant::Auto:
        default:
            if (m_has_avx512) {
                ApplyLoRA_Fixed(output, input, weights, rows, cols, alpha);
            } else {
                ApplyLoRA(output, input, weights, rows, cols, alpha);
            }
            break;
    }
}

//=============================================================================
// MatMul Dispatch
//=============================================================================

void KernelDispatcher::matmul(
    float* C,
    const float* A,
    const float* B,
    int32_t M,
    int32_t N,
    int32_t K,
    KernelVariant variant
) {
    if (m_has_avx512 && variant != KernelVariant::Baseline) {
        MatMul_AVX512(C, A, B, M, N, K);
    } else {
        // Reference C++ implementation
        for (int i = 0; i < M; ++i) {
            for (int j = 0; j < N; ++j) {
                float sum = 0.0f;
                for (int k = 0; k < K; ++k) {
                    sum += A[i * K + k] * B[k * N + j];
                }
                C[i * N + j] = sum;
            }
        }
    }
}

//=============================================================================
// RMSNorm Dispatch
//=============================================================================

void KernelDispatcher::rmsnorm(
    float* output,
    const float* input,
    const float* weight,
    int32_t N,
    float eps,
    KernelVariant variant
) {
    if (m_has_avx512 && variant != KernelVariant::Baseline) {
        RMSNorm_Fused(output, input, weight, N, eps);
    } else {
        // Reference C++ implementation
        float ss = 0.0f;
        for (int i = 0; i < N; ++i) {
            ss += input[i] * input[i];
        }
        ss /= N;
        ss += eps;
        ss = 1.0f / std::sqrt(ss);
        
        for (int i = 0; i < N; ++i) {
            output[i] = weight[i] * (ss * input[i]);
        }
    }
}

} // namespace Kernels
} // namespace RawrXD
