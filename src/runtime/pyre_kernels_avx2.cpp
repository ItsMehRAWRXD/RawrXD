// ============================================================================
// pyre_kernels_avx2.cpp — Pyre Compute AVX2/AVX-512 Kernel Implementations
// ============================================================================
// High-performance inference kernels for Gold runtime
// Features: AVX2/AVX-512, FMA, cache-friendly blocking, branchless where possible
// ============================================================================

#include <immintrin.h>
#include <intrin.h>  // For __cpuid, __cpuidex
#include <cstdint>
#include <cstddef>
#include <cmath>
#include <cstring>

// CPU feature detection
static bool g_avx2Initialized = false;
static bool g_hasAVX2 = false;
static bool g_hasAVX512F = false;
static bool g_hasFMA = false;

// Initialize CPU features
static void InitCpuFeatures() {
    if (g_avx2Initialized) return;
    
    int cpuInfo[4] = {0};
    __cpuid(cpuInfo, 1);
    
    // Check AVX (bit 28 of ECX)
    bool hasAVX = (cpuInfo[2] & (1 << 28)) != 0;
    
    // Check FMA (bit 12 of ECX)
    g_hasFMA = (cpuInfo[2] & (1 << 12)) != 0;
    
    // Check AVX2 (bit 5 of EBX from CPUID leaf 7)
    int cpuInfo7[4] = {0};
    __cpuidex(cpuInfo7, 7, 0);
    g_hasAVX2 = hasAVX && ((cpuInfo7[1] & (1 << 5)) != 0);
    
    // Check AVX-512F (bit 16 of EBX from CPUID leaf 7)
    g_hasAVX512F = (cpuInfo7[1] & (1 << 16)) != 0;
    
    g_avx2Initialized = true;
}

// ============================================================================
// GEMM: General Matrix Multiply (C = A * B)
// ============================================================================

extern "C" {

void asm_pyre_gemm_fp32(const float* A, const float* B, float* C, 
                        int M, int N, int K, float alpha, float beta) {
    InitCpuFeatures();
    
    // Blocking parameters for L1 cache
    constexpr int BM = 32;  // Block size M
    constexpr int BN = 32;  // Block size N  
    constexpr int BK = 32;  // Block size K
    
    // Initialize C with beta * C
    if (beta != 1.0f) {
        for (int i = 0; i < M * N; i++) {
            C[i] *= beta;
        }
    }
    
    // Blocked GEMM
    for (int m0 = 0; m0 < M; m0 += BM) {
        int mMax = (m0 + BM < M) ? m0 + BM : M;
        
        for (int n0 = 0; n0 < N; n0 += BN) {
            int nMax = (n0 + BN < N) ? n0 + BN : N;
            
            // Accumulator for this block
            float accum[BM * BN];
            memset(accum, 0, sizeof(accum));
            
            for (int k0 = 0; k0 < K; k0 += BK) {
                int kMax = (k0 + BK < K) ? k0 + BK : K;
                
                // Micro-kernel
                for (int m = m0; m < mMax; m++) {
                    for (int n = n0; n < nMax; n++) {
                        float sum = accum[(m - m0) * BN + (n - n0)];
                        
                        if (g_hasAVX2 && g_hasFMA) {
                            // AVX2+FMA path - process 8 elements at a time
                            __m256 sumVec = _mm256_setzero_ps();
                            
                            int k = k0;
                            for (; k <= kMax - 8; k += 8) {
                                __m256 aVec = _mm256_loadu_ps(&A[m * K + k]);
                                
                                // Gather B elements
                                float bVals[8];
                                for (int kk = 0; kk < 8; kk++) {
                                    bVals[kk] = B[(k + kk) * N + n];
                                }
                                __m256 bVec = _mm256_loadu_ps(bVals);
                                
                                sumVec = _mm256_fmadd_ps(aVec, bVec, sumVec);
                            }
                            
                            // Horizontal sum
                            float temp[8];
                            _mm256_storeu_ps(temp, sumVec);
                            for (int i = 0; i < 8; i++) sum += temp[i];
                            
                            // Remainder
                            for (; k < kMax; k++) {
                                sum += A[m * K + k] * B[k * N + n];
                            }
                        } else {
                            // Scalar fallback
                            for (int k = k0; k < kMax; k++) {
                                sum += A[m * K + k] * B[k * N + n];
                            }
                        }
                        
                        accum[(m - m0) * BN + (n - n0)] = sum;
                    }
                }
            }
            
            // Write back with alpha scaling
            for (int m = m0; m < mMax; m++) {
                for (int n = n0; n < nMax; n++) {
                    C[m * N + n] += alpha * accum[(m - m0) * BN + (n - n0)];
                }
            }
        }
    }
}

// ============================================================================
// GEMV: General Matrix-Vector Multiply (y = A * x)
// ============================================================================

void asm_pyre_gemv_fp32(const float* A, const float* x, float* y,
                        int M, int N, float alpha, float beta) {
    InitCpuFeatures();
    
    for (int i = 0; i < M; i++) {
        float sum = 0.0f;
        
        if (g_hasAVX2 && g_hasFMA) {
            __m256 sumVec = _mm256_setzero_ps();
            
            int j = 0;
            for (; j <= N - 8; j += 8) {
                __m256 aVec = _mm256_loadu_ps(&A[i * N + j]);
                __m256 xVec = _mm256_loadu_ps(&x[j]);
                sumVec = _mm256_fmadd_ps(aVec, xVec, sumVec);
            }
            
            // Horizontal sum
            float temp[8];
            _mm256_storeu_ps(temp, sumVec);
            for (int k = 0; k < 8; k++) sum += temp[k];
            
            // Remainder
            for (; j < N; j++) {
                sum += A[i * N + j] * x[j];
            }
        } else {
            for (int j = 0; j < N; j++) {
                sum += A[i * N + j] * x[j];
            }
        }
        
        y[i] = alpha * sum + beta * y[i];
    }
}

// ============================================================================
// RMSNorm: Root Mean Square Normalization
// ============================================================================

void asm_pyre_rmsnorm(const float* input, float* output, 
                      int dim, float eps, const float* weight) {
    InitCpuFeatures();
    
    // Compute RMS
    float sum_sq = 0.0f;
    
    if (g_hasAVX2) {
        __m256 sumVec = _mm256_setzero_ps();
        
        int i = 0;
        for (; i <= dim - 8; i += 8) {
            __m256 val = _mm256_loadu_ps(&input[i]);
            sumVec = _mm256_fmadd_ps(val, val, sumVec);
        }
        
        float temp[8];
        _mm256_storeu_ps(temp, sumVec);
        for (int k = 0; k < 8; k++) sum_sq += temp[k];
        
        for (; i < dim; i++) {
            sum_sq += input[i] * input[i];
        }
    } else {
        for (int i = 0; i < dim; i++) {
            sum_sq += input[i] * input[i];
        }
    }
    
    float rms = sqrtf(sum_sq / dim + eps);
    float inv_rms = 1.0f / rms;
    
    // Normalize and apply weight
    if (g_hasAVX2 && weight) {
        __m256 invRmsVec = _mm256_set1_ps(inv_rms);
        
        int i = 0;
        for (; i <= dim - 8; i += 8) {
            __m256 inVec = _mm256_loadu_ps(&input[i]);
            __m256 wVec = _mm256_loadu_ps(&weight[i]);
            __m256 normVec = _mm256_mul_ps(inVec, invRmsVec);
            __m256 outVec = _mm256_mul_ps(normVec, wVec);
            _mm256_storeu_ps(&output[i], outVec);
        }
        
        for (; i < dim; i++) {
            output[i] = input[i] * inv_rms * weight[i];
        }
    } else if (g_hasAVX2) {
        __m256 invRmsVec = _mm256_set1_ps(inv_rms);
        
        int i = 0;
        for (; i <= dim - 8; i += 8) {
            __m256 inVec = _mm256_loadu_ps(&input[i]);
            __m256 outVec = _mm256_mul_ps(inVec, invRmsVec);
            _mm256_storeu_ps(&output[i], outVec);
        }
        
        for (; i < dim; i++) {
            output[i] = input[i] * inv_rms;
        }
    } else {
        for (int i = 0; i < dim; i++) {
            float val = input[i] * inv_rms;
            if (weight) val *= weight[i];
            output[i] = val;
        }
    }
}

// ============================================================================
// SiLU: Sigmoid Linear Unit
// ============================================================================

static inline float silu_scalar(float x) {
    // SiLU(x) = x * sigmoid(x) = x / (1 + exp(-x))
    return x / (1.0f + expf(-x));
}

void asm_pyre_silu(const float* input, float* output, int dim) {
    InitCpuFeatures();
    
    if (g_hasAVX2) {
        int i = 0;
        for (; i <= dim - 8; i += 8) {
            __m256 x = _mm256_loadu_ps(&input[i]);
            
            // Compute exp(-x)
            __m256 negX = _mm256_sub_ps(_mm256_setzero_ps(), x);
            // Approximate exp using fast method
            __m256 expNegX = _mm256_exp_ps(negX); // Requires SVML
            
            // sigmoid = 1 / (1 + exp(-x))
            __m256 one = _mm256_set1_ps(1.0f);
            __m256 denom = _mm256_add_ps(one, expNegX);
            __m256 sigmoid = _mm256_div_ps(one, denom);
            
            // SiLU = x * sigmoid
            __m256 result = _mm256_mul_ps(x, sigmoid);
            _mm256_storeu_ps(&output[i], result);
        }
        
        // Remainder
        for (; i < dim; i++) {
            output[i] = silu_scalar(input[i]);
        }
    } else {
        for (int i = 0; i < dim; i++) {
            output[i] = silu_scalar(input[i]);
        }
    }
}

// ============================================================================
// Softmax: Numerically Stable Softmax
// ============================================================================

void asm_pyre_softmax(const float* input, float* output, int dim) {
    InitCpuFeatures();
    
    // Find max for numerical stability
    float max_val = input[0];
    
    if (g_hasAVX2) {
        __m256 maxVec = _mm256_set1_ps(max_val);
        
        int i = 1;
        for (; i <= dim - 8; i += 8) {
            __m256 val = _mm256_loadu_ps(&input[i]);
            maxVec = _mm256_max_ps(maxVec, val);
        }
        
        float temp[8];
        _mm256_storeu_ps(temp, maxVec);
        for (int k = 0; k < 8; k++) {
            if (temp[k] > max_val) max_val = temp[k];
        }
        
        for (; i < dim; i++) {
            if (input[i] > max_val) max_val = input[i];
        }
    } else {
        for (int i = 1; i < dim; i++) {
            if (input[i] > max_val) max_val = input[i];
        }
    }
    
    // Compute exp(x - max) and sum
    float sum = 0.0f;
    
    if (g_hasAVX2) {
        __m256 maxValVec = _mm256_set1_ps(max_val);
        __m256 sumVec = _mm256_setzero_ps();
        
        int i = 0;
        for (; i <= dim - 8; i += 8) {
            __m256 val = _mm256_loadu_ps(&input[i]);
            __m256 shifted = _mm256_sub_ps(val, maxValVec);
            __m256 expVal = _mm256_exp_ps(shifted); // SVML
            _mm256_storeu_ps(&output[i], expVal);
            sumVec = _mm256_add_ps(sumVec, expVal);
        }
        
        float temp[8];
        _mm256_storeu_ps(temp, sumVec);
        for (int k = 0; k < 8; k++) sum += temp[k];
        
        for (; i < dim; i++) {
            float exp_val = expf(input[i] - max_val);
            output[i] = exp_val;
            sum += exp_val;
        }
    } else {
        for (int i = 0; i < dim; i++) {
            float exp_val = expf(input[i] - max_val);
            output[i] = exp_val;
            sum += exp_val;
        }
    }
    
    // Normalize
    float inv_sum = 1.0f / sum;
    
    if (g_hasAVX2) {
        __m256 invSumVec = _mm256_set1_ps(inv_sum);
        
        int i = 0;
        for (; i <= dim - 8; i += 8) {
            __m256 val = _mm256_loadu_ps(&output[i]);
            __m256 norm = _mm256_mul_ps(val, invSumVec);
            _mm256_storeu_ps(&output[i], norm);
        }
        
        for (; i < dim; i++) {
            output[i] *= inv_sum;
        }
    } else {
        for (int i = 0; i < dim; i++) {
            output[i] *= inv_sum;
        }
    }
}

// ============================================================================
// RoPE: Rotary Positional Embedding
// ============================================================================

void asm_pyre_rope(float* vec, int dim, int pos, float base, float scale) {
    InitCpuFeatures();
    
    // Apply RoPE to pairs of dimensions
    for (int i = 0; i < dim / 2; i++) {
        int j = i + dim / 2;
        
        float freq = powf(base, -2.0f * i / dim);
        float angle = pos * freq / scale;
        
        float cos_a = cosf(angle);
        float sin_a = sinf(angle);
        
        float x0 = vec[i];
        float x1 = vec[j];
        
        vec[i] = x0 * cos_a - x1 * sin_a;
        vec[j] = x0 * sin_a + x1 * cos_a;
    }
}

// ============================================================================
// Element-wise Add
// ============================================================================

void asm_pyre_add_fp32(const float* a, const float* b, float* out, int dim) {
    InitCpuFeatures();
    
    if (g_hasAVX2) {
        int i = 0;
        for (; i <= dim - 8; i += 8) {
            __m256 va = _mm256_loadu_ps(&a[i]);
            __m256 vb = _mm256_loadu_ps(&b[i]);
            __m256 vc = _mm256_add_ps(va, vb);
            _mm256_storeu_ps(&out[i], vc);
        }
        
        for (; i < dim; i++) {
            out[i] = a[i] + b[i];
        }
    } else {
        for (int i = 0; i < dim; i++) {
            out[i] = a[i] + b[i];
        }
    }
}

// ============================================================================
// Element-wise Multiply
// ============================================================================

void asm_pyre_mul_fp32(const float* a, const float* b, float* out, int dim) {
    InitCpuFeatures();
    
    if (g_hasAVX2) {
        int i = 0;
        for (; i <= dim - 8; i += 8) {
            __m256 va = _mm256_loadu_ps(&a[i]);
            __m256 vb = _mm256_loadu_ps(&b[i]);
            __m256 vc = _mm256_mul_ps(va, vb);
            _mm256_storeu_ps(&out[i], vc);
        }
        
        for (; i < dim; i++) {
            out[i] = a[i] * b[i];
        }
    } else {
        for (int i = 0; i < dim; i++) {
            out[i] = a[i] * b[i];
        }
    }
}

// ============================================================================
// Embedding Lookup
// ============================================================================

void asm_pyre_embedding_lookup(const float* embedding_table, int token_id,
                               int embedding_dim, float* output) {
    // Simple lookup and copy
    const float* src = embedding_table + token_id * embedding_dim;
    
    if (g_hasAVX2) {
        int i = 0;
        for (; i <= embedding_dim - 8; i += 8) {
            __m256 val = _mm256_loadu_ps(&src[i]);
            _mm256_storeu_ps(&output[i], val);
        }
        
        for (; i < embedding_dim; i++) {
            output[i] = src[i];
        }
    } else {
        memcpy(output, src, embedding_dim * sizeof(float));
    }
}

} // extern "C"
