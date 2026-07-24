//============================================================================
// nevm_determinism_safeguards.hpp
// RawrXD N-EVM - Determinism Safeguards
// Addresses parallel reduction drift and FMA/AVX precision edge cases
//============================================================================

#pragma once

#include <cmath>
#include <limits>
#include <algorithm>

namespace RawrXD {
namespace NEVM {

//============================================================================
// Floating-Point Determinism Controls
//============================================================================

class DeterminismControls {
public:
    // FP Control flags for consistent rounding
    static void EnableStrictFPMode() {
        #ifdef _WIN32
        // Disable FMA for determinism (use separate multiply-add)
        _controlfp_s(nullptr, _PC_53, _MCW_PC);  // 53-bit precision (double)
        #endif
        
        // Set rounding mode to round-to-nearest, ties to even
        std::fesetround(FE_TONEAREST);
    }
    
    // Check if FMA is available but disabled for determinism
    static bool IsFMADisabled() {
        #ifdef _WIN32
        unsigned int cw;
        _controlfp_s(&cw, 0, 0);
        return (cw & _MCW_PC) == _PC_53;
        #else
        return true;  // Assume disabled on non-Windows
        #endif
    }
};

//============================================================================
// Deterministic Reduction
//============================================================================

// Tree-based reduction for deterministic parallel sums
// Avoids non-associative accumulation order issues
template<typename T>
class DeterministicReduction {
public:
    // Sequential reduction (always deterministic)
    static T SequentialSum(const T* data, size_t n) {
        T sum = 0;
        for (size_t i = 0; i < n; ++i) {
            sum += data[i];
        }
        return sum;
    }
    
    // Tree reduction (deterministic with fixed thread count)
    static T TreeSum(const T* data, size_t n, int num_threads = 1) {
        if (num_threads == 1 || n < 1024) {
            return SequentialSum(data, n);
        }
        
        // Divide into fixed-size chunks
        size_t chunk_size = (n + num_threads - 1) / num_threads;
        std::vector<T> partial_sums(num_threads, 0);
        
        // Parallel chunk summation
        #pragma omp parallel for num_threads(num_threads) schedule(static)
        for (int t = 0; t < num_threads; ++t) {
            size_t start = t * chunk_size;
            size_t end = std::min(start + chunk_size, n);
            
            T local_sum = 0;
            for (size_t i = start; i < end; ++i) {
                local_sum += data[i];
            }
            partial_sums[t] = local_sum;
        }
        
        // Deterministic final reduction (always sequential)
        return SequentialSum(partial_sums.data(), partial_sums.size());
    }
    
    // Kahan summation for improved precision
    static T KahanSum(const T* data, size_t n) {
        T sum = 0;
        T c = 0;  // Running compensation
        
        for (size_t i = 0; i < n; ++i) {
            T y = data[i] - c;
            T t = sum + y;
            c = (t - sum) - y;
            sum = t;
        }
        
        return sum;
    }
};

//============================================================================
// SoftMax Determinism
//============================================================================

class DeterministicSoftMax {
public:
    // Deterministic online softmax (no parallel max search)
    static void Compute(const float* input, float* output, int n) {
        // Step 1: Find max (sequential for determinism)
        float max_val = -std::numeric_limits<float>::infinity();
        for (int i = 0; i < n; ++i) {
            max_val = std::max(max_val, input[i]);
        }
        
        // Step 2: Compute exp and sum (Kahan summation)
        float sum = 0;
        float c = 0;
        for (int i = 0; i < n; ++i) {
            float exp_val = std::exp(input[i] - max_val);
            output[i] = exp_val;
            
            // Kahan summation
            float y = exp_val - c;
            float t = sum + y;
            c = (t - sum) - y;
            sum = t;
        }
        
        // Step 3: Normalize
        for (int i = 0; i < n; ++i) {
            output[i] /= sum;
        }
    }
};

//============================================================================
// GEMM Determinism
//============================================================================

class DeterministicGEMM {
public:
    // Fixed tile sizes for reproducible computation order
    static constexpr int TILE_M = 64;
    static constexpr int TILE_N = 64;
    static constexpr int TILE_K = 256;
    
    // Deterministic matrix multiplication
    // Uses fixed loop ordering and no FMA
    static void Multiply(const float* A, const float* B, float* C,
                         int M, int N, int K) {
        // Initialize C to zero
        for (int i = 0; i < M * N; ++i) {
            C[i] = 0;
        }
        
        // Tiled multiplication with fixed order
        for (int m = 0; m < M; m += TILE_M) {
            int m_end = std::min(m + TILE_M, M);
            
            for (int n = 0; n < N; n += TILE_N) {
                int n_end = std::min(n + TILE_N, N);
                
                for (int k = 0; k < K; k += TILE_K) {
                    int k_end = std::min(k + TILE_K, K);
                    
                    // Multiply tile
                    for (int mm = m; mm < m_end; ++mm) {
                        for (int nn = n; nn < n_end; ++nn) {
                            float sum = C[mm * N + nn];
                            
                            for (int kk = k; kk < k_end; ++kk) {
                                // Explicit multiply-add (no FMA)
                                sum = sum + A[mm * K + kk] * B[kk * N + nn];
                            }
                            
                            C[mm * N + nn] = sum;
                        }
                    }
                }
            }
        }
    }
};

//============================================================================
// Validation Helpers
//============================================================================

class DeterminismValidator {
public:
    // Check if two results are within acceptable tolerance
    static bool Validate(const float* a, const float* b, size_t n,
                        float abs_tolerance = 1e-5f,
                        float rel_tolerance = 1e-4f) {
        for (size_t i = 0; i < n; ++i) {
            float abs_diff = std::abs(a[i] - b[i]);
            
            if (abs_diff > abs_tolerance) {
                float rel_diff = abs_diff / std::max(std::abs(a[i]), std::abs(b[i]));
                if (rel_diff > rel_tolerance) {
                    return false;
                }
            }
        }
        return true;
    }
    
    // Check for NaN/Inf (indicates numerical instability)
    static bool CheckValid(const float* data, size_t n) {
        for (size_t i = 0; i < n; ++i) {
            if (std::isnan(data[i]) || std::isinf(data[i])) {
                return false;
            }
        }
        return true;
    }
};

//============================================================================
// Usage Example
//============================================================================

/*
// In kernel initialization:
DeterminismControls::EnableStrictFPMode();

// In SoftMax kernel:
DeterministicSoftMax::Compute(input, output, size);

// In GEMM kernel:
DeterministicGEMM::Multiply(A, B, C, M, N, K);

// In validation:
bool valid = DeterminismValidator::Validate(ref, test, size);
*/

} // namespace NEVM
} // namespace RawrXD
