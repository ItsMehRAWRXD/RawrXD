// tensor_ops.cpp - Functional Tensor Operations Implementation
// ============================================================================

#define RAWRXD_CURRENT_DOMAIN RAWRXD_DOMAIN_CORE_RUNTIME
#include "core_runtime/symbol_ownership.h"
#include "core_runtime/tensor_ops.h"

#include <cmath>
#include <algorithm>
#include <vector>
#include <string>
#include <Windows.h>
#include <immintrin.h>

namespace RawrXD { 
namespace Core {

// ============================================================================
// Tensor Data Structure
// ============================================================================
struct TensorData {
    std::vector<float> data;
    std::vector<size_t> shape;
    size_t GetSize() const {
        size_t size = 1;
        for (auto dim : shape) size *= dim;
        return size;
    }
};

// ============================================================================
// TensorOps Implementation
// ============================================================================
class TensorOps::Impl {
public:
    bool useSIMD = true;
    bool useAVX2 = false;
    
    Impl() {
        // Check CPU features
        int cpuInfo[4];
        __cpuid(cpuInfo, 1);
        useAVX2 = (cpuInfo[2] & (1 << 28)) != 0; // Check AVX bit
        
        // Check for AVX2
        __cpuidex(cpuInfo, 7, 0);
        useAVX2 = useAVX2 && ((cpuInfo[1] & (1 << 5)) != 0);
    }
    
    // Element-wise addition
    bool Add(const float* a, const float* b, float* result, size_t size) {
        if (!a || !b || !result) return false;
        
        if (useAVX2 && size >= 8) {
            // AVX2 implementation
            size_t i = 0;
            for (; i + 8 <= size; i += 8) {
                __m256 va = _mm256_loadu_ps(a + i);
                __m256 vb = _mm256_loadu_ps(b + i);
                __m256 vr = _mm256_add_ps(va, vb);
                _mm256_storeu_ps(result + i, vr);
            }
            // Handle remaining elements
            for (; i < size; ++i) {
                result[i] = a[i] + b[i];
            }
        } else {
            // Scalar implementation
            for (size_t i = 0; i < size; ++i) {
                result[i] = a[i] + b[i];
            }
        }
        return true;
    }
    
    // Element-wise multiplication
    bool Multiply(const float* a, const float* b, float* result, size_t size) {
        if (!a || !b || !result) return false;
        
        if (useAVX2 && size >= 8) {
            size_t i = 0;
            for (; i + 8 <= size; i += 8) {
                __m256 va = _mm256_loadu_ps(a + i);
                __m256 vb = _mm256_loadu_ps(b + i);
                __m256 vr = _mm256_mul_ps(va, vb);
                _mm256_storeu_ps(result + i, vr);
            }
            for (; i < size; ++i) {
                result[i] = a[i] * b[i];
            }
        } else {
            for (size_t i = 0; i < size; ++i) {
                result[i] = a[i] * b[i];
            }
        }
        return true;
    }
    
    // Matrix multiplication: C = A * B
    bool MatMul(const float* a, const float* b, float* c,
                size_t m, size_t k, size_t n) {
        if (!a || !b || !c) return false;
        
        // Initialize C to zero
        std::memset(c, 0, m * n * sizeof(float));
        
        // Simple triple-loop matrix multiplication
        for (size_t i = 0; i < m; ++i) {
            for (size_t l = 0; l < k; ++l) {
                float aVal = a[i * k + l];
                for (size_t j = 0; j < n; ++j) {
                    c[i * n + j] += aVal * b[l * n + j];
                }
            }
        }
        return true;
    }
    
    // ReLU activation
    bool ReLU(const float* input, float* output, size_t size) {
        if (!input || !output) return false;
        
        if (useAVX2 && size >= 8) {
            __m256 zero = _mm256_setzero_ps();
            size_t i = 0;
            for (; i + 8 <= size; i += 8) {
                __m256 v = _mm256_loadu_ps(input + i);
                __m256 r = _mm256_max_ps(v, zero);
                _mm256_storeu_ps(output + i, r);
            }
            for (; i < size; ++i) {
                output[i] = std::max(0.0f, input[i]);
            }
        } else {
            for (size_t i = 0; i < size; ++i) {
                output[i] = std::max(0.0f, input[i]);
            }
        }
        return true;
    }
    
    // GELU activation
    bool GELU(const float* input, float* output, size_t size) {
        if (!input || !output) return false;
        
        const float sqrt2OverPi = 0.7978845608f;
        for (size_t i = 0; i < size; ++i) {
            float x = input[i];
            float cdf = 0.5f * (1.0f + std::tanh(sqrt2OverPi * (x + 0.044715f * x * x * x)));
            output[i] = x * cdf;
        }
        return true;
    }
    
    // Softmax
    bool Softmax(const float* input, float* output, size_t size) {
        if (!input || !output) return false;
        
        // Find max for numerical stability
        float maxVal = input[0];
        for (size_t i = 1; i < size; ++i) {
            maxVal = std::max(maxVal, input[i]);
        }
        
        // Compute exp and sum
        float sum = 0.0f;
        for (size_t i = 0; i < size; ++i) {
            output[i] = std::exp(input[i] - maxVal);
            sum += output[i];
        }
        
        // Normalize
        if (sum > 0.0f) {
            float invSum = 1.0f / sum;
            for (size_t i = 0; i < size; ++i) {
                output[i] *= invSum;
            }
        }
        return true;
    }
    
    // Layer normalization
    bool LayerNorm(const float* input, float* output, size_t size,
                   float epsilon = 1e-5f) {
        if (!input || !output) return false;
        
        // Compute mean
        float mean = 0.0f;
        for (size_t i = 0; i < size; ++i) {
            mean += input[i];
        }
        mean /= size;
        
        // Compute variance
        float variance = 0.0f;
        for (size_t i = 0; i < size; ++i) {
            float diff = input[i] - mean;
            variance += diff * diff;
        }
        variance /= size;
        
        // Normalize
        float stdDev = std::sqrt(variance + epsilon);
        float invStdDev = 1.0f / stdDev;
        for (size_t i = 0; i < size; ++i) {
            output[i] = (input[i] - mean) * invStdDev;
        }
        return true;
    }
    
    // Transpose
    bool Transpose(const float* input, float* output,
                   size_t rows, size_t cols) {
        if (!input || !output) return false;
        
        for (size_t i = 0; i < rows; ++i) {
            for (size_t j = 0; j < cols; ++j) {
                output[j * rows + i] = input[i * cols + j];
            }
        }
        return true;
    }
    
    // Scale
    bool Scale(float* data, size_t size, float scale) {
        if (!data) return false;
        
        if (useAVX2 && size >= 8) {
            __m256 vscale = _mm256_set1_ps(scale);
            size_t i = 0;
            for (; i + 8 <= size; i += 8) {
                __m256 v = _mm256_loadu_ps(data + i);
                v = _mm256_mul_ps(v, vscale);
                _mm256_storeu_ps(data + i, v);
            }
            for (; i < size; ++i) {
                data[i] *= scale;
            }
        } else {
            for (size_t i = 0; i < size; ++i) {
                data[i] *= scale;
            }
        }
        return true;
    }
};

// ============================================================================
// TensorOps Public Interface
// ============================================================================
TensorOps::TensorOps() : pImpl(new Impl()) {}
TensorOps::~TensorOps() = default;
TensorOps::TensorOps(TensorOps&&) noexcept = default;
TensorOps& TensorOps::operator=(TensorOps&&) noexcept = default;

bool TensorOps::Add(const float* a, const float* b, float* result, size_t size) {
    return pImpl->Add(a, b, result, size);
}

bool TensorOps::Multiply(const float* a, const float* b, float* result, size_t size) {
    return pImpl->Multiply(a, b, result, size);
}

bool TensorOps::MatMul(const float* a, const float* b, float* c,
                       size_t m, size_t k, size_t n) {
    return pImpl->MatMul(a, b, c, m, k, n);
}

bool TensorOps::ReLU(const float* input, float* output, size_t size) {
    return pImpl->ReLU(input, output, size);
}

bool TensorOps::GELU(const float* input, float* output, size_t size) {
    return pImpl->GELU(input, output, size);
}

bool TensorOps::Softmax(const float* input, float* output, size_t size) {
    return pImpl->Softmax(input, output, size);
}

bool TensorOps::LayerNorm(const float* input, float* output, size_t size, float epsilon) {
    return pImpl->LayerNorm(input, output, size, epsilon);
}

bool TensorOps::Transpose(const float* input, float* output, size_t rows, size_t cols) {
    return pImpl->Transpose(input, output, rows, cols);
}

bool TensorOps::Scale(float* data, size_t size, float scale) {
    return pImpl->Scale(data, size, scale);
}

// ============================================================================
// C API for external linking
// ============================================================================
extern "C" {
    void* TensorOps_Create() {
        return new TensorOps();
    }
    
    void TensorOps_Destroy(void* ops) {
        delete static_cast<TensorOps*>(ops);
    }
    
    int TensorOps_Add(void* ops, const float* a, const float* b, float* result, size_t size) {
        if (!ops) return -1;
        return static_cast<TensorOps*>(ops)->Add(a, b, result, size) ? 0 : -1;
    }
    
    int TensorOps_Multiply(void* ops, const float* a, const float* b, float* result, size_t size) {
        if (!ops) return -1;
        return static_cast<TensorOps*>(ops)->Multiply(a, b, result, size) ? 0 : -1;
    }
    
    int TensorOps_MatMul(void* ops, const float* a, const float* b, float* c,
                         size_t m, size_t k, size_t n) {
        if (!ops) return -1;
        return static_cast<TensorOps*>(ops)->MatMul(a, b, c, m, k, n) ? 0 : -1;
    }
    
    int TensorOps_ReLU(void* ops, const float* input, float* output, size_t size) {
        if (!ops) return -1;
        return static_cast<TensorOps*>(ops)->ReLU(input, output, size) ? 0 : -1;
    }
    
    int TensorOps_GELU(void* ops, const float* input, float* output, size_t size) {
        if (!ops) return -1;
        return static_cast<TensorOps*>(ops)->GELU(input, output, size) ? 0 : -1;
    }
    
    int TensorOps_Softmax(void* ops, const float* input, float* output, size_t size) {
        if (!ops) return -1;
        return static_cast<TensorOps*>(ops)->Softmax(input, output, size) ? 0 : -1;
    }
    
    int TensorOps_LayerNorm(void* ops, const float* input, float* output, size_t size) {
        if (!ops) return -1;
        return static_cast<TensorOps*>(ops)->LayerNorm(input, output, size) ? 0 : -1;
    }
}

}} // namespace RawrXD::Core
