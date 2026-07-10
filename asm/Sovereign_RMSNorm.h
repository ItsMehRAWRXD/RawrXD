// ============================================================================
// Sovereign_RMSNorm.h - C++ Interface for RMS Normalization Kernel
// ============================================================================
// Production-ready header for RawrXD Transformer
// ============================================================================

#pragma once

#include <cstdint>
#include <cstddef>

#ifdef __cplusplus
extern "C" {
#endif

// ----------------------------------------------------------------------------
// C API
// ----------------------------------------------------------------------------

/**
 * @brief RMS Normalization for F32 tensors (AVX2 optimized)
 * 
 * y = x / sqrt(mean(x^2) + epsilon) * weight
 * 
 * @param input Input tensor (F32)
 * @param output Output tensor (F32)
 * @param weight Weight tensor (F32)
 * @param n_elements Number of elements
 * @param epsilon Small constant for numerical stability
 * @return 0 on success, -1 on error
 */
int rms_norm_f32(float* input, float* output, float* weight,
                 size_t n_elements, float epsilon);

/**
 * @brief In-place RMS Normalization for F32 tensors
 * 
 * @param buffer Input/output tensor (F32)
 * @param weight Weight tensor (F32)
 * @param n_elements Number of elements
 * @param epsilon Small constant for numerical stability
 * @return 0 on success, -1 on error
 */
int rms_norm_f32_inplace(float* buffer, float* weight,
                         size_t n_elements, float epsilon);

// ----------------------------------------------------------------------------
// C++ Wrapper
// ----------------------------------------------------------------------------

#ifdef __cplusplus

#include <vector>
#include <stdexcept>

namespace Sovereign {

/**
 * @brief RMSNorm operation for transformer layers
 */
class RMSNorm {
public:
    /**
     * @brief Construct RMSNorm with weight tensor
     * @param weight Weight tensor (must be F32)
     * @param epsilon Numerical stability constant
     */
    RMSNorm(const std::vector<float>& weight, float epsilon = 1e-6f)
        : weight_(weight), epsilon_(epsilon) {}
    
    /**
     * @brief Apply RMSNorm to input tensor
     * @param input Input tensor (F32)
     * @return Normalized output tensor
     */
    std::vector<float> forward(const std::vector<float>& input) const {
        if (input.size() != weight_.size()) {
            throw std::invalid_argument("Input and weight sizes must match");
        }
        
        std::vector<float> output(input.size());
        
        int result = rms_norm_f32(
            const_cast<float*>(input.data()),
            output.data(),
            const_cast<float*>(weight_.data()),
            input.size(),
            epsilon_
        );
        
        if (result != 0) {
            throw std::runtime_error("RMSNorm computation failed");
        }
        
        return output;
    }
    
    /**
     * @brief Apply RMSNorm in-place
     * @param buffer Input/output tensor (modified in place)
     */
    void forward_inplace(std::vector<float>& buffer) const {
        if (buffer.size() != weight_.size()) {
            throw std::invalid_argument("Buffer and weight sizes must match");
        }
        
        int result = rms_norm_f32_inplace(
            buffer.data(),
            const_cast<float*>(weight_.data()),
            buffer.size(),
            epsilon_
        );
        
        if (result != 0) {
            throw std::runtime_error("RMSNorm computation failed");
        }
    }
    
    size_t size() const { return weight_.size(); }
    float epsilon() const { return epsilon_; }

private:
    std::vector<float> weight_;
    float epsilon_;
};

/**
 * @brief Apply RMSNorm to a tensor slice
 * @tparam T Input type (float)
 * @param input Input data pointer
 * @param output Output data pointer
 * @param weight Weight data pointer
 * @param n_elements Number of elements
 * @param epsilon Numerical stability constant
 */
template<typename T>
inline void apply_rms_norm(T* input, T* output, T* weight,
                           size_t n_elements, float epsilon = 1e-6f) {
    static_assert(std::is_same_v<T, float>, "Only F32 is currently supported");
    
    int result = rms_norm_f32(
        reinterpret_cast<float*>(input),
        reinterpret_cast<float*>(output),
        reinterpret_cast<float*>(weight),
        n_elements,
        epsilon
    );
    
    if (result != 0) {
        throw std::runtime_error("RMSNorm failed");
    }
}

} // namespace Sovereign

#endif // __cplusplus

#ifdef __cplusplus
}
#endif
