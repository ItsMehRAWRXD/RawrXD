/*===========================================================================
 * Deep2Bridge_Quantized.cpp
 * 
 * Implementation of quantized layer integration for Deep2Bridge
 *===========================================================================*/

#include "Deep2Bridge_Quantized.hpp"
#include <cstring>

namespace RawrXD {
namespace Bridge {

/*===========================================================================
 * Deep2QuantizedLinear Implementation
 *===========================================================================*/

Deep2QuantizedLinear::Deep2QuantizedLinear(Deep2QuantizedLinear&& other) noexcept
    : weights_(other.weights_)
    , rows_(other.rows_)
    , cols_(other.cols_)
    , type_(other.type_)
    , initialized_(other.initialized_)
    , impl_(other.impl_)
    , stats_(other.stats_) {
    other.weights_ = {};
    other.rows_ = 0;
    other.cols_ = 0;
    other.type_ = QuantizedLayerType::FP32;
    other.initialized_ = false;
    other.impl_ = {};
}

Deep2QuantizedLinear& Deep2QuantizedLinear::operator=(Deep2QuantizedLinear&& other) noexcept {
    if (this != &other) {
        // Cleanup current implementation
        if (initialized_) {
            switch (type_) {
                case QuantizedLayerType::Q4_K_M:
                    if (impl_.q4km_impl) {
                        delete impl_.q4km_impl;
                    }
                    break;
                default:
                    break;
            }
        }
        
        weights_ = other.weights_;
        rows_ = other.rows_;
        cols_ = other.cols_;
        type_ = other.type_;
        initialized_ = other.initialized_;
        impl_ = other.impl_;
        stats_ = other.stats_;
        
        other.weights_ = {};
        other.rows_ = 0;
        other.cols_ = 0;
        other.type_ = QuantizedLayerType::FP32;
        other.initialized_ = false;
        other.impl_ = {};
    }
    return *this;
}

bool Deep2QuantizedLinear::Initialize(const QuantizedWeightHandle& handle) {
    if (!handle.IsValid()) {
        return false;
    }
    
    // Cleanup any existing implementation
    if (initialized_) {
        switch (type_) {
            case QuantizedLayerType::Q4_K_M:
                if (impl_.q4km_impl) {
                    delete impl_.q4km_impl;
                    impl_.q4km_impl = nullptr;
                }
                break;
            default:
                break;
        }
    }
    
    weights_ = handle;
    rows_ = handle.rows;
    cols_ = handle.cols;
    type_ = handle.type;
    
    // Initialize implementation based on type
    switch (type_) {
        case QuantizedLayerType::Q4_K_M:
            impl_.q4km_impl = new Deep2::Q4KMLinear();
            if (!impl_.q4km_impl->Initialize(handle.data, cols_, rows_)) {
                delete impl_.q4km_impl;
                impl_.q4km_impl = nullptr;
                initialized_ = false;
                return false;
            }
            break;
            
        case QuantizedLayerType::FP32:
        case QuantizedLayerType::FP16:
            // FP32/FP16 use direct GEMV - no special initialization
            break;
            
        default:
            // Unsupported quantization type
            return false;
    }
    
    initialized_ = true;
    return true;
}

bool Deep2QuantizedLinear::Forward(const float* x, float* y) {
    if (!initialized_ || !x || !y) {
        return false;
    }
    
    switch (type_) {
        case QuantizedLayerType::Q4_K_M:
            return Forward_Q4KM(x, y);
            
        case QuantizedLayerType::FP32:
            return Forward_FP32(x, y);
            
        default:
            return false;
    }
}

bool Deep2QuantizedLinear::Forward_Q4KM(const float* x, float* y) {
    if (!impl_.q4km_impl) {
        return false;
    }
    
    auto start = __rdtsc();
    bool result = impl_.q4km_impl->Forward(x, y);
    auto end = __rdtsc();
    
    if (result) {
        ++stats_.forward_calls;
        stats_.total_cycles += (end - start);
        stats_.avg_cycles_per_call = 
            static_cast<double>(stats_.total_cycles) / stats_.forward_calls;
    }
    
    return result;
}

bool Deep2QuantizedLinear::Forward_FP32(const float* x, float* y) {
    // For FP32, weights should be in FP32 format
    // Compute y = weights * x using standard GEMV
    // This is a fallback path
    
    const float* weights = reinterpret_cast<const float*>(weights_.data);
    
    for (size_t row = 0; row < rows_; ++row) {
        float sum = 0.0f;
        const float* row_ptr = weights + row * cols_;
        
        // Simple dot product
        for (size_t col = 0; col < cols_; ++col) {
            sum += row_ptr[col] * x[col];
        }
        
        y[row] = sum;
    }
    
    ++stats_.forward_calls;
    return true;
}

} // namespace Bridge
} // namespace RawrXD

/*===========================================================================
 * C API Implementation
 *===========================================================================*/

extern "C" {

using namespace RawrXD::Bridge;

__declspec(dllexport)
void* Deep2Bridge_CreateQuantizedLinear(
    const uint8_t* weight_data,
    size_t num_blocks,
    size_t rows,
    size_t cols,
    int quant_type) {
    
    QuantizedWeightHandle handle;
    handle.data = weight_data;
    handle.num_blocks = num_blocks;
    handle.rows = rows;
    handle.cols = cols;
    handle.type = GGUFQuantToInternal(quant_type);
    handle.valid = true;
    
    auto* layer = new Deep2QuantizedLinear();
    if (!layer->Initialize(handle)) {
        delete layer;
        return nullptr;
    }
    
    return layer;
}

__declspec(dllexport)
bool Deep2Bridge_QuantizedLinear_Forward(
    void* layer,
    const float* input,
    float* output) {
    
    if (!layer || !input || !output) {
        return false;
    }
    
    auto* linear = static_cast<Deep2QuantizedLinear*>(layer);
    return linear->Forward(input, output);
}

__declspec(dllexport)
void Deep2Bridge_DestroyQuantizedLinear(void* layer) {
    if (layer) {
        delete static_cast<Deep2QuantizedLinear*>(layer);
    }
}

__declspec(dllexport)
bool Deep2Bridge_HasQuantizedKernels(void) {
    // Check if Q4_K_M kernels are available
    return Deep2::Q4KMDispatch::Instance().HasAVX2();
}

__declspec(dllexport)
const char* Deep2Bridge_GetQuantizedKernelVersion(void) {
    auto& dispatch = Deep2::Q4KMDispatch::Instance();
    
    if (dispatch.HasAVX512()) {
        return "Q4KM-AVX512-v1.0";
    } else if (dispatch.HasAVX2()) {
        return "Q4KM-AVX2-v1.0";
    }
    return "Q4KM-Scalar-v1.0";
}

} // extern "C"
