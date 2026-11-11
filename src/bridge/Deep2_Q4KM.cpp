/*===========================================================================
 * Deep2_Q4KM.cpp
 * 
 * Q4_K_M quantized matrix operations implementation
 *===========================================================================*/

#include "Deep2_Q4KM.hpp"
#include <cstring>
#include <algorithm>

#ifdef _WIN32
#include <windows.h>
#include <intrin.h>
#endif

// External Deep2 kernels
extern "C" {
    void Deep2_VecDotProduct(const float* a, const float* b, float* out, size_t n);
    int Deep2_HasAVX2(void);
    int Deep2_HasAVX512(void);
}

namespace RawrXD {
namespace Deep2 {

/*===========================================================================
 * DequantBuffer Implementation
 *===========================================================================*/
DequantBuffer::DequantBuffer(size_t num_floats) {
    Resize(num_floats);
}

DequantBuffer::~DequantBuffer() {
    if (data_) {
        _aligned_free(data_);
    }
}

DequantBuffer::DequantBuffer(DequantBuffer&& other) noexcept
    : data_(other.data_), size_(other.size_), capacity_(other.capacity_) {
    other.data_ = nullptr;
    other.size_ = 0;
    other.capacity_ = 0;
}

DequantBuffer& DequantBuffer::operator=(DequantBuffer&& other) noexcept {
    if (this != &other) {
        if (data_) {
            _aligned_free(data_);
        }
        data_ = other.data_;
        size_ = other.size_;
        capacity_ = other.capacity_;
        other.data_ = nullptr;
        other.size_ = 0;
        other.capacity_ = 0;
    }
    return *this;
}

bool DequantBuffer::Resize(size_t num_floats) {
    if (num_floats <= capacity_) {
        size_ = num_floats;
        return true;
    }
    
    if (data_) {
        _aligned_free(data_);
    }
    
    // Allocate with 32-byte alignment for AVX2/AVX-512
    data_ = (float*)_aligned_malloc(num_floats * sizeof(float), 32);
    if (!data_) {
        size_ = 0;
        capacity_ = 0;
        return false;
    }
    
    size_ = num_floats;
    capacity_ = num_floats;
    return true;
}

/*===========================================================================
 * Q4KMLinear Implementation
 *===========================================================================*/
bool Q4KMLinear::Initialize(const uint8_t* weight_data, size_t in_features, size_t out_features) {
    if (!weight_data || in_features == 0 || out_features == 0) {
        return false;
    }
    
    // Calculate number of blocks needed
    // Each block holds 256 values
    size_t total_values = in_features * out_features;
    size_t num_blocks = (total_values + 255) / 256;
    
    weights_ = Q4KMTensorView(weight_data, num_blocks, out_features, in_features);
    in_features_ = in_features;
    out_features_ = out_features;
    
    // Allocate scratch buffer for one row (dequantized)
    row_buffer_.Resize(in_features);
    
    return weights_.IsValid() && row_buffer_.IsValid();
}

bool Q4KMLinear::Forward(const float* x, float* y) {
    if (!IsInitialized() || !x || !y) {
        return false;
    }
    
    // Use fused implementation if available
    return Forward_Fused(x, y);
}

bool Q4KMLinear::Forward_Fused(const float* x, float* y) {
    // Fused dequant + GEMV implementation
    // For each output row:
    //   1. Dequantize the row's weights
    //   2. Compute dot product with input vector
    //   3. Store result
    
    const size_t blocks_per_row = (in_features_ + 255) / 256;
    float* row_buffer = row_buffer_.Data();
    
    for (size_t row = 0; row < out_features_; ++row) {
        // Get pointer to this row's blocks
        const uint8_t* row_blocks = weights_.Data() + row * blocks_per_row * sizeof(Q4KMBlock);
        
        // Dequantize this row
        Sovereign_Q4KM_DequantRange(row_blocks, row_buffer, blocks_per_row);
        
        // Compute dot product with input
        float result = 0.0f;
        Deep2_VecDotProduct(row_buffer, x, &result, in_features_);
        
        y[row] = result;
    }
    
    ++stats_.forward_calls;
    return true;
}

bool Q4KMLinear::Forward_DequantThenGEMV(const float* x, float* y) {
    // Alternative: Dequantize entire matrix first, then GEMV
    // Higher memory usage but potentially better for batch processing
    // Not implemented - use Forward_Fused instead
    (void)x;
    (void)y;
    return false;
}

/*===========================================================================
 * Q4KMDispatch Implementation
 *===========================================================================*/
Q4KMDispatch& Q4KMDispatch::Instance() {
    static Q4KMDispatch instance;
    if (!instance.initialized_) {
        instance.Initialize();
    }
    return instance;
}

void Q4KMDispatch::Initialize() {
    has_avx2_ = Deep2_HasAVX2() != 0;
    has_avx512_ = Deep2_HasAVX512() != 0;
    initialized_ = true;
}

bool Q4KMDispatch::HasAVX512() const {
    return has_avx512_;
}

bool Q4KMDispatch::HasAVX2() const {
    return has_avx2_;
}

Q4KMKernelType Q4KMDispatch::GetBestKernelType() const {
    if (has_avx512_) return Q4KMKernelType::AVX512;
    if (has_avx2_) return Q4KMKernelType::AVX2;
    return Q4KMKernelType::Scalar;
}

void Q4KMDispatch::Dequantize(const uint8_t* blocks, float* dest, size_t num_blocks) {
    if (!blocks || !dest || num_blocks == 0) {
        return;
    }
    
    // Call the MASM implementation which handles dispatch internally
    Sovereign_Q4KM_DequantRange(blocks, dest, num_blocks);
}

void Q4KMDispatch::FusedGEMV(const Q4KMBlock* weights, const float* x, float* y, size_t len) {
    if (!weights || !x || !y || len == 0) {
        return;
    }
    
    // Calculate blocks needed
    size_t num_blocks = (len + 255) / 256;
    
    // Allocate temp buffer for dequantized weights
    float* temp_buffer = (float*)_aligned_malloc(len * sizeof(float), 32);
    if (!temp_buffer) {
        return;
    }
    
    // Dequantize
    Sovereign_Q4KM_DequantRange(
        reinterpret_cast<const uint8_t*>(weights),
        temp_buffer,
        num_blocks
    );
    
    // Compute dot product
    Deep2_VecDotProduct(temp_buffer, x, y, len);
    
    _aligned_free(temp_buffer);
}

} // namespace Deep2
} // namespace RawrXD

/*===========================================================================
 * C API for MASM Integration
 *===========================================================================*/

extern "C" {

/**
 * Deep2Linear_Q4KM - Main entry point for Q4_K_M linear layer
 * Called from Deep2 transformer layer
 */
__declspec(dllexport)
bool Deep2Linear_Q4KM(
    const uint8_t* weight_blocks,  // Q4_K_M quantized weights
    const float* input,             // FP32 input vector
    float* output,                  // FP32 output vector
    size_t in_features,             // Input dimension
    size_t out_features             // Output dimension
) {
    using namespace RawrXD::Deep2;
    
    Q4KMLinear linear;
    if (!linear.Initialize(weight_blocks, in_features, out_features)) {
        return false;
    }
    
    return linear.Forward(input, output);
}

/**
 * Deep2_Q4KM_GetDispatch - Get kernel dispatch info
 */
__declspec(dllexport)
int Deep2_Q4KM_GetDispatch(void) {
    using namespace RawrXD::Deep2;
    auto& dispatch = Q4KMDispatch::Instance();
    
    if (dispatch.HasAVX512()) return 2;  // AVX-512
    if (dispatch.HasAVX2()) return 1;     // AVX2
    return 0;                            // Scalar
}

} // extern "C"
