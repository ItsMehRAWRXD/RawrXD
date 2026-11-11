//=============================================================================
// Tensor Layout Optimizer - NHWC (Interleaved) vs NCHW (Planar)
// Converts model weights to NHWC for maximum AVX-512 throughput
//=============================================================================
#pragma once

#include <cstdint.h>
#include <cstddef.h>

namespace RawrXD {
namespace Kernels {

//=============================================================================
// Layout Strategy Decision
//=============================================================================

// NHWC = Interleaved: [N][H][W][C] - channels last
// NCHW = Planar: [N][C][H][W] - channels first

// For transformer inference:
// - Tokens = H (sequence dimension)
// - Features = C (head_dim * num_heads)
// - Batch = N
// - Width = 1 (not used)

// NHWC is optimal for attention because:
// 1. All features for a token are contiguous (cache-friendly)
// 2. AVX-512 loads are aligned and sequential
// 3. No gather instructions needed

enum class TensorLayout {
    NCHW,  // Planar - default in most frameworks
    NHWC,  // Interleaved - optimal for inference
};

//=============================================================================
// Layout Conversion Utilities
//=============================================================================

// Convert tensor from NCHW to NHWC
// This should be done OFFLINE during model conversion, not at runtime
void ConvertNCHWtoNHWC(
    const float* __restrict src,  // Source in NCHW
    float* __restrict dst,        // Destination in NHWC
    int N, int C, int H, int W
);

// Convert tensor from NHWC back to NCHW (for debugging)
void ConvertNHWCtoNCHW(
    const float* __restrict src,  // Source in NHWC
    float* __restrict dst,        // Destination in NCHW
    int N, int C, int H, int W
);

// Check if dimensions are AVX-512 friendly (multiple of 16)
bool IsAVX512Friendly(int dim);

// Pad dimension to nearest multiple of 16 for alignment
int PadToAVX512(int dim);

//=============================================================================
// NHWC Tensor View
// Provides convenient access to interleaved data
//=============================================================================

template <typename T>
class NHWCTensorView {
public:
    NHWCTensorView(T* data, int N, int H, int W, int C)
        : data_(data), N_(N), H_(H), W_(W), C_(C) {}
    
    // Access element at [n][h][w][c]
    T& At(int n, int h, int w, int c) {
        return data_[((n * H_ + h) * W_ + w) * C_ + c];
    }
    
    const T& At(int n, int h, int w, int c) const {
        return data_[((n * H_ + w) * W_ + w) * C_ + c];
    }
    
    // Get pointer to all channels for a position [n][h][w]
    // This is the key optimization - contiguous memory access
    T* GetFeaturePtr(int n, int h, int w) {
        return data_ + ((n * H_ + h) * W_ + w) * C_;
    }
    
    const T* GetFeaturePtr(int n, int h, int w) const {
        return data_ + ((n * H_ + h) * W_ + w) * C_;
    }
    
    // Dimensions
    int N() const { return N_; }
    int H() const { return H_; }
    int W() const { return W_; }
    int C() const { return C_; }
    
    // Total size
    size_t Size() const { return static_cast<size_t>(N_) * H_ * W_ * C_; }
    
private:
    T* data_;
    int N_, H_, W_, C_;
};

//=============================================================================
// Model Layout Converter
// One-time offline conversion tool
//=============================================================================

class ModelLayoutConverter {
public:
    // Convert entire model from NCHW to NHWC
    // This is the RECOMMENDED approach - do it once at model import time
    static bool ConvertModelWeights(
        const char* input_path,   // Original model (NCHW)
        const char* output_path   // Optimized model (NHWC)
    );
    
    // Verify converted model integrity
    static bool VerifyConversion(
        const char* original_path,
        const char* converted_path
    );
    
    // Get recommended layout for a layer type
    static TensorLayout GetRecommendedLayout(const char* layer_type);
};

//=============================================================================
// Runtime Layout Adapter (Fallback)
// Only used if model wasn't pre-converted
//=============================================================================

class RuntimeLayoutAdapter {
public:
    // On-the-fly conversion (NOT RECOMMENDED - slow)
    // Only use for debugging or unsupported models
    static bool ConvertOnTheFly(
        const float* nchw_input,
        float* nhwc_output,
        int N, int C, int H, int W
    );
    
    // Check if conversion is needed
    static bool NeedsConversion(TensorLayout current, TensorLayout target);
};

} // namespace Kernels
} // namespace RawrXD
