/*===========================================================================
 * tensor_layout.hpp
 * 
 * Memory layout definitions and tensor re-layout utilities
 * 
 * Layouts:
 *   NCHW - Planar (channels first) - legacy
 *   NHWC - Interleaved (channels last) - optimized for SIMD
 * 
 * NHWC Benefits:
 *   - Contiguous memory access for channel-wise operations
 *   - 64-byte aligned loads for AVX-512 (16 floats per load)
 *   - Reduced cache misses in attention kernels
 *   - 1.5-2x throughput improvement
 *===========================================================================*/

#pragma once

#include <cstdint>
#include <cstddef>

namespace RawrXD {
namespace Kernels {

// Layout type enumeration
enum class TensorLayout : uint32_t {
    NCHW = 0,  // Planar: [N, C, H, W] - legacy
    NHWC = 1,  // Interleaved: [N, H, W, C] - optimized
    NCHWc = 2  // Blocked: [N, C/c, H, W, c] - for future use
};

// Tensor descriptor
struct TensorDesc {
    uint32_t N;           // Batch size
    uint32_t C;           // Channels
    uint32_t H;           // Height
    uint32_t W;           // Width
    TensorLayout layout;  // Memory layout
    uint32_t alignment;   // Required alignment (bytes)
    
    // Compute strides for current layout
    size_t GetStrideN() const;
    size_t GetStrideC() const;
    size_t GetStrideH() const;
    size_t GetStrideW() const;
    
    // Total size in bytes
    size_t GetTotalBytes() const { return N * C * H * W * sizeof(float); }
    
    // Check if layout is SIMD-friendly
    bool IsSIMDFriendly() const { return layout == TensorLayout::NHWC; }
};

// Layout conversion interface
class TensorLayoutConverter {
public:
    // Convert between layouts
    // Returns false if output buffer is insufficient
    static bool Convert(
        const float* input,
        float* output,
        const TensorDesc& srcDesc,
        const TensorDesc& dstDesc
    );
    
    // Optimized NCHW -> NHWC conversion
    // Uses blocking for cache efficiency
    static bool NCHWtoNHWC(
        const float* nchw,
        float* nhwc,
        uint32_t N, uint32_t C, uint32_t H, uint32_t W
    );
    
    // Optimized NHWC -> NCHW conversion
    static bool NHWCtoNCHW(
        const float* nhwc,
        float* nchw,
        uint32_t N, uint32_t C, uint32_t H, uint32_t W
    );
    
    // In-place layout verification
    static bool VerifyNHWCAlignment(const float* data, uint32_t C);
    
private:
    // Block sizes for cache-efficient conversion
    static constexpr uint32_t kBlockN = 1;
    static constexpr uint32_t kBlockC = 64;   // AVX-512 friendly
    static constexpr uint32_t kBlockH = 32;
    static constexpr uint32_t kBlockW = 32;
};

// C-compatible exports
extern "C" {
    __declspec(dllexport) int RawrXD_ConvertLayout(
        const float* input,
        float* output,
        uint32_t N, uint32_t C, uint32_t H, uint32_t W,
        uint32_t srcLayout,  // 0=NCHW, 1=NHWC
        uint32_t dstLayout
    );
    
    __declspec(dllexport) uint32_t RawrXD_GetOptimalBlockSize();
}

} // namespace Kernels
} // namespace RawrXD
