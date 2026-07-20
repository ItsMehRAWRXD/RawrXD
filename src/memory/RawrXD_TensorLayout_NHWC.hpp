/**=============================================================================
 * RawrXD_TensorLayout_NHWC.hpp
 * Memory Layout Transformation for Optimal Cache Locality
 * 
 * Converts tensors from NCHW (Planar) to NHWC (Interleaved) layout
 * for improved AVX-512 cache utilization and reduced gather/scatter penalties
 *=============================================================================*/

#ifndef RAWRXD_TENSOR_LAYOUT_NHWC_HPP
#define RAWRXD_TENSOR_LAYOUT_NHWC_HPP

#include <cstdint>
#include <cstddef>
#include <immintrin.h>
#include <algorithm>
#include <cstring>

namespace RawrXD {
namespace Memory {

/**=============================================================================
 * Layout Constants
 *=============================================================================*/
constexpr uint32_t LAYOUT_MAGIC_NCHW = 0x4E434857;  // "NCHW"
constexpr uint32_t LAYOUT_MAGIC_NHWC = 0x4E485743;  // "NHWC"
constexpr uint32_t LAYOUT_MAGIC_RAWH = 0x52415748;  // "RAWH" (RawrXD optimized)

/**=============================================================================
 * Tensor Layout Descriptor
 *=============================================================================*/
struct TensorLayoutDesc {
    uint32_t magic;           // Layout identifier
    uint32_t ndims;           // Number of dimensions
    uint32_t shape[8];        // Tensor shape (up to 8D)
    uint32_t strides[8];      // Stride in elements
    uint32_t data_type;       // Data type enum
    uint32_t alignment;       // Required alignment (bytes)
    uint64_t total_size;      // Total size in bytes
    
    bool IsNHWC() const { return magic == LAYOUT_MAGIC_NHWC || magic == LAYOUT_MAGIC_RAWH; }
    bool IsNCHW() const { return magic == LAYOUT_MAGIC_NCHW; }
};

/**=============================================================================
 * NHWC Layout Converter
 * 
 * Transforms tensors from [N, C, H, W] to [N, H, W, C] layout
 * This improves cache locality for convolution and attention operations
 *=============================================================================*/
class NHWCLayoutConverter {
public:
    /**=========================================================================
     * Convert float32 tensor from NCHW to NHWC
     * 
     * @param src Source tensor in NCHW layout
     * @param dst Destination buffer (must be pre-allocated)
     * @param N Batch size
     * @param C Channels
     * @param H Height
     * @param W Width
     *=========================================================================*/
    static void ConvertNCHWtoNHWC(
        const float* __restrict src,
        float* __restrict dst,
        int N, int C, int H, int W
    ) {
        // Optimized AVX-512 implementation for large channels
        if (C >= 16) {
            ConvertNCHWtoNHWC_AVX512(src, dst, N, C, H, W);
        } else {
            ConvertNCHWtoNHWC_Scalar(src, dst, N, C, H, W);
        }
    }
    
    /**=========================================================================
     * Convert quantized tensor (Q4_0) from NCHW to NHWC
     *=========================================================================*/
    static void ConvertNCHWtoNHWC_Q4_0(
        const void* __restrict src,
        void* __restrict dst,
        int N, int C, int H, int W,
        size_t block_size = 32
    );
    
    /**=========================================================================
     * Convert quantized tensor (Q8_0) from NCHW to NHWC
     *=========================================================================*/
    static void ConvertNCHWtoNHWC_Q8_0(
        const void* __restrict src,
        void* __restrict dst,
        int N, int C, int H, int W,
        size_t block_size = 32
    );
    
    /**=========================================================================
     * Calculate NHWC strides for given shape
     *=========================================================================*/
    static void CalculateNHWCStrides(
        int N, int C, int H, int W,
        uint32_t* out_strides
    ) {
        // NHWC layout: stride[N] = H*W*C, stride[H] = W*C, stride[W] = C, stride[C] = 1
        out_strides[0] = H * W * C;  // N stride
        out_strides[1] = W * C;      // H stride
        out_strides[2] = C;          // W stride
        out_strides[3] = 1;          // C stride
    }
    
    /**=========================================================================
     * Calculate NCHW strides for given shape
     *=========================================================================*/
    static void CalculateNCHWStrides(
        int N, int C, int H, int W,
        uint32_t* out_strides
    ) {
        // NCHW layout: stride[N] = C*H*W, stride[C] = H*W, stride[H] = W, stride[W] = 1
        out_strides[0] = C * H * W;  // N stride
        out_strides[1] = H * W;      // C stride
        out_strides[2] = W;          // H stride
        out_strides[3] = 1;          // W stride
    }
    
    /**=========================================================================
     * Get element index in NHWC layout
     *=========================================================================*/
    static inline size_t IndexNHWC(int n, int h, int w, int c, int H, int W, int C) {
        return ((size_t)n * H + h) * W + w) * C + c;
    }
    
    /**=========================================================================
     * Get element index in NCHW layout
     *=========================================================================*/
    static inline size_t IndexNCHW(int n, int c, int h, int w, int C, int H, int W) {
        return ((size_t)n * C + c) * H + h) * W + w;
    }

private:
    /**=========================================================================
     * AVX-512 optimized conversion for large channels
     * Uses gather instructions for efficient strided access
     *=========================================================================*/
    static void ConvertNCHWtoNHWC_AVX512(
        const float* __restrict src,
        float* __restrict dst,
        int N, int C, int H, int W
    ) {
        const int C_aligned = (C + 15) & ~15;  // Align to 16 floats (64 bytes)
        
        for (int n = 0; n < N; ++n) {
            for (int h = 0; h < H; ++h) {
                for (int w = 0; w < W; ++w) {
                    float* dst_ptr = dst + ((size_t)n * H + h) * W + w) * C;
                    
                    // Process 16 channels at a time with AVX-512
                    int c = 0;
                    for (; c + 16 <= C; c += 16) {
                        // Gather 16 elements from strided NCHW layout
                        // src[n][c:c+16][h][w]
                        __m512 gathered = _mm512_setzero_ps();
                        
                        // Load each channel separately (gather)
                        for (int ci = 0; ci < 16; ++ci) {
                            size_t src_idx = ((size_t)n * C + (c + ci)) * H * W + h * W + w;
                            float val = src[src_idx];
                            gathered = _mm512_mask_expandloadu_ps(
                                gathered, 
                                (__mmask16)(1 << ci), 
                                &val
                            );
                        }
                        
                        // Store contiguously to NHWC
                        _mm512_storeu_ps(dst_ptr + c, gathered);
                    }
                    
                    // Handle remaining channels
                    for (; c < C; ++c) {
                        size_t src_idx = ((size_t)n * C + c) * H * W + h * W + w;
                        dst_ptr[c] = src[src_idx];
                    }
                }
            }
        }
    }
    
    /**=========================================================================
     * Scalar fallback for small channels
     *=========================================================================*/
    static void ConvertNCHWtoNHWC_Scalar(
        const float* __restrict src,
        float* __restrict dst,
        int N, int C, int H, int W
    ) {
        for (int n = 0; n < N; ++n) {
            for (int h = 0; h < H; ++h) {
                for (int w = 0; w < W; ++w) {
                    for (int c = 0; c < C; ++c) {
                        // src[n][c][h][w] -> dst[n][h][w][c]
                        size_t src_idx = ((size_t)n * C + c) * H * W + h * W + w;
                        size_t dst_idx = ((size_t)n * H + h) * W + w) * C + c;
                        dst[dst_idx] = src[src_idx];
                    }
                }
            }
        }
    }
};

/**=============================================================================
 * Cache-Optimized Tensor Access
 * 
 * Provides optimized access patterns for NHWC layout tensors
 *=============================================================================*/
template<typename T>
class NHWCTensorView {
public:
    NHWCTensorView(T* data, int N, int C, int H, int W) 
        : data_(data), N_(N), C_(C), H_(H), W_(W) {
        // Precompute strides
        stride_n_ = H * W * C;
        stride_h_ = W * C;
        stride_w_ = C;
        stride_c_ = 1;
    }
    
    // Fast inline access
    inline T& operator()(int n, int h, int w, int c) {
        return data_[((size_t)n * H_ + h) * W_ + w) * C_ + c];
    }
    
    inline const T& operator()(int n, int h, int w, int c) const {
        return data_[((size_t)n * H_ + h) * W_ + w) * C_ + c];
    }
    
    // Get pointer to contiguous channel data at (n, h, w)
    // In NHWC, channels are contiguous - perfect for vectorized ops
    inline T* GetChannelPtr(int n, int h, int w) {
        return data_ + ((size_t)n * H_ + h) * W_ + w) * C_;
    }
    
    // Prefetch channels for upcoming access
    inline void PrefetchChannels(int n, int h, int w) {
        _mm_prefetch((const char*)GetChannelPtr(n, h, w), _MM_HINT_T0);
    }

private:
    T* data_;
    int N_, C_, H_, W_;
    size_t stride_n_, stride_h_, stride_w_, stride_c_;
};

/**=============================================================================
 * Layout Validation
 *=============================================================================*/
class LayoutValidator {
public:
    static bool ValidateNHWCConversion(
        const float* original_nchw,
        const float* converted_nhwc,
        int N, int C, int H, int W
    ) {
        // Spot-check random elements
        const int num_checks = 100;
        for (int i = 0; i < num_checks; ++i) {
            int n = rand() % N;
            int c = rand() % C;
            int h = rand() % H;
            int w = rand() % W;
            
            size_t nchw_idx = ((size_t)n * C + c) * H * W + h * W + w;
            size_t nhwc_idx = ((size_t)n * H + h) * W + w) * C + c;
            
            if (original_nchw[nchw_idx] != converted_nhwc[nhwc_idx]) {
                return false;
            }
        }
        return true;
    }
};

} // namespace Memory
} // namespace RawrXD

#endif // RAWRXD_TENSOR_LAYOUT_NHWC_HPP
