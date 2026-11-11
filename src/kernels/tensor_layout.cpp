/*===========================================================================
 * tensor_layout.cpp
 * 
 * Tensor layout conversion implementation
 * 
 * Optimized for:
 *   - AVX-512 (16 floats per load)
 *   - Cache blocking (L1/L2/L3 aware)
 *   - 64-byte alignment
 *===========================================================================*/

#include "tensor_layout.hpp"
#include "avx512_kernels.hpp"
#include <cstring>
#include <immintrin.h>

namespace RawrXD {
namespace Kernels {

// Compute strides for NCHW layout
size_t TensorDesc::GetStrideN() const {
    return (layout == TensorLayout::NCHW) ? C * H * W : C;
}

size_t TensorDesc::GetStrideC() const {
    return (layout == TensorLayout::NCHW) ? H * W : 1;
}

size_t TensorDesc::GetStrideH() const {
    return (layout == TensorLayout::NCHW) ? W : W * C;
}

size_t TensorDesc::GetStrideW() const {
    return (layout == TensorLayout::NCHW) ? 1 : C;
}

// Generic layout conversion
bool TensorLayoutConverter::Convert(
    const float* input,
    float* output,
    const TensorDesc& srcDesc,
    const TensorDesc& dstDesc
) {
    if (srcDesc.N != dstDesc.N || srcDesc.C != dstDesc.C ||
        srcDesc.H != dstDesc.H || srcDesc.W != dstDesc.W) {
        return false;  // Dimension mismatch
    }
    
    // Direct conversion paths
    if (srcDesc.layout == TensorLayout::NCHW && dstDesc.layout == TensorLayout::NHWC) {
        return NCHWtoNHWC(input, output, srcDesc.N, srcDesc.C, srcDesc.H, srcDesc.W);
    }
    
    if (srcDesc.layout == TensorLayout::NHWC && dstDesc.layout == TensorLayout::NCHW) {
        return NHWCtoNCHW(input, output, srcDesc.N, srcDesc.C, srcDesc.H, srcDesc.W);
    }
    
    // Same layout - just copy
    if (srcDesc.layout == dstDesc.layout) {
        std::memcpy(output, input, srcDesc.GetTotalBytes());
        return true;
    }
    
    return false;  // Unsupported conversion
}

// Optimized NCHW -> NHWC conversion
// From: [N, C, H, W] to [N, H, W, C]
bool TensorLayoutConverter::NCHWtoNHWC(
    const float* nchw,
    float* nhwc,
    uint32_t N, uint32_t C, uint32_t H, uint32_t W
) {
    if (!nchw || !nhwc) return false;
    
    // Block sizes tuned for L1 cache (32KB) and AVX-512 (64 bytes)
    constexpr uint32_t blockC = 64;   // Process 64 channels at a time
    constexpr uint32_t blockH = 32;   // Process 32 rows at a time
    constexpr uint32_t blockW = 16;   // Process 16 cols at a time
    
    // Align C to blockC for AVX-512 efficiency
    uint32_t C_aligned = (C + blockC - 1) & ~(blockC - 1);
    
    for (uint32_t n = 0; n < N; ++n) {
        for (uint32_t h_block = 0; h_block < H; h_block += blockH) {
            uint32_t h_end = std::min(h_block + blockH, H);
            
            for (uint32_t w_block = 0; w_block < W; w_block += blockW) {
                uint32_t w_end = std::min(w_block + blockW, W);
                
                for (uint32_t c_block = 0; c_block < C; c_block += blockC) {
                    uint32_t c_end = std::min(c_block + blockC, C);
                    
                    // Process this block
                    for (uint32_t h = h_block; h < h_end; ++h) {
                        for (uint32_t w = w_block; w < w_end; ++w) {
                            // Compute output position: [N, H, W, C]
                            float* out_ptr = nhwc + 
                                ((n * H + h) * W + w) * C_aligned + c_block;
                            
                            // Compute input position: [N, C, H, W]
                            const float* in_ptr = nchw + 
                                ((n * C + c_block) * H + h) * W + w;
                            
                            // Copy block of channels
                            uint32_t c_count = c_end - c_block;
                            
                            // Use AVX-512 for aligned blocks of 16 floats
                            uint32_t c = 0;
                            for (; c + 16 <= c_count; c += 16) {
                                __m512 vec = _mm512_loadu_ps(in_ptr + c * H * W);
                                _mm512_storeu_ps(out_ptr + c, vec);
                            }
                            
                            // Handle remainder
                            for (; c < c_count; ++c) {
                                out_ptr[c] = in_ptr[c * H * W];
                            }
                        }
                    }
                }
            }
        }
    }
    
    return true;
}

// Optimized NHWC -> NCHW conversion
// From: [N, H, W, C] to [N, C, H, W]
bool TensorLayoutConverter::NHWCtoNCHW(
    const float* nhwc,
    float* nchw,
    uint32_t N, uint32_t C, uint32_t H, uint32_t W
) {
    if (!nhwc || !nchw) return false;
    
    // Similar blocking strategy
    constexpr uint32_t blockC = 64;
    constexpr uint32_t blockH = 32;
    constexpr uint32_t blockW = 16;
    
    uint32_t C_aligned = (C + blockC - 1) & ~(blockC - 1);
    
    for (uint32_t n = 0; n < N; ++n) {
        for (uint32_t c_block = 0; c_block < C; c_block += blockC) {
            uint32_t c_end = std::min(c_block + blockC, C);
            
            for (uint32_t h_block = 0; h_block < H; h_block += blockH) {
                uint32_t h_end = std::min(h_block + blockH, H);
                
                for (uint32_t w_block = 0; w_block < W; w_block += blockW) {
                    uint32_t w_end = std::min(w_block + blockW, W);
                    
                    // Process this block
                    for (uint32_t c = c_block; c < c_end; ++c) {
                        for (uint32_t h = h_block; h < h_end; ++h) {
                            // Compute positions
                            const float* in_ptr = nhwc + 
                                ((n * H + h) * W + w_block) * C_aligned + c;
                            
                            float* out_ptr = nchw + 
                                ((n * C + c) * H + h) * W + w_block;
                            
                            // Copy block of width
                            uint32_t w_count = w_end - w_block;
                            
                            // AVX-512 for aligned blocks
                            uint32_t w = 0;
                            for (; w + 16 <= w_count; w += 16) {
                                // Gather from NHWC layout
                                // This is trickier - need to stride by C
                                __m512 vec = _mm512_set_ps(
                                    in_ptr[15 * C_aligned], in_ptr[14 * C_aligned],
                                    in_ptr[13 * C_aligned], in_ptr[12 * C_aligned],
                                    in_ptr[11 * C_aligned], in_ptr[10 * C_aligned],
                                    in_ptr[9 * C_aligned], in_ptr[8 * C_aligned],
                                    in_ptr[7 * C_aligned], in_ptr[6 * C_aligned],
                                    in_ptr[5 * C_aligned], in_ptr[4 * C_aligned],
                                    in_ptr[3 * C_aligned], in_ptr[2 * C_aligned],
                                    in_ptr[1 * C_aligned], in_ptr[0 * C_aligned]
                                );
                                _mm512_storeu_ps(out_ptr + w, vec);
                                in_ptr += 16 * C_aligned;
                            }
                            
                            // Handle remainder
                            for (; w < w_count; ++w) {
                                out_ptr[w] = in_ptr[w * C_aligned];
                            }
                        }
                    }
                }
            }
        }
    }
    
    return true;
}

// Verify NHWC alignment
bool TensorLayoutConverter::VerifyNHWCAlignment(const float* data, uint32_t C) {
    // Check if channel dimension is 64-byte aligned
    return (reinterpret_cast<uintptr_t>(data) % 64 == 0) && (C % 16 == 0);
}

} // namespace Kernels
} // namespace RawrXD

// C exports
extern "C" {

__declspec(dllexport) int RawrXD_ConvertLayout(
    const float* input,
    float* output,
    uint32_t N, uint32_t C, uint32_t H, uint32_t W,
    uint32_t srcLayout,
    uint32_t dstLayout
) {
    using namespace RawrXD::Kernels;
    
    TensorDesc srcDesc = {N, C, H, W, 
        static_cast<TensorLayout>(srcLayout), 64};
    TensorDesc dstDesc = {N, C, H, W, 
        static_cast<TensorLayout>(dstLayout), 64};
    
    return TensorLayoutConverter::Convert(input, output, srcDesc, dstDesc) ? 0 : -1;
}

__declspec(dllexport) uint32_t RawrXD_GetOptimalBlockSize() {
    // Return optimal block size for current CPU
    // 64 floats = 256 bytes = 4 AVX-512 registers
    return 64;
}

}
