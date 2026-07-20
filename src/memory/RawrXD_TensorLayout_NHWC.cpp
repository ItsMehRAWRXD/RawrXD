/**=============================================================================
 * RawrXD_TensorLayout_NHWC.cpp
 * Memory Layout Transformation Implementation
 * 
 * High-performance tensor layout conversion with AVX-512 optimization
 *=============================================================================*/

#include "RawrXD_TensorLayout_NHWC.hpp"
#include <cstring>
#include <algorithm>

namespace RawrXD {
namespace Memory {

/**=============================================================================
 * Quantized Tensor Layout Conversion (Q4_0)
 * 
 * Q4_0 format: 32 4-bit weights packed into 16 bytes + 2-byte scale
 * Layout: [N, C, H, W] -> [N, H, W, C] where C is in blocks of 32
 *=============================================================================*/
void NHWCLayoutConverter::ConvertNCHWtoNHWC_Q4_0(
    const void* __restrict src,
    void* __restrict dst,
    int N, int C, int H, int W,
    size_t block_size
) {
    const int blocks_per_channel = (C + block_size - 1) / block_size;
    const size_t block_bytes = block_size / 2 + sizeof(uint16_t);  // 16 bytes weights + 2 bytes scale
    
    // Source: [N, C/blocks, H, W, block]
    // Dest:   [N, H, W, C/blocks, block]
    
    for (int n = 0; n < N; ++n) {
        for (int h = 0; h < H; ++h) {
            for (int w = 0; w < W; ++w) {
                // Destination pointer for this spatial location
                uint8_t* dst_ptr = (uint8_t*)dst + 
                    (((size_t)n * H + h) * W + w) * blocks_per_channel * block_bytes;
                
                for (int cb = 0; cb < blocks_per_channel; ++cb) {
                    // Source index: [n][cb][h][w]
                    size_t src_idx = (((size_t)n * blocks_per_channel + cb) * H + h) * W + w;
                    const uint8_t* src_block = (const uint8_t*)src + src_idx * block_bytes;
                    uint8_t* dst_block = dst_ptr + cb * block_bytes;
                    
                    // Copy entire block (weights + scale)
                    std::memcpy(dst_block, src_block, block_bytes);
                }
            }
        }
    }
}

/**=============================================================================
 * Quantized Tensor Layout Conversion (Q8_0)
 * 
 * Q8_0 format: 32 8-bit weights + 2-byte scale
 *=============================================================================*/
void NHWCLayoutConverter::ConvertNCHWtoNHWC_Q8_0(
    const void* __restrict src,
    void* __restrict dst,
    int N, int C, int H, int W,
    size_t block_size
) {
    const int blocks_per_channel = (C + block_size - 1) / block_size;
    const size_t block_bytes = block_size + sizeof(uint16_t);  // 32 bytes weights + 2 bytes scale
    
    for (int n = 0; n < N; ++n) {
        for (int h = 0; h < H; ++h) {
            for (int w = 0; w < W; ++w) {
                uint8_t* dst_ptr = (uint8_t*)dst + 
                    (((size_t)n * H + h) * W + w) * blocks_per_channel * block_bytes;
                
                for (int cb = 0; cb < blocks_per_channel; ++cb) {
                    size_t src_idx = (((size_t)n * blocks_per_channel + cb) * H + h) * W + w;
                    const uint8_t* src_block = (const uint8_t*)src + src_idx * block_bytes;
                    uint8_t* dst_block = dst_ptr + cb * block_bytes;
                    
                    std::memcpy(dst_block, src_block, block_bytes);
                }
            }
        }
    }
}

/**=============================================================================
 * Batch Layout Conversion
 * 
 * Converts multiple tensors in a batch for model loading
 *=============================================================================*/
class BatchLayoutConverter {
public:
    struct ConversionTask {
        const void* src;
        void* dst;
        int N, C, H, W;
        uint32_t data_type;  // 0=f32, 1=q4_0, 2=q8_0
    };
    
    static void ConvertBatch(
        const ConversionTask* tasks,
        int num_tasks,
        int num_threads = 0  // 0 = auto
    ) {
        if (num_threads <= 0) {
            num_threads = std::thread::hardware_concurrency();
        }
        
        // Simple parallel for
        #pragma omp parallel for num_threads(num_threads)
        for (int i = 0; i < num_tasks; ++i) {
            const auto& task = tasks[i];
            
            switch (task.data_type) {
                case 0:  // float32
                    NHWCLayoutConverter::ConvertNCHWtoNHWC(
                        (const float*)task.src,
                        (float*)task.dst,
                        task.N, task.C, task.H, task.W
                    );
                    break;
                    
                case 1:  // Q4_0
                    NHWCLayoutConverter::ConvertNCHWtoNHWC_Q4_0(
                        task.src, task.dst,
                        task.N, task.C, task.H, task.W
                    );
                    break;
                    
                case 2:  // Q8_0
                    NHWCLayoutConverter::ConvertNCHWtoNHWC_Q8_0(
                        task.src, task.dst,
                        task.N, task.C, task.H, task.W
                    );
                    break;
            }
        }
    }
};

/**=============================================================================
 * Compiler Integration
 * 
 * Functions for integrating with RawrXD_Universal_Compiler
 *=============================================================================*/

extern "C" {

/**=========================================================================
 * C API for compiler integration
 *=========================================================================*/
int RawrXD_ConvertLayout_NCHWtoNHWC(
    const void* src,
    void* dst,
    int N, int C, int H, int W,
    int data_type  // 0=f32, 1=q4_0, 2=q8_0
) {
    try {
        switch (data_type) {
            case 0:
                NHWCLayoutConverter::ConvertNCHWtoNHWC(
                    (const float*)src, (float*)dst,
                    N, C, H, W
                );
                return 0;
                
            case 1:
                NHWCLayoutConverter::ConvertNCHWtoNHWC_Q4_0(
                    src, dst, N, C, H, W
                );
                return 0;
                
            case 2:
                NHWCLayoutConverter::ConvertNCHWtoNHWC_Q8_0(
                    src, dst, N, C, H, W
                );
                return 0;
                
            default:
                return -1;  // Unknown data type
        }
    } catch (...) {
        return -2;  // Conversion error
    }
}

/**=========================================================================
 * Calculate output size for NHWC layout
 *=========================================================================*/
size_t RawrXD_CalculateNHWCSize(
    int N, int C, int H, int W,
    int data_type,
    size_t block_size = 32
) {
    size_t elements = (size_t)N * C * H * W;
    
    switch (data_type) {
        case 0:  // float32
            return elements * sizeof(float);
            
        case 1: {  // Q4_0
            size_t blocks = (elements + block_size - 1) / block_size;
            return blocks * (block_size / 2 + sizeof(uint16_t));
        }
            
        case 2: {  // Q8_0
            size_t blocks = (elements + block_size - 1) / block_size;
            return blocks * (block_size + sizeof(uint16_t));
        }
            
        default:
            return 0;
    }
}

/**=========================================================================
 * Write layout header for compiled model
 *=========================================================================*/
void RawrXD_WriteLayoutHeader(
    void* dst,
    uint32_t magic,
    int N, int C, int H, int W,
    uint32_t data_type
) {
    TensorLayoutDesc* desc = (TensorLayoutDesc*)dst;
    desc->magic = magic;
    desc->ndims = 4;
    desc->shape[0] = N;
    desc->shape[1] = H;  // Note: H and W come before C in NHWC
    desc->shape[2] = W;
    desc->shape[3] = C;
    
    NHWCLayoutConverter::CalculateNHWCStrides(N, C, H, W, desc->strides);
    
    desc->data_type = data_type;
    desc->alignment = 64;  // AVX-512 alignment
    desc->total_size = RawrXD_CalculateNHWCSize(N, C, H, W, data_type);
}

} // extern "C"

} // namespace Memory
} // namespace RawrXD
