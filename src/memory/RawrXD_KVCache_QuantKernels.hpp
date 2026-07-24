//=============================================================================
// Fix 5B Phase 2: Quantization Kernels for KV Cache Residency
// RawrXD IDE - High-Performance Inference
//=============================================================================
//
// QUANTIZATION KERNELS:
// =====================
// SIMD-optimized quantization kernels for tiered KV cache compression:
//   - FP16 -> Q8_0 (WARM tier): 2x compression, fast decompression
//   - FP16 -> Q4_0 (COLD tier): 4x compression, good balance
//   - FP16 -> Q4_K (COLD tier): 4x compression, block-wise scaling
//   - FP16 -> Q2_K (FROZEN tier): 8x compression, emergency only
//
// ARCHITECTURE:
// =============
// These kernels are called by the async migration worker during page
// compression/decompression. They operate on aligned buffers and use
// AVX2/AVX-512 when available for maximum throughput.
//
// BLOCK STRUCTURE:
// ================
// Q8_0: 32 values per block, 1 scale (float32) + 32 int8 values = 36 bytes
// Q4_0: 32 values per block, 1 scale (float32) + 16 uint8 values = 20 bytes
// Q4_K: 256 values per superblock, 8 scales + 8 mins + 128 uint4 values
// Q2_K: 256 values per superblock, 16 scales + 64 uint8 values
//=============================================================================

#pragma once

#include <cstdint>
#include <cstddef>

// PrecisionMode is defined in RawrXD_KVCache_Residency_v2.hpp
namespace NEVM {
namespace ISA {
    enum class PrecisionMode;
}
}

namespace RawrXD {
namespace Memory {

//=============================================================================
// Quantization Block Structures
//=============================================================================

// Q8_0: 2x compression, 32 values per block
struct BlockQ8_0 {
    float scale;           // Quantization scale
    int8_t values[32];     // Quantized values
};

// Q4_0: 4x compression, 32 values per block
struct BlockQ4_0 {
    float scale;           // Quantization scale
    uint8_t values[16];    // Packed uint4 values (2 per byte)
};

// Q4_K: 4x compression with block-wise scaling
struct BlockQ4_K {
    uint8_t scales[8];     // Block scales (quantized)
    uint8_t mins[8];       // Block minimums (quantized)
    uint8_t values[128];   // 256 values packed as uint4
};

// Q2_K: 8x compression for emergency eviction
struct BlockQ2_K {
    uint8_t scales[16];    // Block scales
    uint8_t values[64];    // 256 values packed as uint2
};

//=============================================================================
// Quantization Kernel Interface
//=============================================================================

class KVQuantizationKernels {
public:
    //=============================================================================
    // FP16 -> Quantized (Compression)
    //=============================================================================
    
    // Compress FP16 data to Q8_0 (2x compression)
    // @param src: Source FP16 buffer (count elements)
    // @param dst: Destination Q8_0 buffer (must be pre-allocated)
    // @param count: Number of elements (must be multiple of 32)
    // @return: Number of bytes written
    static size_t QuantizeFP16ToQ8_0(const void* src, BlockQ8_0* dst, size_t count);
    
    // Compress FP16 data to Q4_0 (4x compression)
    static size_t QuantizeFP16ToQ4_0(const void* src, BlockQ4_0* dst, size_t count);
    
    // Compress FP16 data to Q4_K (4x compression, better quality)
    static size_t QuantizeFP16ToQ4_K(const void* src, BlockQ4_K* dst, size_t count);
    
    // Compress FP16 data to Q2_K (8x compression, emergency only)
    static size_t QuantizeFP16ToQ2_K(const void* src, BlockQ2_K* dst, size_t count);
    
    //=============================================================================
    // Quantized -> FP16 (Decompression)
    //=============================================================================
    
    // Decompress Q8_0 to FP16
    static void DequantizeQ8_0ToFP16(const BlockQ8_0* src, void* dst, size_t count);
    
    // Decompress Q4_0 to FP16
    static void DequantizeQ4_0ToFP16(const BlockQ4_0* src, void* dst, size_t count);
    
    // Decompress Q4_K to FP16
    static void DequantizeQ4_KToFP16(const BlockQ4_K* src, void* dst, size_t count);
    
    // Decompress Q2_K to FP16 (emergency only, lower quality)
    static void DequantizeQ2_KToFP16(const BlockQ2_K* src, void* dst, size_t count);
    
    //=============================================================================
    // Utility Functions
    //=============================================================================
    
    // Calculate required buffer size for quantization
    static size_t GetQuantizedBufferSize(size_t element_count, int bits_per_element);
    
    // Get block size for quantization format
    static size_t GetBlockSize(int bits_per_element);
    
    // Validate alignment requirements
    static bool ValidateAlignment(const void* ptr, size_t alignment);
    
private:
    // SIMD dispatch helpers (implemented in .cpp)
    static void QuantizeFP16ToQ8_0_Scalar(const void* src, BlockQ8_0* dst, size_t count);
    static void QuantizeFP16ToQ4_0_Scalar(const void* src, BlockQ4_0* dst, size_t count);
    static void DequantizeQ8_0ToFP16_Scalar(const BlockQ8_0* src, void* dst, size_t count);
    static void DequantizeQ4_0ToFP16_Scalar(const BlockQ4_0* src, void* dst, size_t count);
};

//=============================================================================
// High-Level Compression Interface
//=============================================================================

// Compress page data to target precision
// @param src: Source FP16 data
// @param src_size: Source size in bytes
// @param dst: Destination buffer (must be pre-allocated)
// @param dst_capacity: Destination capacity
// @param target_precision: Target precision mode
// @return: Actual compressed size, or 0 on failure
size_t CompressPageData(const void* src, size_t src_size, 
                        void* dst, size_t dst_capacity,
                        NEVM::ISA::PrecisionMode target_precision);

// Decompress page data from stored precision
// @param src: Source quantized data
// @param src_size: Source size in bytes
// @param dst: Destination FP16 buffer (must be pre-allocated)
// @param dst_capacity: Destination capacity
// @param stored_precision: Stored precision mode
// @return: Actual decompressed size, or 0 on failure
size_t DecompressPageData(const void* src, size_t src_size,
                            void* dst, size_t dst_capacity,
                            NEVM::ISA::PrecisionMode stored_precision);

// Get compression ratio for precision mode
float GetCompressionRatio(NEVM::ISA::PrecisionMode precision);

// Estimate decompression latency (microseconds)
uint64_t EstimateDecompressionLatency(size_t element_count, 
                                       NEVM::ISA::PrecisionMode precision);

} // namespace Memory
} // namespace RawrXD
