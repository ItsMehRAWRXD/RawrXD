//=============================================================================
// RawrXD Quantization Support - PRODUCTION IMPLEMENTATION
// Supports Q4_K_M, Q5_K_M, Q8_0, and other GGML formats
//=============================================================================

#ifndef RAWRXD_QUANTIZATION_HPP
#define RAWRXD_QUANTIZATION_HPP

#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>

namespace RawrXD {
namespace Quantization {

//=============================================================================
// Quantization Type Enumeration (GGML compatible)
//=============================================================================

enum class QuantType : uint32_t {
    // Non-quantized
    F32  = 0,
    F16  = 1,
    BF16 = 30,
    
    // 8-bit
    Q8_0 = 2,
    Q8_1 = 3,
    
    // 4-bit (legacy)
    Q4_0 = 4,
    Q4_1 = 5,
    
    // 5-bit
    Q5_0 = 6,
    Q5_1 = 7,
    
    // K-quants (modern, better quality)
    Q2_K = 14,
    Q3_K = 15,
    Q4_K = 16,
    Q5_K = 17,
    Q6_K = 18,
    Q8_K = 19,
    
    // K-quant variants
    Q4_K_M = 16,  // Alias for Q4_K
    Q5_K_M = 17,  // Alias for Q5_K
    Q4_K_S = 20,
    Q5_K_S = 21,
    
    // I-quants (integer)
    IQ2_XXS = 28,
    IQ2_XS  = 29,
    IQ3_XXS = 30,
    IQ3_XS  = 31,
    IQ4_NL  = 32,
    IQ4_XS  = 33,
    IQ4_KS  = 34,
};

//=============================================================================
// Block Sizes and Type Information
//=============================================================================

struct QuantTypeInfo {
    QuantType type;
    const char* name;
    size_t block_size;      // Number of elements per block
    size_t block_bytes;     // Bytes per block
    size_t type_size;       // Size of single element
    bool is_quantized;
    float typical_ppl_increase;  // Typical perplexity increase vs F16
};

const QuantTypeInfo* GetQuantTypeInfo(QuantType type);
const char* QuantTypeToString(QuantType type);
QuantType StringToQuantType(const char* str);

//=============================================================================
// Quantization Block Structures
//=============================================================================

// Q8_0: 8-bit quantization, 1 scale per 32 elements
struct BlockQ8_0 {
    float scale;           // Scale factor
    int8_t qs[32];         // 32 quantized values
};
static_assert(sizeof(BlockQ8_0) == 36, "BlockQ8_0 size mismatch");

// Q4_0: 4-bit quantization, 1 scale per 32 elements
struct BlockQ4_0 {
    float scale;           // Scale factor
    uint8_t qs[16];        // 32 nibbles packed (16 bytes)
};
static_assert(sizeof(BlockQ4_0) == 20, "BlockQ4_0 size mismatch");

// Q4_1: 4-bit with scale + min
struct BlockQ4_1 {
    float scale;           // Scale factor
    float min;             // Minimum value
    uint8_t qs[16];        // 32 nibbles packed
};
static_assert(sizeof(BlockQ4_1) == 24, "BlockQ4_1 size mismatch");

// Q4_K: K-quant 4-bit (super-block structure)
struct BlockQ4_K {
    uint8_t scales[12];    // Scale factors (compressed)
    uint8_t qs[128];       // 256 nibbles packed
};
static_assert(sizeof(BlockQ4_K) == 140, "BlockQ4_K size mismatch");

// Q5_K: K-quant 5-bit
struct BlockQ5_K {
    uint8_t scales[12];    // Scale factors
    uint8_t qh[32];        // High bits (1 bit per element)
    uint8_t qs[128];       // Low 4 bits
};
static_assert(sizeof(BlockQ5_K) == 172, "BlockQ5_K size mismatch");

// Q6_K: K-quant 6-bit
struct BlockQ6_K {
    uint8_t scales[128];  // Scale factors
    uint8_t ql[128];       // Low 4 bits
    uint8_t qh[64];        // High 2 bits
};
static_assert(sizeof(BlockQ6_K) == 320, "BlockQ6_K size mismatch");

// Q8_K: K-quant 8-bit (for embeddings)
struct BlockQ8_K {
    float scale;
    float bias;
    int8_t qs[256];
};
static_assert(sizeof(BlockQ8_K) == 264, "BlockQ8_K size mismatch");

//=============================================================================
// Dequantization Functions
//=============================================================================

// Dequantize single block to float array
void DequantizeBlockQ8_0(const BlockQ8_0* src, float* dst, size_t n);
void DequantizeBlockQ4_0(const BlockQ4_0* src, float* dst, size_t n);
void DequantizeBlockQ4_1(const BlockQ4_1* src, float* dst, size_t n);
void DequantizeBlockQ4_K(const BlockQ4_K* src, float* dst, size_t n);
void DequantizeBlockQ5_K(const BlockQ5_K* src, float* dst, size_t n);
void DequantizeBlockQ6_K(const BlockQ6_K* src, float* dst, size_t n);
void DequantizeBlockQ8_K(const BlockQ8_K* src, float* dst, size_t n);

// Generic dequantization
void DequantizeTensor(const void* src, QuantType type, float* dst, size_t num_elements);

//=============================================================================
// Quantization Functions (for model conversion)
//=============================================================================

void QuantizeBlockQ8_0(const float* src, BlockQ8_0* dst, size_t n);
void QuantizeBlockQ4_0(const float* src, BlockQ4_0* dst, size_t n);
void QuantizeBlockQ4_1(const float* src, BlockQ4_1* dst, size_t n);

// Generic quantization
void QuantizeTensor(const float* src, void* dst, QuantType type, size_t num_elements);

//=============================================================================
// Tensor Quantization Info
//=============================================================================

struct QuantizedTensorInfo {
    QuantType type;
    size_t num_elements;
    size_t num_blocks;
    size_t bytes_per_block;
    size_t total_bytes;
    size_t original_bytes_f32;
    float compression_ratio;
};

QuantizedTensorInfo CalculateQuantizedTensorInfo(QuantType type, size_t num_elements);

//=============================================================================
// SIMD Optimizations
//=============================================================================

// AVX2/FMA implementations
void DequantizeBlockQ8_0_AVX2(const BlockQ8_0* src, float* dst, size_t n);
void DequantizeBlockQ4_0_AVX2(const BlockQ4_0* src, float* dst, size_t n);

// AVX-512 implementations
void DequantizeBlockQ8_0_AVX512(const BlockQ8_0* src, float* dst, size_t n);
void DequantizeBlockQ4_0_AVX512(const BlockQ4_0* src, float* dst, size_t n);

// ARM NEON implementations
void DequantizeBlockQ8_0_NEON(const BlockQ8_0* src, float* dst, size_t n);
void DequantizeBlockQ4_0_NEON(const BlockQ4_0* src, float* dst, size_t n);

//=============================================================================
// GPU Upload Preparation
//=============================================================================

// Prepare tensor data for GPU upload (handles alignment, padding)
std::vector<uint8_t> PrepareForGPUUpload(const void* src, QuantType type, 
                                           size_t num_elements, 
                                           size_t alignment = 256);

// Get optimal upload chunk size for GPU
size_t GetOptimalGPUChunkSize(QuantType type);

} // namespace Quantization
} // namespace RawrXD

#endif // RAWRXD_QUANTIZATION_HPP
