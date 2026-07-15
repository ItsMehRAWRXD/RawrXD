/**
 * @file quantized_tensor.hpp
 * @brief Quantized Tensor Storage for Memory-Efficient Inference
 *
 * Keeps weights in quantized GGUF format, dequantizing on-the-fly during MatMul.
 *
 * @copyright RawrXD 2026
 */

#pragma once

#include <vector>
#include <cstdint>
#include <cstring>
#include <memory>

namespace rawrxd {
namespace inference {

// ============================================================================
// Quantization Types (GGML compatible)
// ============================================================================

enum class QuantType : uint32_t {
    F32  = 0,
    F16  = 1,
    Q4_0 = 2,   // 4-bit, block size 32
    Q4_1 = 3,   // 4-bit with separate min/max
    Q5_0 = 6,
    Q5_1 = 7,
    Q8_0 = 8,   // 8-bit, block size 32
    Q8_1 = 9,
    Q2_K = 10,  // K-quants
    Q3_K = 11,
    Q4_K = 12,  // 4-bit K-quant, block size 256
    Q5_K = 13,
    Q6_K = 14,
    Q8_K = 15,
};

// ============================================================================
// Quantized Tensor
// ============================================================================

struct QuantizedTensor {
    QuantType type = QuantType::F32;
    std::vector<uint64_t> shape;
    std::vector<uint8_t> data;  // Raw quantized bytes
    
    // For memory-mapped tensors (optional optimization)
    const uint8_t* mmap_data = nullptr;
    size_t mmap_size = 0;
    
    // Cached properties
    uint64_t num_elements = 0;
    uint64_t num_blocks = 0;
    
    // Initialize from GGUF tensor data
    bool LoadFromGGUF(QuantType qtype, const std::vector<uint64_t>& dims,
                      const void* src_data, size_t src_size);
    
    // Get size in bytes
    size_t GetDataSize() const { return data.size(); }
    
    // Check if this is a quantized type
    bool IsQuantized() const {
        return type != QuantType::F32 && type != QuantType::F16;
    }
    
    // Get block size for this quantization type
    uint32_t GetBlockSize() const;
    
    // Get bytes per block
    uint32_t GetBytesPerBlock() const;
};

// ============================================================================
// Block Structures for Different Quant Types
// ============================================================================

// Q4_0 block: 32 weights in 16 bytes + 2 bytes (scale) = 18 bytes
struct alignas(2) BlockQ4_0 {
    uint16_t scale;     // FP16 scale
    uint8_t qs[16];   // 32 4-bit weights packed
    
    static constexpr uint32_t BLOCK_SIZE = 32;
    static constexpr uint32_t BYTES = 18;
    
    // Dequantize to FP32
    void Dequantize(float* out) const;
};

// Q8_0 block: 32 weights in 32 bytes + 2 bytes (scale) = 34 bytes
struct alignas(2) BlockQ8_0 {
    uint16_t scale;     // FP16 scale
    int8_t qs[32];      // 32 8-bit weights
    
    static constexpr uint32_t BLOCK_SIZE = 32;
    static constexpr uint32_t BYTES = 34;
    
    void Dequantize(float* out) const;
};

// Q4_K block: 256 weights (K-quant)
struct alignas(64) BlockQ4_K {
    uint8_t scales[12];     // Scale factors
    uint8_t qs[128];        // 256 4-bit weights
    
    static constexpr uint32_t BLOCK_SIZE = 256;
    static constexpr uint32_t BYTES = 144;
    
    void Dequantize(float* out) const;
};

// ============================================================================
// Quantized MatMul Functions
// ============================================================================

/**
 * Matrix multiplication with quantized weights
 * 
 * @param input Input matrix [rows x in_features] (FP32)
 * @param rows Number of rows in input
 * @param in_features Input feature dimension
 * @param weights Quantized weight tensor [in_features x out_features]
 * @param out_features Output feature dimension
 * @return Output matrix [rows x out_features] (FP32)
 */
std::vector<float> MatMulQuantized(
    const std::vector<float>& input,
    uint32_t rows,
    uint32_t in_features,
    const QuantizedTensor& weights,
    uint32_t out_features
);

/**
 * Optimized quantized MatMul using AVX2/AVX-512
 * Dequantizes blocks on-the-fly during multiplication
 */
std::vector<float> MatMulQuantizedAVX2(
    const std::vector<float>& input,
    uint32_t rows,
    uint32_t in_features,
    const QuantizedTensor& weights,
    uint32_t out_features
);

// ============================================================================
// Dequantization Helpers
// ============================================================================

// Dequantize a single block to FP32
void DequantizeBlock(const BlockQ4_0* block, float* out);
void DequantizeBlock(const BlockQ8_0* block, float* out);
void DequantizeBlock(const BlockQ4_K* block, float* out);

// Get the dequantized value at a specific index
float GetQuantizedValue(const QuantizedTensor& tensor, uint64_t idx);

} // namespace inference
} // namespace rawrxd
