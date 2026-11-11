/**
 * @file quantized_tensor.cpp
 * @brief Quantized Tensor Implementation
 *
 * On-the-fly dequantization for memory-efficient inference.
 *
 * @copyright RawrXD 2026
 */

#include "quantized_tensor.hpp"
#include <cmath>
#include <cstring>
#include <immintrin.h>

namespace rawrxd {
namespace inference {

// ============================================================================
// QuantizedTensor Implementation
// ============================================================================

bool QuantizedTensor::LoadFromGGUF(QuantType qtype, const std::vector<uint64_t>& dims,
                                   const void* src_data, size_t src_size) {
    type = qtype;
    shape = dims;
    
    // Calculate total elements
    num_elements = 1;
    for (auto d : dims) {
        num_elements *= d;
    }
    
    // Copy data
    data.resize(src_size);
    std::memcpy(data.data(), src_data, src_size);
    
    // Calculate number of blocks
    num_blocks = (num_elements + GetBlockSize() - 1) / GetBlockSize();
    
    return true;
}

uint32_t QuantizedTensor::GetBlockSize() const {
    switch (type) {
        case QuantType::Q4_0:
        case QuantType::Q8_0:
            return 32;
        case QuantType::Q4_K:
        case QuantType::Q5_K:
        case QuantType::Q6_K:
        case QuantType::Q8_K:
            return 256;
        default:
            return 1;
    }
}

uint32_t QuantizedTensor::GetBytesPerBlock() const {
    switch (type) {
        case QuantType::Q4_0: return 18;
        case QuantType::Q8_0: return 34;
        case QuantType::Q4_K: return 144;
        case QuantType::Q5_K: return 176;
        case QuantType::Q6_K: return 210;
        case QuantType::Q8_K: return 292;
        default: return 4;
    }
}

// ============================================================================
// Block Dequantization
// ============================================================================

void BlockQ4_0::Dequantize(float* out) const {
    // Convert FP16 scale to FP32
    float scale_f32 = static_cast<float>(scale) / 65536.0f;  // Simplified
    
    for (int i = 0; i < 16; ++i) {
        uint8_t q = qs[i];
        // Unpack two 4-bit values
        out[i * 2 + 0] = (static_cast<float>((q & 0x0F)) - 8.0f) * scale_f32;
        out[i * 2 + 1] = (static_cast<float>((q >> 4) & 0x0F) - 8.0f) * scale_f32;
    }
}

void BlockQ8_0::Dequantize(float* out) const {
    float scale_f32 = static_cast<float>(scale) / 65536.0f;
    
    for (int i = 0; i < 32; ++i) {
        out[i] = static_cast<float>(qs[i]) * scale_f32;
    }
}

void BlockQ4_K::Dequantize(float* out) const {
    // Q4_K has more complex scaling - simplified version
    // Real implementation would extract scales from scales[] array
    float scale = 1.0f / 64.0f;  // Placeholder
    
    for (int i = 0; i < 128; ++i) {
        uint8_t q = qs[i];
        out[i * 2 + 0] = (static_cast<float>((q & 0x0F)) - 8.0f) * scale;
        out[i * 2 + 1] = (static_cast<float>((q >> 4) & 0x0F) - 8.0f) * scale;
    }
}

// ============================================================================
// Quantized MatMul Implementation
// ============================================================================

std::vector<float> MatMulQuantized(
    const std::vector<float>& input,
    uint32_t rows,
    uint32_t in_features,
    const QuantizedTensor& weights,
    uint32_t out_features) {
    
    std::vector<float> result(rows * out_features, 0.0f);
    
    // For now, use scalar implementation
    // AVX2/AVX-512 versions can be added for performance
    
    switch (weights.type) {
        case QuantType::Q4_0: {
            const BlockQ4_0* blocks = reinterpret_cast<const BlockQ4_0*>(weights.data.data());
            uint32_t blocks_per_row = in_features / BlockQ4_0::BLOCK_SIZE;
            
            for (uint32_t r = 0; r < rows; ++r) {
                for (uint32_t oc = 0; oc < out_features; ++oc) {
                    float sum = 0.0f;
                    
                    for (uint32_t ic = 0; ic < in_features; ic += BlockQ4_0::BLOCK_SIZE) {
                        uint32_t block_idx = (oc * in_features + ic) / BlockQ4_0::BLOCK_SIZE;
                        const BlockQ4_0& block = blocks[block_idx];
                        
                        // Dequantize block
                        float dequantized[BlockQ4_0::BLOCK_SIZE];
                        block.Dequantize(dequantized);
                        
                        // Multiply with input
                        for (uint32_t j = 0; j < BlockQ4_0::BLOCK_SIZE && (ic + j) < in_features; ++j) {
                            sum += input[r * in_features + ic + j] * dequantized[j];
                        }
                    }
                    
                    result[r * out_features + oc] = sum;
                }
            }
            break;
        }
        
        case QuantType::Q8_0: {
            const BlockQ8_0* blocks = reinterpret_cast<const BlockQ8_0*>(weights.data.data());
            uint32_t blocks_per_row = in_features / BlockQ8_0::BLOCK_SIZE;
            
            for (uint32_t r = 0; r < rows; ++r) {
                for (uint32_t oc = 0; oc < out_features; ++oc) {
                    float sum = 0.0f;
                    
                    for (uint32_t ic = 0; ic < in_features; ic += BlockQ8_0::BLOCK_SIZE) {
                        uint32_t block_idx = (oc * in_features + ic) / BlockQ8_0::BLOCK_SIZE;
                        const BlockQ8_0& block = blocks[block_idx];
                        
                        float dequantized[BlockQ8_0::BLOCK_SIZE];
                        block.Dequantize(dequantized);
                        
                        for (uint32_t j = 0; j < BlockQ8_0::BLOCK_SIZE && (ic + j) < in_features; ++j) {
                            sum += input[r * in_features + ic + j] * dequantized[j];
                        }
                    }
                    
                    result[r * out_features + oc] = sum;
                }
            }
            break;
        }
        
        case QuantType::Q4_K: {
            const BlockQ4_K* blocks = reinterpret_cast<const BlockQ4_K*>(weights.data.data());
            
            for (uint32_t r = 0; r < rows; ++r) {
                for (uint32_t oc = 0; oc < out_features; ++oc) {
                    float sum = 0.0f;
                    
                    for (uint32_t ic = 0; ic < in_features; ic += BlockQ4_K::BLOCK_SIZE) {
                        uint32_t block_idx = (oc * in_features + ic) / BlockQ4_K::BLOCK_SIZE;
                        const BlockQ4_K& block = blocks[block_idx];
                        
                        float dequantized[BlockQ4_K::BLOCK_SIZE];
                        block.Dequantize(dequantized);
                        
                        for (uint32_t j = 0; j < BlockQ4_K::BLOCK_SIZE && (ic + j) < in_features; ++j) {
                            sum += input[r * in_features + ic + j] * dequantized[j];
                        }
                    }
                    
                    result[r * out_features + oc] = sum;
                }
            }
            break;
        }
        
        case QuantType::F32: {
            // Fall back to regular FP32 MatMul
            const float* w = reinterpret_cast<const float*>(weights.data.data());
            for (uint32_t r = 0; r < rows; ++r) {
                for (uint32_t oc = 0; oc < out_features; ++oc) {
                    float sum = 0.0f;
                    for (uint32_t ic = 0; ic < in_features; ++ic) {
                        sum += input[r * in_features + ic] * w[oc * in_features + ic];
                    }
                    result[r * out_features + oc] = sum;
                }
            }
            break;
        }
        
        default:
            // Unsupported type - return zeros
            break;
    }
    
    return result;
}

// ============================================================================
// AVX2 Optimized Version (placeholder for future)
// ============================================================================

std::vector<float> MatMulQuantizedAVX2(
    const std::vector<float>& input,
    uint32_t rows,
    uint32_t in_features,
    const QuantizedTensor& weights,
    uint32_t out_features) {
    
    // For now, fall back to scalar version
    // AVX2 version would:
    // 1. Dequantize 8 values at a time using _mm256_loadu_si256
    // 2. Convert to FP32 using _mm256_cvtepi32_ps
    // 3. Multiply and accumulate using _mm256_fmadd_ps
    
    return MatMulQuantized(input, rows, in_features, weights, out_features);
}

// ============================================================================
// Value Access
// ============================================================================

float GetQuantizedValue(const QuantizedTensor& tensor, uint64_t idx) {
    if (!tensor.IsQuantized()) {
        // FP32 or FP16
        if (tensor.type == QuantType::F32) {
            return reinterpret_cast<const float*>(tensor.data.data())[idx];
        }
        return 0.0f;  // FP16 not implemented
    }
    
    uint32_t block_size = tensor.GetBlockSize();
    uint64_t block_idx = idx / block_size;
    uint32_t offset_in_block = idx % block_size;
    
    // Dequantize entire block and return single value
    // This is inefficient but simple
    std::vector<float> dequantized(block_size);
    
    switch (tensor.type) {
        case QuantType::Q4_0: {
            const BlockQ4_0* blocks = reinterpret_cast<const BlockQ4_0*>(tensor.data.data());
            blocks[block_idx].Dequantize(dequantized.data());
            return dequantized[offset_in_block];
        }
        case QuantType::Q8_0: {
            const BlockQ8_0* blocks = reinterpret_cast<const BlockQ8_0*>(tensor.data.data());
            blocks[block_idx].Dequantize(dequantized.data());
            return dequantized[offset_in_block];
        }
        default:
            return 0.0f;
    }
}

} // namespace inference
} // namespace rawrxd
