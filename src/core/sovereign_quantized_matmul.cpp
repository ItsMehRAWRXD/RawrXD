// =============================================================================
// sovereign_quantized_matmul.cpp
// Quantized Matrix Multiplication Implementation
// Performs operations directly on compressed weights
// =============================================================================

#include "sovereign_quantized_matmul.h"
#include "sovereign_q3_k_s_dequant.h"
#include "sovereign_q4_0_dequant.h"
#include <cstring>
#include <unordered_map>
#include <memory>

namespace Sovereign {

// =============================================================================
// Q3_K_S Block Matrix-Vector Multiplication
// =============================================================================
// Q3_K_S block: 256 weights, 98 bytes
// - 2 bytes: scales
// - 96 bytes: 3-bit quantized values

void Q3_K_S_BlockMatVec(
    const uint8_t* block,
    const float* x,
    float* result
) {
    // Extract scales (4 scales for 4 groups of 64)
    float scales[4];
    scales[0] = static_cast<float>(block[0] & 0x0F) / 16.0f;
    scales[1] = static_cast<float>((block[0] >> 4) & 0x0F) / 16.0f;
    scales[2] = static_cast<float>(block[1] & 0x0F) / 16.0f;
    scales[3] = static_cast<float>((block[1] >> 4) & 0x0F) / 16.0f;
    
    const uint8_t* quants = block + 2;  // Skip scale bytes
    
    // Process 256 weights in groups of 64
    for (int group = 0; group < 4; group++) {
        float group_sum = 0.0f;
        float scale = scales[group];
        
        for (int i = 0; i < 64; i++) {
            int idx = group * 64 + i;
            
            // Extract 3-bit value
            int byte_idx = (idx * 3) / 8;
            int bit_offset = (idx * 3) % 8;
            
            uint8_t val = 0;
            if (bit_offset <= 5) {
                val = (quants[byte_idx] >> bit_offset) & 0x07;
            } else {
                uint8_t low_bits = (quants[byte_idx] >> bit_offset) & ((1 << (8 - bit_offset)) - 1);
                uint8_t high_bits = (quants[byte_idx + 1] << (8 - bit_offset)) & 0x07;
                val = low_bits | high_bits;
            }
            
            // Dequantize and multiply
            float weight = (static_cast<float>(val) - 3.5f) * scale;
            group_sum += weight * x[idx];
        }
        
        *result += group_sum;
    }
}

// =============================================================================
// Quantized Matrix-Vector Multiplication
// =============================================================================

void QuantizedMatVecMul(
    const QuantizedWeights& weights,
    const float* x,
    float* y
) {
    if (!weights.data || !x || !y) return;
    
    // Initialize output to zero
    std::memset(y, 0, weights.rows * sizeof(float));
    
    if (weights.quant_type == 0) {  // Q3_K
        const uint32_t n_blocks = weights.n_elements / 256;
        const uint8_t* blocks = weights.data;
        
        // For each output row
        for (uint32_t row = 0; row < weights.rows; row++) {
            float sum = 0.0f;
            
            // Process blocks for this row
            for (uint32_t b = 0; b < n_blocks; b++) {
                const uint8_t* block = blocks + b * 98;
                const float* x_segment = x + b * 256;
                
                // Accumulate block contribution
                float block_sum = 0.0f;
                Q3_K_S_BlockMatVec(block, x_segment, &block_sum);
                sum += block_sum;
            }
            
            y[row] = sum;
        }
    }
    // TODO: Add Q6_K support
}

// =============================================================================
// Q4_0 Matrix-Vector Multiplication
// =============================================================================
// Q4_0 block: 32 weights, 18 bytes
// - 2 bytes: scale (FP16)
// - 16 bytes: 4-bit quantized values (2 weights per byte)

void QuantizedMatVecMul_Q4_0(
    const QuantizedWeights& weights,
    const float* x,
    float* y,
    uint32_t rows,
    uint32_t cols
) {
    if (!weights.data || !x || !y) return;
    
    // Initialize output to zero
    std::memset(y, 0, rows * sizeof(float));
    
    const uint32_t block_size = 32;
    const uint32_t bytes_per_block = 18;
    const uint32_t blocks_per_row = (cols + block_size - 1) / block_size;
    
    // For each output row
    for (uint32_t row = 0; row < rows; row++) {
        float sum = 0.0f;
        
        // Calculate row offset in weight data
        uint64_t row_offset = static_cast<uint64_t>(row) * blocks_per_row * bytes_per_block;
        if (row_offset + blocks_per_row * bytes_per_block > weights.size) {
            break;  // Out of bounds
        }
        
        // Process each block in this row
        for (uint32_t b = 0; b < blocks_per_row; b++) {
            const uint8_t* block = weights.data + row_offset + b * bytes_per_block;
            uint32_t base_idx = b * block_size;
            
            // Extract scale (first 2 bytes as FP16)
            uint16_t scale_bits = block[0] | (block[1] << 8);
            float scale = float16_to_float32(scale_bits);
            
            // Process 32 weights in this block
            for (uint32_t i = 0; i < block_size && (base_idx + i) < cols; i++) {
                uint32_t idx = base_idx + i;
                uint32_t byte_idx = 2 + (i / 2);  // Skip scale bytes
                
                if (byte_idx >= bytes_per_block) break;
                
                // Extract 4-bit value
                uint8_t packed = block[byte_idx];
                uint8_t qval = (i % 2 == 0) ? (packed & 0x0F) : (packed >> 4);
                
                // Dequantize: (q - 8) * scale
                float weight = (static_cast<float>(qval) - 8.0f) * scale;
                sum += weight * x[idx];
            }
        }
        
        y[row] = sum;
    }
}

// =============================================================================
// Q6_K Matrix-Vector Multiplication
// =============================================================================
// Q6_K block: 256 weights, 210 bytes
// - 2 bytes: scale (FP16)
// - 208 bytes: 6-bit quantized values packed
//
// Layout (based on k-quants):
// - 256 weights per block
// - Each weight is 6 bits
// - 256 * 6 = 1536 bits = 192 bytes for weights
// - Plus scales and other metadata

void QuantizedMatVecMul_Q6_K(
    const QuantizedWeights& weights,
    const float* x,
    float* y,
    uint32_t rows,
    uint32_t cols
) {
    if (!weights.data || !x || !y) return;
    
    // Initialize output to zero
    std::memset(y, 0, rows * sizeof(float));
    
    const uint32_t block_size = 256;  // Q6_K uses 256 weights per block
    const uint32_t bytes_per_block = 210;
    const uint32_t blocks_per_row = (cols + block_size - 1) / block_size;
    
    // FIX: Calculate actual bytes per row for proper row addressing
    // Q6_K: 210 bytes per 256 elements, so bytes_per_row = blocks_per_row * 210
    const uint64_t bytes_per_row = static_cast<uint64_t>(blocks_per_row) * bytes_per_block;
    
    // For each output row
    for (uint32_t row = 0; row < rows; row++) {
        float sum = 0.0f;
        
        // FIX: Use bytes_per_row for proper row offset calculation
        // This ensures correct addressing when vocab_size doesn't align with tensor size
        uint64_t row_offset = static_cast<uint64_t>(row) * bytes_per_row;
        if (row_offset + blocks_per_row * bytes_per_block > weights.size) {
            break;  // Out of bounds
        }
        
        // Process each block in this row
        for (uint32_t b = 0; b < blocks_per_row; b++) {
            const uint8_t* block = weights.data + row_offset + b * bytes_per_block;
            uint32_t base_idx = b * block_size;
            
            // Extract scale (first 2 bytes as FP16)
            uint16_t scale_bits = block[0] | (block[1] << 8);
            float scale = float16_to_float32(scale_bits);
            
            // Process 256 weights in this block
            // Q6_K: 6-bit values packed
            // For simplicity, we'll extract each 6-bit value
            for (uint32_t i = 0; i < block_size && (base_idx + i) < cols; i++) {
                uint32_t idx = base_idx + i;
                
                // Calculate byte position and bit offset for 6-bit value
                // 256 weights * 6 bits = 1536 bits = 192 bytes
                // Start after scale bytes (offset 2)
                uint32_t bit_pos = i * 6;
                uint32_t byte_idx = 2 + (bit_pos / 8);
                uint32_t bit_offset = bit_pos % 8;
                
                if (byte_idx >= bytes_per_block - 1) break;
                
                // Extract 6-bit value (may span 2 bytes)
                uint8_t qval;
                if (bit_offset <= 2) {
                    // Fits in one byte
                    qval = (block[byte_idx] >> bit_offset) & 0x3F;
                } else {
                    // Spans two bytes
                    uint8_t low_bits = block[byte_idx] >> bit_offset;
                    uint8_t high_bits = (block[byte_idx + 1] << (8 - bit_offset)) & 0x3F;
                    qval = low_bits | high_bits;
                }
                
                // Dequantize: (q - 32) * scale (centered around 32 for 6-bit)
                float weight = (static_cast<float>(qval) - 32.0f) * scale;
                sum += weight * x[idx];
            }
        }
        
        y[row] = sum;
    }
}

// =============================================================================
// Quantized Weight Bank Implementation
// =============================================================================

struct QuantizedWeightBank::Impl {
    std::unordered_map<std::string, QuantizedWeights> weights;
    uint64_t total_memory = 0;
};

QuantizedWeightBank::QuantizedWeightBank() : pImpl(std::make_unique<Impl>()) {}
QuantizedWeightBank::~QuantizedWeightBank() = default;

bool QuantizedWeightBank::AddTensor(
    const std::string& name,
    const uint8_t* data,
    uint64_t size,
    uint32_t rows,
    uint32_t cols,
    int quant_type
) {
    if (!data || size == 0) return false;
    
    // Allocate and copy data
    uint8_t* copied_data = new uint8_t[size];
    std::memcpy(copied_data, data, size);
    
    QuantizedWeights qw;
    qw.data = copied_data;
    qw.size = size;
    qw.rows = rows;
    qw.cols = cols;
    qw.quant_type = quant_type;
    
    // Calculate n_elements based on quantization type
    if (quant_type == 0) {  // Q3_K: 256 elements per 98 bytes
        qw.n_elements = static_cast<uint32_t>((size / 98) * 256);
    } else {
        qw.n_elements = 0;  // Unknown
    }
    
    pImpl->weights[name] = qw;
    pImpl->total_memory += size;
    
    return true;
}

const QuantizedWeights* QuantizedWeightBank::GetWeights(const std::string& name) const {
    auto it = pImpl->weights.find(name);
    if (it != pImpl->weights.end()) {
        return &it->second;
    }
    return nullptr;
}

bool QuantizedWeightBank::ComputeMatVec(
    const std::string& weight_name,
    const float* x,
    float* y
) const {
    const QuantizedWeights* weights = GetWeights(weight_name);
    if (!weights) return false;
    
    QuantizedMatVecMul(*weights, x, y);
    return true;
}

void QuantizedWeightBank::Clear() {
    for (auto& pair : pImpl->weights) {
        delete[] pair.second.data;
    }
    pImpl->weights.clear();
    pImpl->total_memory = 0;
}

uint64_t QuantizedWeightBank::GetTotalMemory() const {
    return pImpl->total_memory;
}

} // namespace Sovereign
